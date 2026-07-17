using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

public sealed class UploadAuthenticationTests
{
    private const string SigningKey = "test-signing-key-at-least-thirty-two-bytes-long";
    private const string InternalSecret = "test-upload-internal-secret-at-least-thirty-two-bytes";

    [Fact]
    public async Task Upload_uses_public_auth_me_userId_contract()
    {
        var storageRoot = Path.Combine(Path.GetTempPath(), $"fakebook-upload-{Guid.NewGuid():N}");

        try
        {
            await using var factory = new UploadServerFactory(storageRoot);
            using var client = factory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", CreateToken());

            using var content = new MultipartFormDataContent();
            var png = new ByteArrayContent(
            [
                0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
                0x00, 0x00, 0x00, 0x00
            ]);
            png.Headers.ContentType = new MediaTypeHeaderValue("image/png");
            content.Add(png, "file", "avatar.png");

            using var response = await client.PostAsync("/media/upload", content);
            var body = await response.Content.ReadAsStringAsync();

            Assert.True(
                response.StatusCode == HttpStatusCode.OK,
                $"Expected 200, got {(int)response.StatusCode}. Body: {body}. WWW-Authenticate: {string.Join(";", response.Headers.WwwAuthenticate)}. Auth query: {factory.AuthHandler.LastQuery}");
            Assert.Contains("/media/files/", body, StringComparison.Ordinal);
            Assert.Contains("me { userId }", factory.AuthHandler.LastQuery, StringComparison.Ordinal);
        }
        finally
        {
            if (Directory.Exists(storageRoot))
            {
                Directory.Delete(storageRoot, recursive: true);
            }
        }
    }

    [Fact]
    public async Task Upload_rejects_token_without_session_id_before_calling_auth()
    {
        await using var factory = new UploadServerFactory(Path.GetTempPath());
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            CreateToken(includeSessionId: false));

        using var response = await client.PostAsync("/media/upload", CreatePngForm());

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, factory.AuthHandler.CallCount);
    }

    [Fact]
    public async Task Upload_rejects_auth_response_for_a_different_user()
    {
        await using var factory = new UploadServerFactory(Path.GetTempPath(), authUserId: 43);
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", CreateToken());

        using var response = await client.PostAsync("/media/upload", CreatePngForm());

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(1, factory.AuthHandler.CallCount);
    }

    [Fact]
    public async Task Staged_asset_can_only_be_finalized_and_deleted_with_internal_secret()
    {
        var storageRoot = Path.Combine(Path.GetTempPath(), $"fakebook-upload-{Guid.NewGuid():N}");
        try
        {
            await using var factory = new UploadServerFactory(storageRoot);
            using var client = factory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", CreateToken());
            using var uploadResponse = await client.PostAsync("/media/upload", CreatePngForm());
            uploadResponse.EnsureSuccessStatusCode();
            using var uploaded = JsonDocument.Parse(await uploadResponse.Content.ReadAsStringAsync());
            var url = uploaded.RootElement.GetProperty("url").GetString()!;
            var assetId = uploaded.RootElement.GetProperty("assetId").GetString()!;
            Assert.Equal("pending", uploaded.RootElement.GetProperty("state").GetString());

            client.DefaultRequestHeaders.Authorization = null;
            using var denied = await client.PostAsJsonAsync("/internal/media/finalize", new { urls = new[] { url } });
            Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);

            client.DefaultRequestHeaders.Add("X-Internal-UploadService-Secret", InternalSecret);
            using var finalized = await client.PostAsJsonAsync("/internal/media/finalize", new { urls = new[] { url } });
            Assert.Equal(HttpStatusCode.OK, finalized.StatusCode);

            client.DefaultRequestHeaders.Remove("X-Internal-UploadService-Secret");
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", CreateToken());
            using var ownerDelete = await client.DeleteAsync($"/media/assets/{assetId}");
            Assert.Equal(HttpStatusCode.NotFound, ownerDelete.StatusCode);

            client.DefaultRequestHeaders.Authorization = null;
            client.DefaultRequestHeaders.Add("X-Internal-UploadService-Secret", InternalSecret);
            using var deleted = await client.PostAsJsonAsync("/internal/media/delete", new { urls = new[] { url } });
            Assert.Equal(HttpStatusCode.OK, deleted.StatusCode);
            using var missing = await client.GetAsync(url);
            Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        }
        finally
        {
            if (Directory.Exists(storageRoot)) Directory.Delete(storageRoot, recursive: true);
        }
    }

    [Fact]
    public async Task FinalizeOwned_does_not_commit_metadata_when_asset_file_is_missing()
    {
        var storageRoot = Path.Combine(Path.GetTempPath(), $"fakebook-upload-{Guid.NewGuid():N}");
        try
        {
            var store = new UploadAssetStore(Options.Create(new UploadStorageOptions
            {
                RootPath = storageRoot,
                StagedUploadsEnabled = true,
                PendingLifetimeMinutes = 60
            }));
            var metadata = await store.RegisterAsync(
                $"{Guid.NewGuid():N}.png",
                42,
                "missing.png",
                "image/png",
                10,
                CancellationToken.None);

            var finalized = await store.FinalizeOwnedAsync([metadata.AssetId], 42, CancellationToken.None);

            Assert.Equal(0, finalized);
        }
        finally
        {
            if (Directory.Exists(storageRoot)) Directory.Delete(storageRoot, recursive: true);
        }
    }

    private static string CreateToken(bool includeSessionId = true)
    {
        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SigningKey)),
            SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: "fakebook-auth",
            audience: "fakebook",
            claims: includeSessionId
                ? [new Claim("user_id", "42"), new Claim("sid", "84")]
                : [new Claim("user_id", "42")],
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static MultipartFormDataContent CreatePngForm()
    {
        var content = new MultipartFormDataContent();
        var png = new ByteArrayContent(
        [
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
            0x00, 0x00, 0x00, 0x00
        ]);
        png.Headers.ContentType = new MediaTypeHeaderValue("image/png");
        content.Add(png, "file", "avatar.png");
        return content;
    }

    private sealed class UploadServerFactory(string storageRoot, long authUserId = 42) : WebApplicationFactory<Program>
    {
        public AuthContractHandler AuthHandler { get; } = new(authUserId);

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.ConfigureAppConfiguration((_, configuration) =>
            {
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Jwt:Issuer"] = "fakebook-auth",
                    ["Jwt:Audience"] = "fakebook",
                    ["Jwt:SigningKey"] = SigningKey,
                    ["AuthService:Url"] = "http://auth.test/graphql",
                    ["UploadStorage:RootPath"] = storageRoot,
                    ["UploadStorage:StagedUploadsEnabled"] = "true",
                    ["UploadStorage:PendingLifetimeMinutes"] = "60",
                    ["InternalApi:SharedSecret"] = InternalSecret
                });
            });

            builder.ConfigureServices(services =>
            {
                services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
                {
                    options.TokenValidationParameters.IssuerSigningKey =
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SigningKey));
                    options.TokenValidationParameters.ValidIssuer = "fakebook-auth";
                    options.TokenValidationParameters.ValidAudience = "fakebook";
                });
                services.AddHttpClient("auth-service")
                    .ConfigurePrimaryHttpMessageHandler(() => AuthHandler);
            });
        }
    }

    private sealed class AuthContractHandler(long authUserId) : HttpMessageHandler
    {
        public string LastQuery { get; private set; } = string.Empty;
        public int CallCount { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            CallCount++;
            LastQuery = await request.Content!.ReadAsStringAsync(cancellationToken);
            var validContract = LastQuery.Contains("me { userId }", StringComparison.Ordinal);
            var json = validContract
                ? $"{{\"data\":{{\"me\":{{\"userId\":{authUserId}}}}}}}"
                : "{\"errors\":[{\"message\":\"Cannot query field 'id' on type 'User'.\"}]}";

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };
        }
    }
}
