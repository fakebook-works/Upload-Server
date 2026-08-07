using System.IdentityModel.Tokens.Jwt;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

public sealed class UploadAuthenticationTests
{
    private const string InternalSecret = "test-upload-internal-secret-at-least-thirty-two-bytes";

    [Fact]
    public void Internal_signing_matches_the_documented_cross_language_vectors()
    {
        const string secret = "test-internal-secret-0123456789ab";
        var bodySignature = Convert.ToHexString(InternalRequestSigning.Sign(
            secret,
            "POST",
            "/internal/users?x=1",
            1_753_500_000,
            "0123456789abcdef0123456789abcdef",
            Encoding.UTF8.GetBytes("{\"userId\":42}"))).ToLowerInvariant();
        var emptySignature = Convert.ToHexString(InternalRequestSigning.Sign(
            secret,
            "GET",
            "/internal/users/42/friend-ids",
            1_753_500_000,
            "ffffffffffffffffffffffffffffffff",
            Array.Empty<byte>())).ToLowerInvariant();

        Assert.Equal("e0f96895cf6c2f5b4f075e7f6f36902e591d2ce178321550041d45e6c8726512", bodySignature);
        Assert.Equal("3ff404655307935abc5825da27bf6fd4b311b0f2034a23a0d7ebbc012aa430c1", emptySignature);
    }

    [Fact]
    public async Task Internal_signing_handler_removes_the_raw_secret_and_covers_the_exact_body()
    {
        var capture = new RecordingInternalRequestHandler();
        var signingHandler = new InternalRequestSigningHandler(Options.Create(
            new InternalRequestSigningOptions
            {
                SendLegacySecret = false
            }))
        {
            InnerHandler = capture
        };
        using var client = new HttpClient(signingHandler);
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            "http://upload.test/internal/media/finalize?source=outbox")
        {
            Content = new StringContent("{\"urls\":[\"/media/files/a.jpg\"]}", Encoding.UTF8, "application/json")
        };
        request.Headers.TryAddWithoutValidation("X-Internal-UploadService-Secret", InternalSecret);

        using var response = await client.SendAsync(request);

        Assert.False(capture.Headers.ContainsKey("X-Internal-UploadService-Secret"));
        var timestamp = long.Parse(capture.Headers[InternalRequestSigning.TimestampHeader]);
        var nonce = capture.Headers[InternalRequestSigning.NonceHeader];
        var expected = Convert.ToHexString(InternalRequestSigning.Sign(
            InternalSecret,
            "POST",
            "/internal/media/finalize?source=outbox",
            timestamp,
            nonce,
            capture.Body)).ToLowerInvariant();
        Assert.Equal(expected, capture.Headers[InternalRequestSigning.SignatureHeader]);
    }

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
            var png = new ByteArrayContent(MediaMetadataSanitizerTests.CreatePng());
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
    public async Task Upload_rejects_active_content_after_the_old_8kb_audit_window()
    {
        var storageRoot = Path.Combine(Path.GetTempPath(), $"fakebook-upload-{Guid.NewGuid():N}");

        try
        {
            await using var factory = new UploadServerFactory(storageRoot);
            using var client = factory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", CreateToken());

            var bytes = new byte[70 * 1024];
            new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }.CopyTo(bytes, 0);
            // Start immediately before the 64 KiB scanner boundary to prove both
            // full-file scanning and overlap detection between chunks.
            Encoding.ASCII.GetBytes("<?PhP echo 1;").CopyTo(bytes, (64 * 1024) - 3);

            using var form = new MultipartFormDataContent();
            var png = new ByteArrayContent(bytes);
            png.Headers.ContentType = new MediaTypeHeaderValue("image/png");
            form.Add(png, "file", "late-payload.png");

            using var response = await client.PostAsync("/media/upload", form);
            var body = await response.Content.ReadAsStringAsync();

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Contains("active-content audit", body, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (Directory.Exists(storageRoot)) Directory.Delete(storageRoot, recursive: true);
        }
    }

    [Fact]
    public async Task Upload_accepts_browser_recorded_webm_audio()
    {
        var storageRoot = Path.Combine(Path.GetTempPath(), $"fakebook-upload-{Guid.NewGuid():N}");
        try
        {
            await using var factory = new UploadServerFactory(storageRoot);
            using var client = factory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", CreateToken());

            using var response = await client.PostAsync("/media/upload", CreateWebmAudioForm());
            var body = await response.Content.ReadAsStringAsync();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var uploaded = JsonDocument.Parse(body);
            Assert.Equal("audio", uploaded.RootElement.GetProperty("type").GetString());
            Assert.Equal("audio/webm", uploaded.RootElement.GetProperty("contentType").GetString());
            Assert.EndsWith(".webm", uploaded.RootElement.GetProperty("url").GetString(), StringComparison.Ordinal);
        }
        finally
        {
            if (Directory.Exists(storageRoot)) Directory.Delete(storageRoot, recursive: true);
        }
    }

    [Fact]
    public async Task Upload_accepts_feed_video_above_the_legacy_25mb_limit()
    {
        var storageRoot = Path.Combine(Path.GetTempPath(), $"fakebook-upload-{Guid.NewGuid():N}");
        try
        {
            await using var factory = new UploadServerFactory(storageRoot);
            using var client = factory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", CreateToken());
            using var content = CreateMp4Form(31 * 1024 * 1024);

            using var response = await client.PostAsync("/media/upload", content);
            var body = await response.Content.ReadAsStringAsync();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var uploaded = JsonDocument.Parse(body);
            Assert.Equal("video", uploaded.RootElement.GetProperty("type").GetString());
            Assert.Equal(31 * 1024 * 1024, uploaded.RootElement.GetProperty("size").GetInt64());
        }
        finally
        {
            if (Directory.Exists(storageRoot)) Directory.Delete(storageRoot, recursive: true);
        }
    }

    [Fact]
    public async Task Upload_accepts_office_documents_and_serves_their_content_type()
    {
        var storageRoot = Path.Combine(Path.GetTempPath(), $"fakebook-upload-{Guid.NewGuid():N}");
        try
        {
            await using var factory = new UploadServerFactory(storageRoot);
            using var client = factory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", CreateToken());

            using var response = await client.PostAsync("/media/upload", CreateDocxForm());
            var body = await response.Content.ReadAsStringAsync();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using var uploaded = JsonDocument.Parse(body);
            Assert.Equal("file", uploaded.RootElement.GetProperty("type").GetString());
            Assert.Equal(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                uploaded.RootElement.GetProperty("contentType").GetString());
            Assert.Equal("project-plan.docx", uploaded.RootElement.GetProperty("name").GetString());

            using var download = await client.GetAsync(uploaded.RootElement.GetProperty("url").GetString());
            Assert.Equal(HttpStatusCode.OK, download.StatusCode);
            Assert.Equal(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                download.Content.Headers.ContentType?.MediaType);
            Assert.True(download.Headers.CacheControl?.Private);
            Assert.True(download.Headers.CacheControl?.NoStore);
        }
        finally
        {
            if (Directory.Exists(storageRoot)) Directory.Delete(storageRoot, recursive: true);
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
    public async Task Staged_asset_can_only_be_finalized_and_exact_detach_may_omit_owner_with_internal_secret()
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
            var lifecycleAt = DateTimeOffset.UtcNow;
            var reference = new { url, referenceId = "social:media:integration-test" };
            using var authorized = await client.PostAsJsonAsync(
                "/internal/media/authorize",
                new { ownerUserId = 42, references = new[] { reference }, operationAt = lifecycleAt });
            Assert.Equal(HttpStatusCode.OK, authorized.StatusCode);
            using (var authorizationBody = JsonDocument.Parse(
                       await authorized.Content.ReadAsStringAsync()))
            {
                Assert.True(authorizationBody.RootElement.GetProperty("authorized").GetBoolean());
                Assert.True(authorizationBody.RootElement.GetProperty("exactReferences").GetBoolean());
                Assert.Equal(
                    UploadAssetStore.CurrentLifecycleVersion,
                    authorizationBody.RootElement.GetProperty("lifecycleVersion").GetInt32());
                Assert.Equal(1, authorizationBody.RootElement.GetProperty("referenceCount").GetInt32());
            }
            using var finalized = await client.PostAsJsonAsync(
                "/internal/media/finalize",
                new { ownerUserId = 42, references = new[] { reference }, operationAt = lifecycleAt });
            Assert.Equal(HttpStatusCode.OK, finalized.StatusCode);

            client.DefaultRequestHeaders.Remove("X-Internal-UploadService-Secret");
            using (var served = await client.GetAsync(url))
            {
                Assert.Equal(HttpStatusCode.OK, served.StatusCode);
                Assert.True(served.Headers.CacheControl?.Private);
                Assert.True(served.Headers.CacheControl?.NoStore);
            }

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", CreateToken());
            using var ownerDelete = await client.DeleteAsync($"/media/assets/{assetId}");
            Assert.Equal(HttpStatusCode.NotFound, ownerDelete.StatusCode);

            client.DefaultRequestHeaders.Authorization = null;
            client.DefaultRequestHeaders.Add("X-Internal-UploadService-Secret", InternalSecret);
            using var deleted = await client.PostAsJsonAsync(
                "/internal/media/delete",
                new { references = new[] { reference }, operationAt = lifecycleAt.AddSeconds(1) });
            Assert.Equal(HttpStatusCode.OK, deleted.StatusCode);
            var assetStore = factory.Services.GetRequiredService<UploadAssetStore>();
            await assetStore.CleanupExpiredAsync(
                DateTimeOffset.UtcNow.AddMinutes(121),
                CancellationToken.None);
            using var missing = await client.GetAsync(url);
            Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        }
        finally
        {
            if (Directory.Exists(storageRoot)) Directory.Delete(storageRoot, recursive: true);
        }
    }

    [Fact]
    public async Task Reference_lifecycle_http_requires_operation_time_and_rejects_future_skew()
    {
        await using var factory = new UploadServerFactory(Path.GetTempPath());
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Internal-UploadService-Secret", InternalSecret);
        var reference = new
        {
            url = $"/media/files/{Guid.NewGuid():N}.png",
            referenceId = "socialgraph:media:clock"
        };

        using var missing = await client.PostAsJsonAsync(
            "/internal/media/finalize",
            new { ownerUserId = 42, references = new[] { reference } });
        using var future = await client.PostAsJsonAsync(
            "/internal/media/finalize",
            new
            {
                ownerUserId = 42,
                references = new[] { reference },
                operationAt = DateTimeOffset.UtcNow.AddMinutes(6)
            });

        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);
        Assert.Equal((HttpStatusCode)425, future.StatusCode);
    }

    [Fact]
    public async Task Browser_finalize_rejects_invalid_and_oversized_asset_batches()
    {
        await using var factory = new UploadServerFactory(Path.GetTempPath());
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", CreateToken());

        using var invalid = await client.PostAsJsonAsync(
            "/media/assets/finalize",
            new { assetIds = new[] { "not-an-asset-id" } });
        using var oversized = await client.PostAsJsonAsync(
            "/media/assets/finalize",
            new { assetIds = Enumerable.Range(0, 513).Select(_ => Guid.NewGuid().ToString("N")).ToArray() });

        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, oversized.StatusCode);
    }

    [Fact]
    public async Task Internal_signature_is_required_and_a_nonce_cannot_be_replayed()
    {
        await using var factory = new UploadServerFactory(
            Path.GetTempPath(),
            requireInternalSignature: true);
        using var client = factory.CreateClient();
        const string path = "/internal/media/finalize";
        var body = Encoding.UTF8.GetBytes("{\"urls\":[]}");
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        const string nonce = "0123456789abcdef0123456789abcdef";
        var signature = Convert.ToHexString(InternalRequestSigning.Sign(
            InternalSecret,
            "POST",
            path,
            timestamp,
            nonce,
            body)).ToLowerInvariant();

        static HttpRequestMessage CreateSignedRequest(
            string path,
            byte[] body,
            long timestamp,
            string nonce,
            string signature)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, path)
            {
                Content = new ByteArrayContent(body)
            };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            request.Headers.TryAddWithoutValidation(InternalRequestSigning.TimestampHeader, timestamp.ToString());
            request.Headers.TryAddWithoutValidation(InternalRequestSigning.NonceHeader, nonce);
            request.Headers.TryAddWithoutValidation(InternalRequestSigning.SignatureHeader, signature);
            return request;
        }

        using var unsigned = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new ByteArrayContent(body)
        };
        unsigned.Headers.TryAddWithoutValidation("X-Internal-UploadService-Secret", InternalSecret);
        using var unsignedResponse = await client.SendAsync(unsigned);
        Assert.Equal(HttpStatusCode.Forbidden, unsignedResponse.StatusCode);

        using var firstRequest = CreateSignedRequest(path, body, timestamp, nonce, signature);
        using var firstResponse = await client.SendAsync(firstRequest);
        Assert.True(
            firstResponse.StatusCode == HttpStatusCode.OK,
            $"Expected signed request to succeed, got {(int)firstResponse.StatusCode}: {await firstResponse.Content.ReadAsStringAsync()}");

        using var replayRequest = CreateSignedRequest(path, body, timestamp, nonce, signature);
        using var replayResponse = await client.SendAsync(replayRequest);
        Assert.Equal(HttpStatusCode.Forbidden, replayResponse.StatusCode);
        Assert.Contains(
            "INVALID_INTERNAL_SIGNATURE",
            await replayResponse.Content.ReadAsStringAsync(),
            StringComparison.Ordinal);
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
        using var rsa = TestJwtKeys.CreatePrivateKey();
        var signingKey = new RsaSecurityKey(rsa)
        {
            KeyId = TestJwtKeys.KeyId,
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
        };
        var credentials = new SigningCredentials(
            signingKey,
            SecurityAlgorithms.RsaSha256);
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
        var png = new ByteArrayContent(MediaMetadataSanitizerTests.CreatePng());
        png.Headers.ContentType = new MediaTypeHeaderValue("image/png");
        content.Add(png, "file", "avatar.png");
        return content;
    }

    private static MultipartFormDataContent CreateWebmAudioForm()
    {
        var content = new MultipartFormDataContent();
        var webm = new ByteArrayContent(MediaMetadataSanitizerTests.CreateMinimalWebm());
        webm.Headers.ContentType = new MediaTypeHeaderValue("audio/webm");
        content.Add(webm, "file", "voice-message.webm");
        return content;
    }

    private static MultipartFormDataContent CreateMp4Form(int size)
    {
        var bytes = MediaMetadataSanitizerTests.CreateMinimalMp4(size);
        var content = new MultipartFormDataContent();
        var video = new ByteArrayContent(bytes);
        video.Headers.ContentType = new MediaTypeHeaderValue("video/mp4");
        content.Add(video, "file", "feed-video.mp4");
        return content;
    }

    private static MultipartFormDataContent CreateDocxForm()
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            var contentTypes = archive.CreateEntry("[Content_Types].xml");
            using (var writer = new StreamWriter(contentTypes.Open(), Encoding.UTF8, leaveOpen: false))
            {
                writer.Write("<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\" />");
            }

            var document = archive.CreateEntry("word/document.xml");
            using var documentWriter = new StreamWriter(document.Open(), Encoding.UTF8, leaveOpen: false);
            documentWriter.Write("<document><body><p>Fakebook project plan</p></body></document>");
        }

        var content = new MultipartFormDataContent();
        var docx = new ByteArrayContent(stream.ToArray());
        // Some Windows/browser combinations report Office files as a generic
        // binary or ZIP payload. The server must recover the canonical type
        // from the allow-listed extension and still verify the ZIP signature.
        docx.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(docx, "file", "project-plan.docx");
        return content;
    }

    private sealed class UploadServerFactory(
        string storageRoot,
        long authUserId = 42,
        bool requireInternalSignature = false) : WebApplicationFactory<Program>
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
                    ["Jwt:PublicKeyBase64"] = TestJwtKeys.PublicKeyBase64,
                    ["Jwt:KeyId"] = TestJwtKeys.KeyId,
                    ["AuthService:Url"] = "http://auth.test/graphql",
                    ["UploadStorage:RootPath"] = storageRoot,
                    ["UploadStorage:StagedUploadsEnabled"] = "true",
                    ["UploadStorage:PendingLifetimeMinutes"] = "60",
                    ["InternalApi:SharedSecret"] = InternalSecret,
                    ["InternalAuth:RequireSignature"] = requireInternalSignature.ToString(),
                    ["InternalAuth:SendLegacySecret"] = "false",
                    ["ConnectionStrings:SecurityRedis"] = "test.invalid:6379"
                });
            });

            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IInternalNonceStore>();
                services.AddSingleton<IInternalNonceStore, TestNonceStore>();
                services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
                {
                    options.TokenValidationParameters.IssuerSigningKeys =
                    [
                        new RsaSecurityKey(CreateTestPublicKey()) { KeyId = TestJwtKeys.KeyId }
                    ];
                    options.TokenValidationParameters.ValidIssuer = "fakebook-auth";
                    options.TokenValidationParameters.ValidAudience = "fakebook";
                });
                services.AddHttpClient("auth-service")
                    .ConfigurePrimaryHttpMessageHandler(() => AuthHandler);
            });
        }

        private static RSA CreateTestPublicKey()
        {
            var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(TestJwtKeys.PublicKeyBase64), out _);
            return rsa;
        }
    }

    private sealed class TestNonceStore : IInternalNonceStore
    {
        private readonly HashSet<string> _claimed = new(StringComparer.Ordinal);
        private readonly object _sync = new();

        public Task<InternalNonceClaimResult> TryClaimAsync(
            string audience,
            string nonce,
            TimeSpan retention,
            CancellationToken cancellationToken)
        {
            lock (_sync)
            {
                return Task.FromResult(_claimed.Add($"{audience}:{nonce}")
                    ? InternalNonceClaimResult.Claimed
                    : InternalNonceClaimResult.Duplicate);
            }
        }

        public Task<bool> IsAvailableAsync(CancellationToken cancellationToken) => Task.FromResult(true);
    }

    private sealed class RecordingInternalRequestHandler : HttpMessageHandler
    {
        public Dictionary<string, string> Headers { get; } = new(StringComparer.OrdinalIgnoreCase);
        public byte[] Body { get; private set; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            foreach (var header in request.Headers)
            {
                Headers[header.Key] = string.Join(",", header.Value);
            }
            Body = request.Content is null
                ? []
                : await request.Content.ReadAsByteArrayAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK);
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
