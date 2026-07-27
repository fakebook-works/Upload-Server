using System.Buffers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using IOPath = System.IO.Path;

const string UploadRateLimitPolicy = "upload";

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddFakebookServiceDefaults(builder.Configuration, "fakebook-upload");

builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = UploadSecurity.MaxRequestBodyBytes;
});
builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = UploadSecurity.MaxRequestBodyBytes;
});

builder.Services
    .AddOptions<UploadStorageOptions>()
    .Bind(builder.Configuration.GetSection(UploadStorageOptions.SectionName));

builder.Services
    .AddOptions<UploadInternalApiOptions>()
    .Bind(builder.Configuration.GetSection(UploadInternalApiOptions.SectionName));
builder.Services.AddInternalRequestSigning(
    builder.Configuration,
    "InternalApi:SharedSecret",
    "X-Internal-UploadService-Secret");

builder.Services.AddSingleton<UploadAssetStore>();
builder.Services.AddHostedService<UploadAssetCleanupService>();

builder.Services
    .AddOptions<UploadRateLimitOptions>()
    .Bind(builder.Configuration.GetSection(UploadRateLimitOptions.SectionName));

// Per-user throttle for the write endpoints. Media bytes never pass through the
// Gateway, so this is the only place upload abuse (storage exhaustion, CPU on the
// content audit) can be bounded. Limits are generous so normal composing never trips.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy(UploadRateLimitPolicy, context =>
    {
        var settings = context.RequestServices
            .GetRequiredService<IOptions<UploadRateLimitOptions>>().Value;
        if (!settings.Enabled)
        {
            return RateLimitPartition.GetNoLimiter("upload-disabled");
        }

        var window = TimeSpan.FromSeconds(Math.Max(1, settings.WindowSeconds));
        var partitionKey = UploadIdentity.TryGetPositiveInt64Claim(context.User, "user_id", out var userId)
            ? $"u:{userId}"
            : $"ip:{context.Connection.RemoteIpAddress?.ToString() ?? "unknown"}";

        return RateLimitPartition.GetFixedWindowLimiter(partitionKey, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = Math.Max(1, settings.PermitLimit),
            Window = window,
            QueueLimit = 0,
            AutoReplenishment = true
        });
    });
});

builder.Services
    .AddOptions<AuthServiceOptions>()
    .Bind(builder.Configuration.GetSection(AuthServiceOptions.SectionName))
    .Validate(
        options => Uri.TryCreate(options.Url, UriKind.Absolute, out var uri) &&
                   (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps),
        "AuthService:Url must be an absolute HTTP or HTTPS URL.")
    .ValidateOnStart();

builder.Services
    .AddOptions<JwtOptions>()
    .Bind(builder.Configuration.GetSection(JwtOptions.SectionName))
    .Validate(options => !string.IsNullOrWhiteSpace(options.Issuer), "Jwt:Issuer is required.")
    .Validate(options => !string.IsNullOrWhiteSpace(options.Audience), "Jwt:Audience is required.")
    .Validate(options => options.HasValidPublicKey(),
        "Jwt:PublicKeyBase64 must be a valid SubjectPublicKeyInfo RSA key of at least 2048 bits.")
    .Validate(options => !string.IsNullOrWhiteSpace(options.KeyId) && options.KeyId.Length <= 64,
        "Jwt:KeyId is required and must be at most 64 characters.")
    .Validate(options => string.IsNullOrEmpty(options.LegacySigningKey) || Encoding.UTF8.GetByteCount(options.LegacySigningKey) >= 32,
        "Jwt:LegacySigningKey must be empty or at least 32 bytes.")
    .ValidateOnStart();

builder.Services.AddCors(options =>
{
    options.AddPolicy("Frontend", policy =>
    {
        var origins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ??
                      ["http://localhost:5173", "http://127.0.0.1:5173"];

        policy
            .WithOrigins(origins)
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer();

builder.Services
    .AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<IOptions<JwtOptions>>((options, configuredJwtOptions) =>
    {
        var jwtOptions = configuredJwtOptions.Value;
        var signingKeys = new List<SecurityKey> { jwtOptions.CreatePublicSecurityKey() };
        if (!string.IsNullOrEmpty(jwtOptions.LegacySigningKey))
        {
            signingKeys.Add(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.LegacySigningKey)));
        }
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = signingKeys,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256, SecurityAlgorithms.HmacSha256],
            RequireSignedTokens = true,
            ValidateIssuer = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtOptions.Audience,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.Zero,
            NameClaimType = "user_id"
        };
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = context =>
            {
                if (!UploadIdentity.TryGetPositiveInt64Claim(context.Principal, "user_id", out _))
                {
                    context.Fail("The access token does not contain a valid user_id claim.");
                }
                else if (!UploadIdentity.TryGetPositiveInt64Claim(context.Principal, "sid", out _))
                {
                    context.Fail("The access token does not contain a valid sid claim.");
                }

                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddHttpClient("auth-service", client =>
{
    client.Timeout = TimeSpan.FromSeconds(5);
});

var app = builder.Build();

// Served media is user-supplied, so stop browsers from MIME-sniffing a stored file
// into an executable type regardless of the Content-Type we set on it.
app.Use(async (context, next) =>
{
    context.Response.OnStarting(() =>
    {
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        return Task.CompletedTask;
    });
    await next(context);
});

app.UseMiddleware<InternalRequestSignatureMiddleware>();
app.UseCors("Frontend");
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

// Validate authenticated sessions against the Auth service
app.Use(async (context, next) =>
{
    if (context.User.Identity?.IsAuthenticated == true)
    {
        if (!UploadIdentity.TryGetPositiveInt64Claim(context.User, "user_id", out var tokenUserId))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        var authOptions = context.RequestServices.GetRequiredService<IOptions<AuthServiceOptions>>().Value;
        var httpClientFactory = context.RequestServices.GetRequiredService<IHttpClientFactory>();
        var client = httpClientFactory.CreateClient("auth-service");

        var authHeader = context.Request.Headers.Authorization.ToString();
        if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var token = authHeader["Bearer ".Length..].Trim();

            using var authRequest = new HttpRequestMessage(HttpMethod.Post, authOptions.Url);
            authRequest.Headers.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            authRequest.Content = new StringContent(
                JsonSerializer.Serialize(new { query = "{ me { userId } }" }),
                Encoding.UTF8,
                "application/json");

            try
            {
                using var response = await client.SendAsync(authRequest, context.RequestAborted);
                var body = await response.Content.ReadAsStringAsync(context.RequestAborted);

                if (!response.IsSuccessStatusCode || !AuthSessionValidation.HasAuthenticatedUser(body, tokenUserId))
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(
                        JsonSerializer.Serialize(new { error = "Auth session validation failed." }),
                        context.RequestAborted);
                    return;
                }
            }
            catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
            {
                throw;
            }
            catch (HttpRequestException)
            {
                await AuthSessionValidation.WriteUnavailableAsync(context);
                return;
            }
            catch (OperationCanceledException)
            {
                await AuthSessionValidation.WriteUnavailableAsync(context);
                return;
            }
            catch (JsonException)
            {
                await AuthSessionValidation.WriteUnavailableAsync(context);
                return;
            }
        }
    }

    await next(context);
});

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));
app.MapGet("/health/ready", async (IInternalNonceStore nonceStore, CancellationToken cancellationToken) =>
    await nonceStore.IsAvailableAsync(cancellationToken)
        ? Results.Ok(new { status = "ready" })
        : Results.StatusCode(StatusCodes.Status503ServiceUnavailable));

// Direct file upload – Bearer token validated locally (JWT) + verified with Auth service
app.MapPost("/media/upload", async (
        ClaimsPrincipal user,
        HttpRequest request,
        IOptions<UploadStorageOptions> options,
        UploadAssetStore assetStore,
        CancellationToken cancellationToken) =>
    {
        if (!request.HasFormContentType)
        {
            return Results.BadRequest(new { error = "multipart/form-data is required." });
        }

        var form = await request.ReadFormAsync(cancellationToken);
        var file = form.Files.GetFile("file");
        if (file is null)
        {
            return Results.BadRequest(new { error = "File field 'file' is required." });
        }

        var metadata = UploadSecurity.ValidateMetadata(file.FileName, file.ContentType, file.Length);
        if (!metadata.IsAllowed)
        {
            return Results.BadRequest(new { error = metadata.Error });
        }

        if (!UploadIdentity.TryGetPositiveInt64Claim(user, "user_id", out var ownerUserId))
        {
            return Results.Unauthorized();
        }

        var stored = await UploadSecurity.StoreValidatedFileAsync(file, ownerUserId, options.Value, assetStore, cancellationToken);
        return stored.IsAllowed && stored.Response is not null
            ? Results.Ok(stored.Response)
            : Results.BadRequest(new { error = stored.Error });
    })
    .RequireAuthorization()
    .RequireRateLimiting(UploadRateLimitPolicy)
    .DisableAntiforgery();

// Batch upload – multiple files in a single request
app.MapPost("/media/upload-multiple", async (
        ClaimsPrincipal user,
        HttpRequest request,
        IOptions<UploadStorageOptions> options,
        UploadAssetStore assetStore,
        CancellationToken cancellationToken) =>
    {
        if (!request.HasFormContentType)
        {
            return Results.BadRequest(new { error = "multipart/form-data is required." });
        }

        var form = await request.ReadFormAsync(cancellationToken);
        if (form.Files.Count == 0)
        {
            return Results.BadRequest(new { error = "At least one file is required." });
        }

        if (form.Files.Count > 10)
        {
            return Results.BadRequest(new { error = "Maximum 10 files per upload." });
        }

        var results = new List<object>();
        var hasErrors = false;
        if (!UploadIdentity.TryGetPositiveInt64Claim(user, "user_id", out var ownerUserId))
        {
            return Results.Unauthorized();
        }

        foreach (var file in form.Files)
        {
            var metadata = UploadSecurity.ValidateMetadata(file.FileName, file.ContentType, file.Length);
            if (!metadata.IsAllowed)
            {
                results.Add(new { name = file.FileName, error = metadata.Error });
                hasErrors = true;
                continue;
            }

            var stored = await UploadSecurity.StoreValidatedFileAsync(file, ownerUserId, options.Value, assetStore, cancellationToken);
            if (stored.IsAllowed && stored.Response is not null)
            {
                results.Add(new
                {
                    name = file.FileName,
                    url = stored.Response.Url,
                    type = stored.Response.Type,
                    contentType = stored.Response.ContentType,
                    size = stored.Response.Size,
                    assetId = stored.Response.AssetId,
                    state = stored.Response.State,
                    expiresAt = stored.Response.ExpiresAt
                });
            }
            else
            {
                results.Add(new { name = file.FileName, error = stored.Error });
                hasErrors = true;
            }
        }

        return hasErrors
            ? Results.Json(new { files = results, hasErrors = true }, statusCode: 207)
            : Results.Ok(new { files = results, hasErrors = false });
    })
    .RequireAuthorization()
    .RequireRateLimiting(UploadRateLimitPolicy)
    .DisableAntiforgery();

app.MapDelete("/media/assets/{assetId}", async (
        string assetId,
        ClaimsPrincipal user,
        UploadAssetStore assetStore,
        CancellationToken cancellationToken) =>
    {
        if (!UploadIdentity.TryGetPositiveInt64Claim(user, "user_id", out var ownerUserId))
        {
            return Results.Unauthorized();
        }
        return await assetStore.DeletePendingOwnedAsync(assetId, ownerUserId, cancellationToken)
            ? Results.NoContent()
            : Results.NotFound();
    })
    .RequireAuthorization();

app.MapPost("/media/assets/finalize", async (
        MediaAssetIdsRequest body,
        ClaimsPrincipal user,
        UploadAssetStore assetStore,
        CancellationToken cancellationToken) =>
    {
        if (!UploadIdentity.TryGetPositiveInt64Claim(user, "user_id", out var ownerUserId))
        {
            return Results.Unauthorized();
        }
        var count = await assetStore.FinalizeOwnedAsync(body.AssetIds ?? Array.Empty<string>(), ownerUserId, cancellationToken);
        return Results.Ok(new { finalized = count });
    })
    .RequireAuthorization();

app.MapPost("/internal/media/finalize", async (
        MediaUrlsRequest body,
        HttpRequest request,
        IOptions<UploadInternalApiOptions> internalOptions,
        UploadAssetStore assetStore,
        CancellationToken cancellationToken) =>
    {
        if (!UploadInternalAuthentication.IsAuthorized(request, internalOptions.Value))
        {
            return Results.Unauthorized();
        }
        var count = await assetStore.FinalizeAsync(
            body.Urls ?? Array.Empty<string>(),
            body.OwnerUserId,
            cancellationToken);
        return Results.Ok(new { finalized = count });
    });

// Ownership probe used by domain services before they persist a client-supplied media URL.
// Without it a caller can attach — and therefore later delete — media owned by another user.
app.MapPost("/internal/media/authorize", async (
        MediaUrlsRequest body,
        HttpRequest request,
        IOptions<UploadInternalApiOptions> internalOptions,
        UploadAssetStore assetStore,
        CancellationToken cancellationToken) =>
    {
        if (!UploadInternalAuthentication.IsAuthorized(request, internalOptions.Value))
        {
            return Results.Unauthorized();
        }
        if (body.OwnerUserId is not { } ownerUserId)
        {
            return Results.BadRequest(new { error = "ownerUserId is required." });
        }
        var unauthorized = await assetStore.FindUnauthorizedUrlsAsync(
            body.Urls ?? Array.Empty<string>(),
            ownerUserId,
            cancellationToken);
        return Results.Ok(new { authorized = unauthorized.Count == 0, unauthorizedUrls = unauthorized });
    });

app.MapPost("/internal/media/delete", async (
        MediaUrlsRequest body,
        HttpRequest request,
        IOptions<UploadInternalApiOptions> internalOptions,
        UploadAssetStore assetStore,
        CancellationToken cancellationToken) =>
    {
        if (!UploadInternalAuthentication.IsAuthorized(request, internalOptions.Value))
        {
            return Results.Unauthorized();
        }
        var count = await assetStore.DeleteByUrlsAsync(
            body.Urls ?? Array.Empty<string>(),
            body.OwnerUserId,
            cancellationToken);
        return Results.Ok(new { deleted = count });
    });

// Serve uploaded files
app.MapGet("/media/files/{fileName}", (string fileName, IOptions<UploadStorageOptions> options) =>
{
    if (!UploadSecurity.IsSafeLeafFileName(fileName))
    {
        return Results.BadRequest(new { error = "Invalid media path." });
    }

    var root = UploadSecurity.ResolveStorageRoot(options.Value);
    var path = IOPath.GetFullPath(IOPath.Combine(root, fileName));
    if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase) || !File.Exists(path))
    {
        return Results.NotFound();
    }

    return Results.File(path, UploadSecurity.ResolveContentTypeFromExtension(IOPath.GetExtension(path)), enableRangeProcessing: true);
});

app.Run();

public partial class Program;

// --- Configuration Options ---

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";
    public string Issuer { get; init; } = "fakebook-auth";
    public string Audience { get; init; } = "fakebook";
    public string PublicKeyBase64 { get; init; } = string.Empty;
    public string KeyId { get; init; } = "fakebook-rs256-2026-01";
    public string LegacySigningKey { get; init; } = string.Empty;

    public RsaSecurityKey CreatePublicSecurityKey()
    {
        var rsa = RSA.Create();
        try
        {
            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(PublicKeyBase64), out var bytesRead);
            if (bytesRead == 0 || rsa.KeySize < 2048)
            {
                throw new CryptographicException("RSA public key is too small.");
            }

            return new RsaSecurityKey(rsa) { KeyId = KeyId };
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    public bool HasValidPublicKey()
    {
        try
        {
            var key = CreatePublicSecurityKey();
            key.Rsa?.Dispose();
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}

public sealed class UploadStorageOptions
{
    public const string SectionName = "UploadStorage";
    public string RootPath { get; init; } = ".data/media";
    public bool StagedUploadsEnabled { get; init; }
    public int PendingLifetimeMinutes { get; init; } = 1_440;
    public int CleanupIntervalMinutes { get; init; } = 10;
}

public sealed class UploadInternalApiOptions
{
    public const string SectionName = "InternalApi";
    public string SharedSecret { get; init; } = string.Empty;
}

public sealed class UploadRateLimitOptions
{
    public const string SectionName = "RateLimit";

    /// <summary>Master switch. When false no limiter is attached to the upload endpoints.</summary>
    public bool Enabled { get; init; } = true;

    /// <summary>Fixed-window length in seconds.</summary>
    public int WindowSeconds { get; init; } = 60;

    /// <summary>
    /// Uploads allowed per window per user (falls back to client IP for anonymous callers,
    /// which are rejected at authorization anyway). Deliberately generous so a normal
    /// compose/batch never trips; it caps a single abusive account.
    /// </summary>
    public int PermitLimit { get; init; } = 120;
}

public sealed class AuthServiceOptions
{
    public const string SectionName = "AuthService";
    public string Url { get; init; } = "http://localhost:1001/graphql";
}

// --- Response Records ---

public sealed record MediaUploadResponse(
    string Url,
    string Type,
    string ContentType,
    long Size,
    string Name,
    string AssetId,
    string State,
    DateTimeOffset? ExpiresAt);

public sealed record MediaUrlsRequest(IReadOnlyList<string>? Urls, long? OwnerUserId = null);
public sealed record MediaAssetIdsRequest(IReadOnlyList<string>? AssetIds);

internal static class UploadInternalAuthentication
{
    private const string HeaderName = "X-Internal-UploadService-Secret";

    public static bool IsAuthorized(HttpRequest request, UploadInternalApiOptions options)
    {
        var expected = options.SharedSecret ?? string.Empty;
        if (Encoding.UTF8.GetByteCount(expected) < 32 ||
            !request.Headers.TryGetValue(HeaderName, out var provided))
        {
            return false;
        }
        var expectedBytes = Encoding.UTF8.GetBytes(expected);
        var providedBytes = Encoding.UTF8.GetBytes(provided.ToString());
        return expectedBytes.Length == providedBytes.Length &&
               System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(expectedBytes, providedBytes);
    }
}

internal static class AuthSessionValidation
{
    public static async Task WriteUnavailableAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(
            JsonSerializer.Serialize(new { error = "Auth service unavailable." }),
            context.RequestAborted);
    }

    public static bool HasAuthenticatedUser(string responseBody, long expectedUserId)
    {
        using var document = JsonDocument.Parse(responseBody);
        var root = document.RootElement;

        if (root.TryGetProperty("errors", out var errors) &&
            errors.ValueKind == JsonValueKind.Array &&
            errors.GetArrayLength() > 0)
        {
            return false;
        }

        if (!root.TryGetProperty("data", out var data) ||
            data.ValueKind != JsonValueKind.Object ||
            !data.TryGetProperty("me", out var me) ||
            me.ValueKind != JsonValueKind.Object ||
            !me.TryGetProperty("userId", out var userId))
        {
            return false;
        }

        return userId.ValueKind switch
        {
            JsonValueKind.Number => userId.TryGetInt64(out var numericUserId) && numericUserId == expectedUserId,
            JsonValueKind.String => long.TryParse(userId.GetString(), out var stringUserId) && stringUserId == expectedUserId,
            _ => false
        };
    }
}

internal static class UploadIdentity
{
    public static bool TryGetPositiveInt64Claim(
        ClaimsPrincipal? principal,
        string claimType,
        out long value)
    {
        value = 0;
        var claims = principal?.FindAll(claimType).ToArray();
        return claims is { Length: 1 } &&
               long.TryParse(claims[0].Value, out value) &&
               value > 0;
    }
}

// --- Upload Security ---

internal static class UploadSecurity
{
    public const long MaxStandardUploadBytes = 25 * 1024 * 1024;
    public const long MaxVideoUploadBytes = 100 * 1024 * 1024;
    public const long MaxRequestBodyBytes = MaxVideoUploadBytes + (2 * 1024 * 1024);

    private static readonly IReadOnlyDictionary<string, MediaKind> AllowedTypes = new Dictionary<string, MediaKind>(StringComparer.OrdinalIgnoreCase)
    {
        ["image/jpeg"] = new("image", ".jpg", [".jpg", ".jpeg"]),
        ["image/png"] = new("image", ".png", [".png"]),
        ["image/gif"] = new("image", ".gif", [".gif"]),
        ["image/webp"] = new("image", ".webp", [".webp"]),
        ["audio/webm"] = new("audio", ".webm", [".webm"]),
        ["audio/mp4"] = new("audio", ".m4a", [".m4a", ".mp4"]),
        ["video/mp4"] = new("video", ".mp4", [".mp4"]),
        ["application/pdf"] = new("file", ".pdf", [".pdf"]),
        ["application/msword"] = new("file", ".doc", [".doc"]),
        ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"] = new("file", ".docx", [".docx"]),
        ["application/vnd.ms-excel"] = new("file", ".xls", [".xls"]),
        ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = new("file", ".xlsx", [".xlsx"]),
        ["application/vnd.ms-powerpoint"] = new("file", ".ppt", [".ppt"]),
        ["application/vnd.openxmlformats-officedocument.presentationml.presentation"] = new("file", ".pptx", [".pptx"]),
        ["text/plain"] = new("file", ".txt", [".txt"]),
        ["text/csv"] = new("file", ".csv", [".csv"]),
        ["application/csv"] = new("file", ".csv", [".csv"]),
        ["application/rtf"] = new("file", ".rtf", [".rtf"]),
        ["text/rtf"] = new("file", ".rtf", [".rtf"])
    };

    private static readonly byte[][] SuspiciousPayloadTokens =
    [
        "<?php"u8.ToArray(),
        "<script"u8.ToArray(),
        "eval("u8.ToArray(),
        "powershell"u8.ToArray(),
        "cmd.exe"u8.ToArray(),
        "/bin/sh"u8.ToArray(),
        "system("u8.ToArray(),
        "shell_exec"u8.ToArray(),
        "wscript.shell"u8.ToArray(),
        "mshta"u8.ToArray(),
        "base64_decode"u8.ToArray(),
        "fromcharcode"u8.ToArray()
    ];

    private static readonly byte[][] ActiveImageMarkupTokens =
    [
        "<html"u8.ToArray(),
        "<svg"u8.ToArray()
    ];

    private static readonly int AuditOverlapBytes =
        Math.Max(
            SuspiciousPayloadTokens.Max(token => token.Length),
            ActiveImageMarkupTokens.Max(token => token.Length)) - 1;

    public static MetadataValidation ValidateMetadata(string? fileName, string? contentType, long size)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return MetadataValidation.Rejected("File name is required.");
        }

        if (!IsSafeLeafFileName(fileName))
        {
            return MetadataValidation.Rejected("File name contains an unsafe path.");
        }

        if (size <= 0)
        {
            return MetadataValidation.Rejected("File size must be at least 1 byte.");
        }

        var normalizedContentType = ResolveAllowedContentType(fileName, contentType);
        if (!AllowedTypes.TryGetValue(normalizedContentType, out var mediaKind))
        {
            return MetadataValidation.Rejected("File type is not allowed.");
        }

        var maxUploadBytes = normalizedContentType.StartsWith("video/", StringComparison.OrdinalIgnoreCase)
            ? MaxVideoUploadBytes
            : MaxStandardUploadBytes;
        if (size > maxUploadBytes)
        {
            return MetadataValidation.Rejected($"File size must not exceed {maxUploadBytes} bytes.");
        }

        var extension = IOPath.GetExtension(fileName);
        if (!mediaKind.AllowedExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase))
        {
            return MetadataValidation.Rejected("File extension does not match the declared type.");
        }

        return MetadataValidation.Accepted();
    }

    public static async Task<UploadValidationResult> StoreValidatedFileAsync(
        IFormFile file,
        long ownerUserId,
        UploadStorageOptions options,
        UploadAssetStore assetStore,
        CancellationToken cancellationToken)
    {
        var metadata = ValidateMetadata(file.FileName, file.ContentType, file.Length);
        if (!metadata.IsAllowed)
        {
            return UploadValidationResult.Rejected(metadata.Error);
        }

        await using var input = file.OpenReadStream();
        var headLength = (int)Math.Min(8192, file.Length);
        var head = new byte[headLength];
        var read = await input.ReadAsync(head.AsMemory(0, headLength), cancellationToken);
        Array.Resize(ref head, read);

        var contentType = ResolveAllowedContentType(file.FileName, file.ContentType);
        if (!MatchesMagicHeader(contentType, head))
        {
            return UploadValidationResult.Rejected("File content does not match the declared type.");
        }

        var audit = await AuditPayloadAsync(contentType, input, cancellationToken);
        if (!audit.IsAllowed)
        {
            return UploadValidationResult.Rejected(audit.Error);
        }

        input.Position = 0;
        var root = ResolveStorageRoot(options);
        Directory.CreateDirectory(root);

        var kind = AllowedTypes[contentType];
        var storedName = $"{Guid.NewGuid():N}{kind.StorageExtension}";
        var destination = IOPath.GetFullPath(IOPath.Combine(root, storedName));
        if (!destination.StartsWith(root, StringComparison.OrdinalIgnoreCase))
        {
            return UploadValidationResult.Rejected("Invalid storage path.");
        }

        try
        {
            await using (var output = File.Create(destination))
            {
                await input.CopyToAsync(output, cancellationToken);
            }

            var metadataRecord = await assetStore.RegisterAsync(
                storedName,
                ownerUserId,
                IOPath.GetFileName(file.FileName),
                contentType,
                file.Length,
                cancellationToken);

            return UploadValidationResult.Accepted(new MediaUploadResponse(
                $"/media/files/{storedName}",
                kind.Category,
                contentType,
                file.Length,
                IOPath.GetFileName(file.FileName),
                metadataRecord.AssetId,
                metadataRecord.State,
                metadataRecord.ExpiresAt));
        }
        catch
        {
            if (File.Exists(destination))
            {
                File.Delete(destination);
            }

            throw;
        }
    }

    public static MetadataValidation AuditPayload(string contentType, byte[] head)
    {
        if (head.Length >= 2 && head[0] == 0x4D && head[1] == 0x5A)
        {
            return MetadataValidation.Rejected("Executable payloads are not allowed.");
        }

        var text = Encoding.UTF8.GetString(head).ToLowerInvariant();
        string[] suspiciousTokens =
        [
            "<?php",
            "<script",
            "eval(",
            "powershell",
            "cmd.exe",
            "/bin/sh",
            "system(",
            "shell_exec",
            "wscript.shell",
            "mshta",
            "base64_decode",
            "fromcharcode"
        ];

        if (suspiciousTokens.Any(text.Contains))
        {
            return MetadataValidation.Rejected("File failed active-content audit.");
        }

        if (contentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase) &&
            (text.Contains("<html", StringComparison.OrdinalIgnoreCase) || text.Contains("<svg", StringComparison.OrdinalIgnoreCase)))
        {
            return MetadataValidation.Rejected("Image upload contains active markup.");
        }

        return MetadataValidation.Accepted();
    }

    public static async Task<MetadataValidation> AuditPayloadAsync(
        string contentType,
        Stream input,
        CancellationToken cancellationToken)
    {
        var originalPosition = input.CanSeek ? input.Position : 0;
        if (input.CanSeek)
        {
            input.Position = 0;
        }

        var readBuffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        var scanWindow = ArrayPool<byte>.Shared.Rent(readBuffer.Length + AuditOverlapBytes);
        var overlap = new byte[AuditOverlapBytes];
        var overlapLength = 0;
        long totalRead = 0;
        var maxBytes = contentType.StartsWith("video/", StringComparison.OrdinalIgnoreCase)
            ? MaxVideoUploadBytes
            : MaxStandardUploadBytes;

        try
        {
            while (true)
            {
                var read = await input.ReadAsync(readBuffer.AsMemory(0, readBuffer.Length), cancellationToken);
                if (read == 0)
                {
                    break;
                }

                var firstChunk = totalRead == 0;
                totalRead += read;
                if (totalRead > maxBytes)
                {
                    return MetadataValidation.Rejected($"File size must not exceed {maxBytes} bytes.");
                }

                var auditError = ScanAuditChunk(
                    contentType,
                    readBuffer,
                    read,
                    scanWindow,
                    overlap,
                    ref overlapLength,
                    firstChunk);
                if (auditError is not null)
                {
                    return MetadataValidation.Rejected(auditError);
                }
            }

            return MetadataValidation.Accepted();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(readBuffer, clearArray: true);
            ArrayPool<byte>.Shared.Return(scanWindow, clearArray: true);
            if (input.CanSeek)
            {
                input.Position = originalPosition;
            }
        }
    }

    private static string? ScanAuditChunk(
        string contentType,
        byte[] readBuffer,
        int read,
        byte[] scanWindow,
        byte[] overlap,
        ref int overlapLength,
        bool firstChunk)
    {
        if (firstChunk && read >= 2 && readBuffer[0] == 0x4D && readBuffer[1] == 0x5A)
        {
            return "Executable payloads are not allowed.";
        }

        overlap.AsSpan(0, overlapLength).CopyTo(scanWindow);
        readBuffer.AsSpan(0, read).CopyTo(scanWindow.AsSpan(overlapLength));
        var windowLength = overlapLength + read;
        var window = scanWindow.AsSpan(0, windowLength);
        LowercaseAsciiInPlace(window.Slice(overlapLength));

        if (ContainsAnyToken(window, SuspiciousPayloadTokens))
        {
            return "File failed active-content audit.";
        }

        if (contentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase) &&
            ContainsAnyToken(window, ActiveImageMarkupTokens))
        {
            return "Image upload contains active markup.";
        }

        overlapLength = Math.Min(AuditOverlapBytes, windowLength);
        window.Slice(windowLength - overlapLength, overlapLength).CopyTo(overlap);
        return null;
    }

    private static bool ContainsAnyToken(ReadOnlySpan<byte> bytes, byte[][] tokens)
    {
        foreach (var token in tokens)
        {
            if (bytes.IndexOf(token) >= 0)
            {
                return true;
            }
        }

        return false;
    }

    private static void LowercaseAsciiInPlace(Span<byte> bytes)
    {
        for (var index = 0; index < bytes.Length; index++)
        {
            if (bytes[index] is >= (byte)'A' and <= (byte)'Z')
            {
                bytes[index] = (byte)(bytes[index] + 32);
            }
        }
    }

    public static bool IsSafeLeafFileName(string fileName)
    {
        var safeName = IOPath.GetFileName(fileName);
        return string.Equals(safeName, fileName, StringComparison.Ordinal) &&
               !fileName.Contains("..", StringComparison.Ordinal) &&
               fileName.IndexOfAny(IOPath.GetInvalidFileNameChars()) < 0;
    }

    public static string ResolveStorageRoot(UploadStorageOptions options)
    {
        var configured = string.IsNullOrWhiteSpace(options.RootPath)
            ? IOPath.Combine(AppContext.BaseDirectory, "media-files")
            : options.RootPath;
        return IOPath.GetFullPath(configured);
    }

    public static string ResolveContentTypeFromExtension(string extension) =>
        extension.ToLowerInvariant() switch
        {
            ".jpg" or ".jpeg" => "image/jpeg",
            ".png" => "image/png",
            ".gif" => "image/gif",
            ".webp" => "image/webp",
            ".webm" => "audio/webm",
            ".m4a" => "audio/mp4",
            ".mp4" => "video/mp4",
            ".pdf" => "application/pdf",
            ".doc" => "application/msword",
            ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xls" => "application/vnd.ms-excel",
            ".xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".ppt" => "application/vnd.ms-powerpoint",
            ".pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ".txt" => "text/plain",
            ".csv" => "text/csv",
            ".rtf" => "application/rtf",
            _ => "application/octet-stream"
        };

    private static bool MatchesMagicHeader(string contentType, byte[] head) =>
        contentType switch
        {
            "image/jpeg" => head.Length >= 3 && head[0] == 0xFF && head[1] == 0xD8 && head[2] == 0xFF,
            "image/png" => HasPrefix(head, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A),
            "image/gif" => head.Length >= 6 && (head.AsSpan(0, 6).SequenceEqual("GIF87a"u8) || head.AsSpan(0, 6).SequenceEqual("GIF89a"u8)),
            "image/webp" => head.Length >= 12 && head.AsSpan(0, 4).SequenceEqual("RIFF"u8) && head.AsSpan(8, 4).SequenceEqual("WEBP"u8),
            "audio/webm" => HasPrefix(head, 0x1A, 0x45, 0xDF, 0xA3),
            "audio/mp4" => head.Length >= 12 && head.AsSpan(4, 4).SequenceEqual("ftyp"u8),
            "video/mp4" => head.Length >= 12 && head.AsSpan(4, 4).SequenceEqual("ftyp"u8),
            "application/pdf" => head.Length >= 5 && head.AsSpan(0, 5).SequenceEqual("%PDF-"u8),
            "application/msword" or
                "application/vnd.ms-excel" or
                "application/vnd.ms-powerpoint" => HasPrefix(head, 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document" or
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" or
                "application/vnd.openxmlformats-officedocument.presentationml.presentation" => IsZipContainer(head),
            "text/plain" or "text/csv" or "application/csv" => IsLikelyPlainText(head),
            "application/rtf" or "text/rtf" => HasPrefix(head, 0x7B, 0x5C, 0x72, 0x74, 0x66),
            _ => false
        };

    private static bool IsZipContainer(byte[] head) =>
        HasPrefix(head, 0x50, 0x4B, 0x03, 0x04) ||
        HasPrefix(head, 0x50, 0x4B, 0x05, 0x06) ||
        HasPrefix(head, 0x50, 0x4B, 0x07, 0x08);

    private static bool IsLikelyPlainText(byte[] head)
    {
        var start = HasPrefix(head, 0xEF, 0xBB, 0xBF) ? 3 : 0;
        for (var index = start; index < head.Length; index++)
        {
            var value = head[index];
            if (value == 0 || (value < 0x20 && value is not (0x09 or 0x0A or 0x0D)))
            {
                return false;
            }
        }

        return true;
    }

    private static bool HasPrefix(byte[] bytes, params byte[] prefix) =>
        bytes.Length >= prefix.Length && bytes.AsSpan(0, prefix.Length).SequenceEqual(prefix);

    private static string NormalizeContentType(string? contentType) =>
        (contentType ?? string.Empty).Split(';', 2)[0].Trim().ToLowerInvariant();

    private static string ResolveAllowedContentType(string fileName, string? contentType)
    {
        var normalized = NormalizeContentType(contentType);
        if (AllowedTypes.ContainsKey(normalized))
        {
            return normalized;
        }

        if (normalized is "" or "application/octet-stream" or "application/zip" or "application/x-zip-compressed")
        {
            var inferred = ResolveContentTypeFromExtension(IOPath.GetExtension(fileName));
            if (AllowedTypes.ContainsKey(inferred))
            {
                return inferred;
            }
        }

        return normalized;
    }

    private sealed record MediaKind(string Category, string StorageExtension, string[] AllowedExtensions);
}

internal sealed record MetadataValidation(bool IsAllowed, string? Error)
{
    public static MetadataValidation Accepted() => new(true, null);
    public static MetadataValidation Rejected(string error) => new(false, error);
}

internal sealed record UploadValidationResult(bool IsAllowed, string? Error, MediaUploadResponse? Response)
{
    public static UploadValidationResult Accepted(MediaUploadResponse response) => new(true, null, response);
    public static UploadValidationResult Rejected(string? error) => new(false, error ?? "Upload rejected.", null);
}
