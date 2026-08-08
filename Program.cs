using System.Buffers;
using System.Globalization;
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
const int MaxBrowserFinalizeBodyBytes = 64 * 1024;
const int MaxBrowserFinalizeAssets = 512;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddFakebookServiceDefaults(builder.Configuration, "fakebook-upload");

builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = UploadSecurity.MaxRequestBodyBytes;
});
builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = UploadSecurity.MaxRequestBodyBytes;
    // Keep multipart parsing itself bounded. The endpoint-level file-count checks happen
    // after ReadFormAsync, so a hostile caller must not be able to spend one rate-limit
    // permit on thousands of oversized headers/fields before those checks run.
    options.MultipartHeadersCountLimit = 64;
    options.MultipartHeadersLengthLimit = 16 * 1024;
    options.KeyLengthLimit = 256;
    options.ValueLengthLimit = 16 * 1024;
    options.ValueCountLimit = 1_024;
    options.MemoryBufferThreshold = 64 * 1024;
});

builder.Services
    .AddOptions<UploadStorageOptions>()
    .Bind(builder.Configuration.GetSection(UploadStorageOptions.SectionName))
    .Validate(options => options.LifecycleLockTimeoutSeconds is >= 1 and <= 120,
        "UploadStorage:LifecycleLockTimeoutSeconds must be between 1 and 120.")
    .Validate(options => options.AuthorizationReservationMinutes is >= 5 and <= 10_080,
        "UploadStorage:AuthorizationReservationMinutes must be between 5 and 10080.")
    .Validate(options => options.BrowserReservationMinutes is >= 5 and <= 1_440,
        "UploadStorage:BrowserReservationMinutes must be between 5 and 1440.")
    .Validate(options => options.ReferenceDeleteGraceMinutes is >= 0 and <= 10_080,
        "UploadStorage:ReferenceDeleteGraceMinutes must be between 0 and 10080.")
    .Validate(options => options.DeletedTombstoneRetentionMinutes is >= 60 and <= 525_600,
        "UploadStorage:DeletedTombstoneRetentionMinutes must be between 60 and 525600.")
    .Validate(options => options.QuarantineRetentionMinutes is >= 30 and <= 10_080,
        "UploadStorage:QuarantineRetentionMinutes must be between 30 and 10080.")
    .Validate(options => options.ImageLossyQuality is >= 60 and <= 95,
        "UploadStorage:ImageLossyQuality must be between 60 and 95.")
    .Validate(options => options.MaxImageDimension is >= 1_024 and <= 16_384,
        "UploadStorage:MaxImageDimension must be between 1024 and 16384.")
    .Validate(options => options.MaxImagePixels is >= 1_000_000 and <= 50_000_000,
        "UploadStorage:MaxImagePixels must be between 1000000 and 50000000.")
    .Validate(options => options.MaxDecodedImageBytes is >= 16 * 1024 * 1024 and <= 256L * 1024 * 1024,
        "UploadStorage:MaxDecodedImageBytes must be between 16 MiB and 256 MiB.")
    .Validate(options => options.MaxAnimatedImageTotalPixels is >= 1_000_000 and <= 50_000_000,
        "UploadStorage:MaxAnimatedImageTotalPixels must be between 1000000 and 50000000.")
    .Validate(options => options.MaxStoredImageDimension is >= 1_024 and <= 16_384,
        "UploadStorage:MaxStoredImageDimension must be between 1024 and 16384.")
    .Validate(options => (options.PreferredStillImageFormat ?? string.Empty).Trim().ToLowerInvariant()
            is "preserve" or "avif" or "webp" or "jpeg" or "jpg",
        "UploadStorage:PreferredStillImageFormat must be preserve, avif, webp or jpeg.")
    .ValidateOnStart();

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

// A busy/unavailable shared lifecycle store is a temporary infrastructure failure,
// not an application bug and never a reason to acknowledge a parent mutation.
app.Use(async (context, next) =>
{
    try
    {
        await next(context);
    }
    catch (TimeoutException exception)
    {
        context.RequestServices
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger("UploadLifecycle")
            .LogWarning(exception, "Media lifecycle storage timed out.");
        context.Response.Clear();
        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(
            new { error = "Media lifecycle storage is temporarily unavailable." },
            context.RequestAborted);
    }
});

app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/internal/media") ||
        context.Request.Path.Equals("/media/assets/finalize", StringComparison.OrdinalIgnoreCase))
    {
        var maxBodyBytes = context.Request.Path.StartsWithSegments("/internal/media")
            ? UploadSecurity.MaxInternalLifecycleBodyBytes
            : MaxBrowserFinalizeBodyBytes;
        var sizeFeature = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (sizeFeature is { IsReadOnly: false })
        {
            sizeFeature.MaxRequestBodySize = maxBodyBytes;
        }
        if (context.Request.ContentLength > maxBodyBytes)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }
    }
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

        var authorizationValues = context.Request.Headers.Authorization;
        if (authorizationValues.Count != 1)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        var authHeader = authorizationValues[0]!;
        if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var token = authHeader["Bearer ".Length..].Trim();
            if (token.Length is 0 or > AuthSessionValidation.MaxBearerTokenCharacters)
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }

            using var authRequest = new HttpRequestMessage(HttpMethod.Post, authOptions.Url);
            authRequest.Headers.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            authRequest.Content = new StringContent(
                JsonSerializer.Serialize(new { query = "{ me { userId } }" }),
                Encoding.UTF8,
                "application/json");

            try
            {
                using var response = await client.SendAsync(
                    authRequest,
                    HttpCompletionOption.ResponseHeadersRead,
                    context.RequestAborted);
                var body = await AuthSessionValidation.ReadBoundedBodyAsync(
                    response.Content,
                    context.RequestAborted);

                if (!response.IsSuccessStatusCode || body is null ||
                    !AuthSessionValidation.HasAuthenticatedUser(body, tokenUserId))
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
            catch (IOException)
            {
                await AuthSessionValidation.WriteUnavailableAsync(context);
                return;
            }
        }
    }

    await next(context);
});

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));
app.MapGet("/health/ready", async (
        IInternalNonceStore nonceStore,
        UploadAssetStore assetStore,
        CancellationToken cancellationToken) =>
    await nonceStore.IsAvailableAsync(cancellationToken) &&
    await assetStore.IsStorageAvailableAsync(cancellationToken)
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
        if (form.Files.Count != 1)
        {
            return Results.BadRequest(new { error = "Exactly one file is required." });
        }
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
            var displayName = UploadSecurity.NormalizeFileName(file.FileName);
            var metadata = UploadSecurity.ValidateMetadata(file.FileName, file.ContentType, file.Length);
            if (!metadata.IsAllowed)
            {
                results.Add(new { name = displayName, error = metadata.Error });
                hasErrors = true;
                continue;
            }

            var stored = await UploadSecurity.StoreValidatedFileAsync(file, ownerUserId, options.Value, assetStore, cancellationToken);
            if (stored.IsAllowed && stored.Response is not null)
            {
                results.Add(new
                {
                    name = displayName,
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
                results.Add(new { name = displayName, error = stored.Error });
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
    .RequireAuthorization()
    .RequireRateLimiting(UploadRateLimitPolicy);

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
        var rawAssetIds = body.AssetIds ?? Array.Empty<string>();
        if (rawAssetIds.Count > MaxBrowserFinalizeAssets)
        {
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        }
        if (rawAssetIds.Any(assetId => string.IsNullOrWhiteSpace(assetId) ||
                                       !Guid.TryParseExact(assetId, "N", out _)))
        {
            return Results.BadRequest(new { error = "The finalize request contains an invalid asset identifier." });
        }
        var assetIds = rawAssetIds
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var count = await assetStore.FinalizeOwnedAsync(assetIds, ownerUserId, cancellationToken);
        if (count != assetIds.Length)
        {
            // Do not acknowledge a partial browser upload batch. The caller can retry
            // while the staged files are still available instead of leaving pending
            // assets to be deleted silently by the cleanup worker.
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
        return Results.Ok(new { finalized = count });
    })
    .RequireAuthorization()
    .RequireRateLimiting(UploadRateLimitPolicy);

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
        var references = body.References ?? Array.Empty<UploadMediaReference>();
        var suppliedUrls = body.Urls ?? Array.Empty<string>();
        if (references.Count > UploadAssetStore.MaxLifecycleBatchSize)
        {
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        }
        if (suppliedUrls.Count > UploadAssetStore.MaxLifecycleBatchSize)
        {
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        }
        if (references.Count > 0 && suppliedUrls.Count > 0)
        {
            return Results.BadRequest(new { error = "Provide references or legacy URLs, not both." });
        }
        if (references.Count > 0)
        {
            if (body.OwnerUserId is not > 0)
            {
                return Results.BadRequest(new { error = "ownerUserId is required for reference lifecycle requests." });
            }
            if (body.OperationAt is null)
            {
                return Results.BadRequest(new { error = "The finalize request requires operationAt." });
            }
            var referenceResult = await assetStore.AttachReferencesDetailedAsync(
                references,
                body.OwnerUserId,
                body.OperationAt,
                cancellationToken);
            if (referenceResult.NormalizedCount != referenceResult.RequestedCount)
            {
                return Results.BadRequest(new { error = "The finalize request contains an invalid media reference." });
            }
            if (referenceResult.OwnershipMismatchCount > 0)
            {
                return Results.Conflict(new { error = "Media ownership validation failed." });
            }
            if (referenceResult.CapacityExceededCount > 0)
            {
                // Capacity can become available after other parents detach. Treat it as
                // retryable so a committed parent is never permanently left untracked.
                return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
            }
            if (referenceResult.InvalidOperationTimeCount > 0)
            {
                // A required timestamp was supplied above; this branch represents
                // dependency clock skew and must remain retryable after NTP recovers.
                return Results.Json(
                    new { error = "The finalize request operationAt is too far in the future." },
                    statusCode: 425);
            }
            if (referenceResult.MissingFileCount > 0 ||
                referenceResult.MetadataUnavailableCount > 0 ||
                referenceResult.AppliedCount != referenceResult.NormalizedCount)
            {
                return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
            }
            return Results.Ok(new
            {
                finalized = referenceResult.AppliedCount,
                stale = referenceResult.StaleCount
            });
        }

        var urls = suppliedUrls;
        var result = await assetStore.FinalizeDetailedAsync(
            urls,
            body.OwnerUserId,
            cancellationToken);

        // A lifecycle event is a batch contract: acknowledging a partial batch would
        // mark the outbox row complete while the remaining files stay pending and are
        // later removed by expiry cleanup. Invalid/off-server URLs are a caller bug;
        // missing files are a storage visibility failure and must be retried.
        if (result.NormalizedCount != result.RequestedCount)
        {
            return Results.BadRequest(new { error = "The finalize request contains an invalid media URL." });
        }
        if (result.OwnershipMismatchCount > 0)
        {
            return Results.Conflict(new { error = "Media ownership validation failed." });
        }
        if (result.MissingFileCount > 0 ||
            result.MetadataUnavailableCount > 0 ||
            result.FinalizedCount != result.NormalizedCount)
        {
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }

        return Results.Ok(new { finalized = result.FinalizedCount });
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
        if (body.OwnerUserId is not > 0)
        {
            return Results.BadRequest(new { error = "ownerUserId is required." });
        }
        var ownerUserId = body.OwnerUserId.Value;
        var references = body.References ?? Array.Empty<UploadMediaReference>();
        var urls = body.Urls ?? Array.Empty<string>();
        if (references.Count > UploadAssetStore.MaxLifecycleBatchSize ||
            urls.Count > UploadAssetStore.MaxLifecycleBatchSize)
        {
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        }
        if (references.Count > 0 && urls.Count > 0)
        {
            return Results.BadRequest(new { error = "Provide references or legacy URLs, not both." });
        }
        if (references.Count > 0)
        {
            if (body.OperationAt is null)
            {
                return Results.BadRequest(new { error = "The authorize request requires operationAt." });
            }
            var referenceResult = await assetStore.AuthorizeReferencesDetailedAsync(
                references,
                ownerUserId,
                body.OperationAt,
                cancellationToken);
            if (referenceResult.InvalidOperationTimeCount > 0)
            {
                return Results.Json(
                    new { error = "The authorize request operationAt is too far in the future." },
                    statusCode: 425);
            }
            if (referenceResult.NormalizedCount != referenceResult.RequestedCount)
            {
                return Results.BadRequest(new { error = "The authorize request contains an invalid media reference." });
            }
            if (referenceResult.CapacityExceededCount > 0)
            {
                return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
            }
            return Results.Ok(new
            {
                authorized = referenceResult.UnauthorizedUrls.Count == 0,
                unauthorizedUrls = referenceResult.UnauthorizedUrls,
                // A new exact-reference client must require these acknowledgements.
                // Older Upload versions deserialize unknown `references` as an empty
                // legacy URL request and can otherwise return a false-positive success
                // during a rolling deployment.
                exactReferences = true,
                lifecycleVersion = UploadAssetStore.CurrentLifecycleVersion,
                referenceCount = referenceResult.NormalizedCount
            });
        }
        var unauthorized = await assetStore.FindUnauthorizedUrlsAsync(
            urls,
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
        var references = body.References ?? Array.Empty<UploadMediaReference>();
        var urls = body.Urls ?? Array.Empty<string>();
        if (references.Count > UploadAssetStore.MaxLifecycleBatchSize)
        {
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        }
        if (urls.Count > UploadAssetStore.MaxLifecycleBatchSize)
        {
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        }
        if (references.Count > 0 && urls.Count > 0)
        {
            return Results.BadRequest(new { error = "Provide references or legacy URLs, not both." });
        }
        if (references.Count > 0)
        {
            if (body.OperationAt is null)
            {
                return Results.BadRequest(new { error = "The delete request requires operationAt." });
            }
            var result = await assetStore.DetachReferencesDetailedAsync(
                references,
                body.OwnerUserId,
                body.OperationAt,
                cancellationToken);
            if (result.NormalizedCount != result.RequestedCount)
            {
                return Results.BadRequest(new { error = "The delete request contains an invalid media reference." });
            }
            if (result.OwnershipMismatchCount > 0)
            {
                return Results.Conflict(new { error = "Media ownership validation failed." });
            }
            if (result.MetadataUnavailableCount > 0)
            {
                return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
            }
            if (result.InvalidOperationTimeCount > 0)
            {
                return Results.Json(
                    new { error = "The delete request operationAt is too far in the future." },
                    statusCode: 425);
            }
            if (result.CapacityExceededCount > 0)
            {
                return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
            }
            return Results.Ok(new
            {
                detached = result.AppliedCount,
                stale = result.StaleCount
            });
        }

        var count = await assetStore.DeleteByUrlsAsync(
            urls,
            body.OwnerUserId,
            cancellationToken);
        return Results.Ok(new { scheduled = count });
    });

// Serve uploaded files
app.MapGet("/media/files/{fileName}", async (
    string fileName,
    HttpContext context,
    IOptions<UploadStorageOptions> options,
    UploadAssetStore assetStore,
    CancellationToken cancellationToken) =>
{
    if (!UploadSecurity.IsSafeLeafFileName(fileName))
    {
        return Results.BadRequest(new { error = "Invalid media path." });
    }

    var root = UploadSecurity.ResolveStorageRoot(options.Value);
    var path = IOPath.GetFullPath(IOPath.Combine(root, fileName));
    if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase) ||
        !await assetStore.CanServeAsync(fileName, cancellationToken))
    {
        return Results.NotFound();
    }

    // Until a deployment has a verified CDN purge protocol, a client/proxy must not
    // retain bytes after the final parent reference is deleted and tombstoned.
    context.Response.Headers.CacheControl = "private, no-store";
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
    public int CleanupIntervalMinutes { get; init; } = 2;
    public int PendingCleanupGraceMinutes { get; init; } = 120;
    public int ReferenceDeleteGraceMinutes { get; init; } = 0;
    public int AuthorizationReservationMinutes { get; init; } = 10_080;
    public int BrowserReservationMinutes { get; init; } = 120;
    public int DeletedTombstoneRetentionMinutes { get; init; } = 43_200;
    public int QuarantineRetentionMinutes { get; init; } = 60;
    public int LifecycleLockTimeoutSeconds { get; init; } = 15;
    public bool CleanupEnabled { get; init; } = true;
    public string[] AllowedMediaOrigins { get; init; } = Array.Empty<string>();
    public int ImageLossyQuality { get; init; } = 78;
    public int MaxImageDimension { get; init; } = 16_384;
    public long MaxImagePixels { get; init; } = 50_000_000;
    public long MaxDecodedImageBytes { get; init; } = 200L * 1024 * 1024;
    public long MaxAnimatedImageTotalPixels { get; init; } = 50_000_000;
    public int MaxStoredImageDimension { get; init; } = 6_144;
    public string PreferredStillImageFormat { get; init; } = "preserve";
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

public sealed record MediaUrlsRequest(
    IReadOnlyList<string>? Urls = null,
    long? OwnerUserId = null,
    IReadOnlyList<UploadMediaReference>? References = null,
    DateTimeOffset? OperationAt = null);
public sealed record MediaAssetIdsRequest(IReadOnlyList<string>? AssetIds);

internal static class UploadInternalAuthentication
{
    private const string HeaderName = "X-Internal-UploadService-Secret";

    public static bool IsAuthorized(HttpRequest request, UploadInternalApiOptions options)
    {
        var expected = options.SharedSecret ?? string.Empty;
        if (Encoding.UTF8.GetByteCount(expected) < 32 ||
            !request.Headers.TryGetValue(HeaderName, out var provided) ||
            provided.Count != 1)
        {
            return false;
        }
        var expectedBytes = Encoding.UTF8.GetBytes(expected);
        var providedBytes = Encoding.UTF8.GetBytes(provided[0]!);
        return expectedBytes.Length == providedBytes.Length &&
               System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(expectedBytes, providedBytes);
    }
}

internal static class AuthSessionValidation
{
    public const int MaxBearerTokenCharacters = 16 * 1024;
    public const int MaxResponseBytes = 64 * 1024;

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
        using var document = JsonDocument.Parse(responseBody, new JsonDocumentOptions
        {
            MaxDepth = 16,
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow
        });
        var root = document.RootElement;

        if (root.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        if (root.TryGetProperty("errors", out var errors) &&
            (errors.ValueKind != JsonValueKind.Array || errors.GetArrayLength() > 0))
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
            JsonValueKind.String => TryParsePositiveIdentity(userId.GetString(), out var stringUserId) &&
                                    stringUserId == expectedUserId,
            _ => false
        };
    }

    private static bool TryParsePositiveIdentity(string? value, out long userId)
    {
        userId = 0;
        return !string.IsNullOrEmpty(value) &&
               value.Length <= 19 &&
               value.All(char.IsAsciiDigit) &&
               long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out userId) &&
               userId > 0;
    }

    public static async Task<string?> ReadBoundedBodyAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is { } contentLength && contentLength > MaxResponseBytes)
        {
            return null;
        }

        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream(8 * 1024);
        var chunk = new byte[8 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(chunk.AsMemory(), cancellationToken);
            if (read == 0)
            {
                try
                {
                    return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)
                        .GetString(buffer.GetBuffer(), 0, checked((int)buffer.Length));
                }
                catch (DecoderFallbackException)
                {
                    return null;
                }
            }

            if (buffer.Length + read > MaxResponseBytes)
            {
                return null;
            }

            await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken);
        }
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
               claims[0].Value.Length <= 19 &&
               long.TryParse(
                   claims[0].Value,
                   NumberStyles.None,
                   CultureInfo.InvariantCulture,
                   out value) &&
               value > 0;
    }
}

// --- Upload Security ---

internal static class UploadSecurity
{
    public const int MaxOriginalFileNameCharacters = 255;
    public const int MaxOriginalFileNameUtf8Bytes = 1_024;
    public const int MaxContentTypeCharacters = 128;
    public const int MaxCombiningMarksInFileName = 32;
    public const long MaxStandardUploadBytes = 25 * 1024 * 1024;
    public const long MaxVideoUploadBytes = 500 * 1024 * 1024;
    public const long MaxRequestBodyBytes = MaxVideoUploadBytes + (2 * 1024 * 1024);
    public const long MaxInternalLifecycleBodyBytes = 512 * 1024;

    private static readonly IReadOnlyDictionary<string, MediaKind> AllowedTypes = new Dictionary<string, MediaKind>(StringComparer.OrdinalIgnoreCase)
    {
        ["image/jpeg"] = new("image", ".jpg", [".jpg", ".jpeg"]),
        ["image/png"] = new("image", ".png", [".png"]),
        ["image/gif"] = new("image", ".gif", [".gif"]),
        ["image/webp"] = new("image", ".webp", [".webp"]),
        ["image/avif"] = new("image", ".avif", [".avif"]),
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

        if (fileName.Length > MaxOriginalFileNameCharacters ||
            Encoding.UTF8.GetByteCount(fileName) > MaxOriginalFileNameUtf8Bytes)
        {
            return MetadataValidation.Rejected("File name is too long.");
        }

        if ((contentType?.Length ?? 0) > MaxContentTypeCharacters)
        {
            return MetadataValidation.Rejected("Content type is too long.");
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

        var originalKind = AllowedTypes[contentType];
        string? storedName = null;
        string? destination = null;
        UploadAssetMetadata? metadataRecord = null;
        var published = false;

        // A validated stream is still private until its media container has been
        // scrubbed. Quarantine lives below the storage root (same volume for the final
        // atomic move), but cannot be addressed by /media/files/{leafName}.
        var quarantineRoot = IOPath.GetFullPath(IOPath.Combine(root, ".quarantine"));
        if (!quarantineRoot.StartsWith(root, StringComparison.OrdinalIgnoreCase))
        {
            return UploadValidationResult.Rejected("Invalid storage path.");
        }
        Directory.CreateDirectory(quarantineRoot);
        var quarantineId = Guid.NewGuid().ToString("N");
        var sourceQuarantinePath = IOPath.Combine(quarantineRoot, quarantineId + ".source");
        var sanitizedQuarantinePath = IOPath.Combine(quarantineRoot, quarantineId + ".sanitized");

        try
        {
            await using (var quarantine = new FileStream(
                sourceQuarantinePath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                await input.CopyToAsync(quarantine, cancellationToken);
                await quarantine.FlushAsync(cancellationToken);
            }

            var sanitization = await MediaMetadataSanitizer.SanitizeAsync(
                contentType,
                sourceQuarantinePath,
                sanitizedQuarantinePath,
                options,
                cancellationToken);

            var outputContentType = sanitization.ContentType;
            if (!AllowedTypes.TryGetValue(outputContentType, out var outputKind) ||
                outputKind.Category != originalKind.Category)
            {
                return UploadValidationResult.Rejected("Media output type is not allowed.");
            }
            var outputExtension = sanitization.StorageExtension ?? outputKind.StorageExtension;
            storedName = $"{Guid.NewGuid():N}{outputExtension}";
            destination = IOPath.GetFullPath(IOPath.Combine(root, storedName));
            if (!destination.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            {
                return UploadValidationResult.Rejected("Invalid storage path.");
            }

            var sanitizedSize = new FileInfo(sanitizedQuarantinePath).Length;
            var maxSanitizedSize = outputContentType.StartsWith("video/", StringComparison.OrdinalIgnoreCase)
                ? MaxVideoUploadBytes
                : MaxStandardUploadBytes;
            if (sanitizedSize <= 0 || sanitizedSize > maxSanitizedSize)
            {
                return UploadValidationResult.Rejected("Media metadata could not be removed safely.");
            }

            await using (var sanitizedInput = new FileStream(
                sanitizedQuarantinePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                var sanitizedHeadLength = (int)Math.Min(8192, sanitizedSize);
                var sanitizedHead = new byte[sanitizedHeadLength];
                var sanitizedHeadRead = await sanitizedInput.ReadAsync(
                    sanitizedHead.AsMemory(),
                    cancellationToken);
                Array.Resize(ref sanitizedHead, sanitizedHeadRead);
                if (!MatchesMagicHeader(outputContentType, sanitizedHead))
                {
                    return UploadValidationResult.Rejected("Media metadata could not be removed safely.");
                }

                sanitizedInput.Position = 0;
                var sanitizedAudit = await AuditPayloadAsync(
                    outputContentType,
                    sanitizedInput,
                    cancellationToken);
                if (!sanitizedAudit.IsAllowed)
                {
                    return UploadValidationResult.Rejected("Media metadata could not be removed safely.");
                }
            }

            // Make lifecycle state durable before the public path can exist. If the
            // process dies after this write but before the move, pending cleanup sees a
            // normal expired record; the inverse order left untracked public orphans.
            var safeOriginalName = NormalizeFileName(file.FileName);
            metadataRecord = await assetStore.RegisterAsync(
                storedName!,
                ownerUserId,
                safeOriginalName,
                outputContentType,
                sanitizedSize,
                cancellationToken);
            File.Move(sanitizedQuarantinePath, destination!);
            published = true;

            return UploadValidationResult.Accepted(new MediaUploadResponse(
                $"/media/files/{storedName}",
                outputKind.Category,
                outputContentType,
                sanitizedSize,
                safeOriginalName,
                metadataRecord.AssetId,
                metadataRecord.State,
                metadataRecord.ExpiresAt));
        }
        catch (MediaSanitizationException)
        {
            return UploadValidationResult.Rejected("Media metadata could not be removed safely.");
        }
        catch
        {
            if (published && destination is not null && File.Exists(destination))
            {
                File.Delete(destination);
            }
            if (metadataRecord is not null)
            {
                try
                {
                    await assetStore.DeletePendingOwnedAsync(
                        metadataRecord.AssetId,
                        ownerUserId,
                        CancellationToken.None);
                }
                catch
                {
                    // Best effort only: the durable pending record remains bounded by
                    // normal expiry cleanup if rollback storage is temporarily offline.
                }
            }

            throw;
        }
        finally
        {
            if (File.Exists(sourceQuarantinePath))
            {
                File.Delete(sourceQuarantinePath);
            }
            if (File.Exists(sanitizedQuarantinePath))
            {
                File.Delete(sanitizedQuarantinePath);
            }
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
        if (string.IsNullOrEmpty(fileName) ||
            fileName.Length > MaxOriginalFileNameCharacters ||
            Encoding.UTF8.GetByteCount(fileName) > MaxOriginalFileNameUtf8Bytes)
        {
            return false;
        }

        var safeName = IOPath.GetFileName(fileName);
        if (!string.Equals(safeName, fileName, StringComparison.Ordinal) ||
            fileName.Contains("..", StringComparison.Ordinal) ||
            fileName.IndexOfAny(IOPath.GetInvalidFileNameChars()) >= 0)
        {
            return false;
        }

        // Validate the UTF-16 representation before EnumerateRunes. Invalid surrogate
        // sequences would otherwise be surfaced as U+FFFD, making malformed metadata
        // indistinguishable from an intentionally supplied replacement character.
        for (var index = 0; index < fileName.Length; index++)
        {
            var character = fileName[index];
            if (char.IsHighSurrogate(character))
            {
                if (index + 1 >= fileName.Length || !char.IsLowSurrogate(fileName[index + 1]))
                {
                    return false;
                }
                index++;
                continue;
            }
            if (char.IsLowSurrogate(character))
            {
                return false;
            }
        }

        var combiningMarks = 0;
        foreach (var rune in fileName.EnumerateRunes())
        {
            var category = Rune.GetUnicodeCategory(rune);
            if (category is UnicodeCategory.Control or
                UnicodeCategory.Format or
                UnicodeCategory.Surrogate or
                UnicodeCategory.PrivateUse or
                UnicodeCategory.OtherNotAssigned)
            {
                return false;
            }
            if (category is UnicodeCategory.NonSpacingMark or
                UnicodeCategory.SpacingCombiningMark or
                UnicodeCategory.EnclosingMark)
            {
                combiningMarks++;
                if (combiningMarks > MaxCombiningMarksInFileName)
                {
                    return false;
                }
            }
        }

        return true;
    }

    public static string NormalizeFileName(string fileName)
    {
        try
        {
            return fileName.Normalize(NormalizationForm.FormC);
        }
        catch (ArgumentException)
        {
            return fileName;
        }
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
            ".avif" => "image/avif",
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
            "image/avif" => IsAvifHeader(head),
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

    private static bool IsAvifHeader(byte[] head)
    {
        if (head.Length < 16 || !head.AsSpan(4, 4).SequenceEqual("ftyp"u8))
        {
            return false;
        }

        // AVIF files use an ISO-BMFF file type with avif/avis as the major brand,
        // or mif1/msf1 as a compatible brand. Require a bounded, aligned brand list.
        var major = head.AsSpan(8, 4);
        if (major.SequenceEqual("avif"u8) || major.SequenceEqual("avis"u8))
        {
            return true;
        }
        var compatibleLength = Math.Min(head.Length - 16, 32);
        for (var offset = 16; offset + 4 <= 16 + compatibleLength; offset += 4)
        {
            var brand = head.AsSpan(offset, 4);
            if (brand.SequenceEqual("avif"u8) || brand.SequenceEqual("avis"u8) ||
                brand.SequenceEqual("mif1"u8) || brand.SequenceEqual("msf1"u8))
            {
                return true;
            }
        }
        return false;
    }

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
