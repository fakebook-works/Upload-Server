using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

public sealed class InternalRequestSigningOptions
{
    public const string SectionName = "InternalAuth";

    public bool RequireSignature { get; set; }
    public bool SendLegacySecret { get; set; } = true;
    public int ClockSkewSeconds { get; set; } = 300;
    public int NonceRetentionSeconds { get; set; } = 900;
    public int MaxBodyBytes { get; set; } = 2 * 1024 * 1024;
    public string RedisKeyPrefix { get; set; } = "fakebook:internal-nonce:v1";
    public int RedisOperationTimeoutMilliseconds { get; set; } = 1_000;
}

public sealed record InternalRequestSigningTarget(
    IConfiguration Configuration,
    string SecretConfigurationKey,
    string LegacyHeaderName,
    string Audience)
{
    public string Secret => Configuration[SecretConfigurationKey] ?? string.Empty;
}

public enum InternalSignatureValidationResult
{
    NoSignature,
    Valid,
    Invalid,
    Unavailable
}

public enum InternalNonceClaimResult
{
    Claimed,
    Duplicate,
    Unavailable
}

public interface IInternalNonceStore
{
    Task<InternalNonceClaimResult> TryClaimAsync(
        string audience,
        string nonce,
        TimeSpan retention,
        CancellationToken cancellationToken);

    Task<bool> IsAvailableAsync(CancellationToken cancellationToken);
}

public sealed class InternalNonceRedisConnection : IDisposable
{
    private readonly Lazy<IConnectionMultiplexer> _connection;

    public InternalNonceRedisConnection(string connectionString, int operationTimeoutMilliseconds)
    {
        ConnectionString = connectionString;
        _connection = new Lazy<IConnectionMultiplexer>(() =>
        {
            var configuration = ConfigurationOptions.Parse(connectionString);
            configuration.AbortOnConnectFail = false;
            configuration.ConnectRetry = 0;
            configuration.ConnectTimeout = Math.Clamp(operationTimeoutMilliseconds, 100, 5_000);
            configuration.AsyncTimeout = Math.Clamp(operationTimeoutMilliseconds, 100, 5_000);
            configuration.SyncTimeout = Math.Clamp(operationTimeoutMilliseconds, 100, 5_000);
            return ConnectionMultiplexer.Connect(configuration);
        }, LazyThreadSafetyMode.ExecutionAndPublication);
    }

    public string ConnectionString { get; }
    public IConnectionMultiplexer Connection => _connection.Value;

    public void Dispose()
    {
        if (_connection.IsValueCreated)
        {
            _connection.Value.Dispose();
        }
    }
}

public sealed class RedisInternalNonceStore(
    InternalNonceRedisConnection redis,
    IOptions<InternalRequestSigningOptions> options,
    ILogger<RedisInternalNonceStore> logger) : IInternalNonceStore
{
    public async Task<InternalNonceClaimResult> TryClaimAsync(
        string audience,
        string nonce,
        TimeSpan retention,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var key = $"{options.Value.RedisKeyPrefix}:{NormalizeAudience(audience)}:{nonce.ToLowerInvariant()}";
            var claimed = await redis.Connection.GetDatabase().StringSetAsync(
                key,
                "1",
                retention,
                When.NotExists,
                CommandFlags.DemandMaster);
            return claimed ? InternalNonceClaimResult.Claimed : InternalNonceClaimResult.Duplicate;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (IsRedisAvailabilityFailure(exception))
        {
            logger.LogWarning(exception, "Internal request replay protection is unavailable.");
            return InternalNonceClaimResult.Unavailable;
        }
    }

    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            return await redis.Connection.GetDatabase().PingAsync() <= TimeSpan.FromSeconds(5);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (IsRedisAvailabilityFailure(exception))
        {
            logger.LogWarning(exception, "Internal request replay-protection health check failed.");
            return false;
        }
    }

    private static string NormalizeAudience(string value) => string.Concat(
        value.ToLowerInvariant().Select(character => char.IsAsciiLetterOrDigit(character) ? character : '-'));

    private static bool IsRedisAvailabilityFailure(Exception exception) =>
        exception is RedisException or TimeoutException or InvalidOperationException or ArgumentException;
}

public sealed class InternalNonceStoreHealthCheck(IInternalNonceStore nonceStore) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default) =>
        await nonceStore.IsAvailableAsync(cancellationToken)
            ? HealthCheckResult.Healthy("Distributed replay protection is available.")
            : HealthCheckResult.Unhealthy("Distributed replay protection is unavailable.");
}

public static class InternalRequestSigning
{
    public const string TimestampHeader = "X-Internal-Timestamp";
    public const string NonceHeader = "X-Internal-Nonce";
    public const string SignatureHeader = "X-Internal-Signature";

    public static string BuildCanonicalString(
        string method,
        string pathAndQuery,
        long unixTimestamp,
        string nonce,
        ReadOnlySpan<byte> body)
    {
        var bodyHash = Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();
        return $"v1\n{method.ToUpperInvariant()}\n{pathAndQuery}\n{unixTimestamp.ToString(CultureInfo.InvariantCulture)}\n{nonce}\n{bodyHash}";
    }

    public static byte[] Sign(
        string secret,
        string method,
        string pathAndQuery,
        long unixTimestamp,
        string nonce,
        ReadOnlySpan<byte> body)
    {
        var canonical = BuildCanonicalString(method, pathAndQuery, unixTimestamp, nonce, body);
        return HMACSHA256.HashData(
            Encoding.UTF8.GetBytes(secret),
            Encoding.UTF8.GetBytes(canonical));
    }

    public static string ResolvePathAndQuery(Uri uri)
    {
        if (uri.IsAbsoluteUri)
        {
            return uri.PathAndQuery;
        }

        var value = uri.OriginalString;
        return value.StartsWith("/", StringComparison.Ordinal) ? value : "/" + value;
    }
}

public sealed class InternalRequestSigningHandler(IOptions<InternalRequestSigningOptions> options)
    : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var candidates = request.Headers
            .Where(header =>
                header.Key.StartsWith("X-Internal-", StringComparison.OrdinalIgnoreCase) &&
                header.Key.EndsWith("-Secret", StringComparison.OrdinalIgnoreCase))
            .ToArray();

        if (candidates.Length == 0)
        {
            return await base.SendAsync(request, cancellationToken);
        }

        if (candidates.Length != 1)
        {
            throw new InvalidOperationException("An internal request must contain exactly one target-service secret header.");
        }

        var secretValues = candidates[0].Value.ToArray();
        if (secretValues.Length != 1 || string.IsNullOrWhiteSpace(secretValues[0]))
        {
            throw new InvalidOperationException("The internal target-service secret is missing or ambiguous.");
        }

        var configured = options.Value;
        var body = request.Content is null
            ? Array.Empty<byte>()
            : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        if (body.Length > configured.MaxBodyBytes)
        {
            throw new InvalidOperationException("The internal request body exceeds the signing limit.");
        }

        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var nonce = Guid.NewGuid().ToString("N");
        var pathAndQuery = InternalRequestSigning.ResolvePathAndQuery(
            request.RequestUri ?? throw new InvalidOperationException("Internal request URI is required."));
        var signature = Convert.ToHexString(InternalRequestSigning.Sign(
            secretValues[0],
            request.Method.Method,
            pathAndQuery,
            timestamp,
            nonce,
            body)).ToLowerInvariant();

        request.Headers.Remove(InternalRequestSigning.TimestampHeader);
        request.Headers.Remove(InternalRequestSigning.NonceHeader);
        request.Headers.Remove(InternalRequestSigning.SignatureHeader);
        request.Headers.TryAddWithoutValidation(
            InternalRequestSigning.TimestampHeader,
            timestamp.ToString(CultureInfo.InvariantCulture));
        request.Headers.TryAddWithoutValidation(InternalRequestSigning.NonceHeader, nonce);
        request.Headers.TryAddWithoutValidation(InternalRequestSigning.SignatureHeader, signature);

        if (!configured.SendLegacySecret)
        {
            request.Headers.Remove(candidates[0].Key);
        }

        return await base.SendAsync(request, cancellationToken);
    }
}

public sealed class InternalSignatureValidator(
    IOptions<InternalRequestSigningOptions> options,
    TimeProvider timeProvider,
    IInternalNonceStore nonceStore,
    InternalRequestSigningTarget target)
{
    public async Task<InternalSignatureValidationResult> ValidateAsync(
        HttpRequest request,
        string secret,
        CancellationToken cancellationToken)
    {
        var timestampValues = request.Headers[InternalRequestSigning.TimestampHeader];
        var nonceValues = request.Headers[InternalRequestSigning.NonceHeader];
        var signatureValues = request.Headers[InternalRequestSigning.SignatureHeader];
        var anyPresent =
            request.Headers.ContainsKey(InternalRequestSigning.TimestampHeader) ||
            request.Headers.ContainsKey(InternalRequestSigning.NonceHeader) ||
            request.Headers.ContainsKey(InternalRequestSigning.SignatureHeader);

        if (!anyPresent)
        {
            return InternalSignatureValidationResult.NoSignature;
        }

        if (timestampValues.Count != 1 || nonceValues.Count != 1 || signatureValues.Count != 1)
        {
            return InternalSignatureValidationResult.Invalid;
        }

        var timestampText = timestampValues[0];
        var nonce = nonceValues[0];
        var signatureText = signatureValues[0];
        if (!long.TryParse(timestampText, NumberStyles.None, CultureInfo.InvariantCulture, out var timestamp) ||
            nonce is null ||
            nonce.Length != 32 ||
            nonce.Any(character => !Uri.IsHexDigit(character)) ||
            signatureText is null ||
            signatureText.Length != 64)
        {
            return InternalSignatureValidationResult.Invalid;
        }

        var now = timeProvider.GetUtcNow().ToUnixTimeSeconds();
        if (timestamp > now + options.Value.ClockSkewSeconds ||
            timestamp < now - options.Value.ClockSkewSeconds)
        {
            return InternalSignatureValidationResult.Invalid;
        }

        var body = await ReadBodyAsync(request, options.Value.MaxBodyBytes, cancellationToken);
        if (body is null)
        {
            return InternalSignatureValidationResult.Invalid;
        }

        var pathAndQuery = request.PathBase.Add(request.Path).Value + request.QueryString.Value;
        var expected = InternalRequestSigning.Sign(
            secret,
            request.Method,
            pathAndQuery,
            timestamp,
            nonce,
            body);

        if (!SignatureMatches(expected, signatureText))
        {
            return InternalSignatureValidationResult.Invalid;
        }

        var nonceResult = await nonceStore.TryClaimAsync(
            target.Audience,
            nonce,
            TimeSpan.FromSeconds(options.Value.NonceRetentionSeconds),
            cancellationToken);
        if (nonceResult == InternalNonceClaimResult.Unavailable)
        {
            return InternalSignatureValidationResult.Unavailable;
        }

        if (nonceResult != InternalNonceClaimResult.Claimed)
        {
            return InternalSignatureValidationResult.Invalid;
        }

        return InternalSignatureValidationResult.Valid;
    }

    private static bool SignatureMatches(byte[] expected, string suppliedText)
    {
        try
        {
            var supplied = Convert.FromHexString(suppliedText);
            return expected.Length == supplied.Length &&
                   CryptographicOperations.FixedTimeEquals(expected, supplied);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static async Task<byte[]?> ReadBodyAsync(
        HttpRequest request,
        int maxBodyBytes,
        CancellationToken cancellationToken)
    {
        if (request.ContentLength is > 0 && request.ContentLength > maxBodyBytes)
        {
            return null;
        }

        request.EnableBuffering();
        request.Body.Position = 0;
        await using var body = new MemoryStream();
        var buffer = new byte[16 * 1024];

        try
        {
            while (true)
            {
                var read = await request.Body.ReadAsync(buffer.AsMemory(), cancellationToken);
                if (read == 0)
                {
                    return body.ToArray();
                }

                if (body.Length + read > maxBodyBytes)
                {
                    return null;
                }

                await body.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            }
        }
        finally
        {
            request.Body.Position = 0;
        }
    }
}

public sealed class InternalRequestSignatureMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(
        HttpContext context,
        InternalSignatureValidator validator,
        InternalRequestSigningTarget target,
        IOptions<InternalRequestSigningOptions> options)
    {
        if (!context.Request.Path.StartsWithSegments("/internal", StringComparison.OrdinalIgnoreCase))
        {
            await next(context);
            return;
        }

        var result = await validator.ValidateAsync(
            context.Request,
            target.Secret,
            context.RequestAborted);

        if (result == InternalSignatureValidationResult.Valid)
        {
            // Existing service authentication remains the single authorization
            // implementation. Inject only into this in-memory request after HMAC
            // validation; the raw secret was not sent over the network.
            context.Request.Headers[target.LegacyHeaderName] = target.Secret;
            await next(context);
            return;
        }

        if (result == InternalSignatureValidationResult.NoSignature && !options.Value.RequireSignature)
        {
            await next(context);
            return;
        }

        context.Response.StatusCode = result == InternalSignatureValidationResult.Unavailable
            ? StatusCodes.Status503ServiceUnavailable
            : StatusCodes.Status403Forbidden;
        await context.Response.WriteAsJsonAsync(
            new
            {
                error = new
                {
                    code = result switch
                    {
                        InternalSignatureValidationResult.NoSignature => "INTERNAL_SIGNATURE_REQUIRED",
                        InternalSignatureValidationResult.Unavailable => "INTERNAL_REPLAY_PROTECTION_UNAVAILABLE",
                        _ => "INVALID_INTERNAL_SIGNATURE"
                    },
                    message = "Internal request signature validation failed."
                }
            },
            context.RequestAborted);
    }
}

public static class InternalRequestSigningServiceCollectionExtensions
{
    public static IServiceCollection AddInternalRequestSigning(
        this IServiceCollection services,
        IConfiguration configuration,
        string? incomingSecretConfigurationKey = null,
        string? incomingLegacyHeaderName = null)
    {
        services
            .AddOptions<InternalRequestSigningOptions>()
            .Bind(configuration.GetSection(InternalRequestSigningOptions.SectionName))
            .Validate(
                value => value.ClockSkewSeconds is >= 30 and <= 900 &&
                         value.NonceRetentionSeconds >= value.ClockSkewSeconds &&
                         value.NonceRetentionSeconds <= 3600 &&
                         value.MaxBodyBytes is >= 1024 and <= 16 * 1024 * 1024 &&
                         value.RedisOperationTimeoutMilliseconds is >= 100 and <= 5_000 &&
                         !string.IsNullOrWhiteSpace(value.RedisKeyPrefix) &&
                         value.RedisKeyPrefix.Length <= 100,
                "InternalAuth signing limits are invalid.")
            .Validate(
                value => incomingSecretConfigurationKey is null ||
                         !value.RequireSignature ||
                         !string.IsNullOrWhiteSpace(configuration.GetConnectionString("SecurityRedis")),
                "ConnectionStrings:SecurityRedis is required when internal signatures are required.")
            .ValidateOnStart();
        services.AddSingleton(TimeProvider.System);
        services.AddTransient<InternalRequestSigningHandler>();

        if (incomingSecretConfigurationKey is not null && incomingLegacyHeaderName is not null)
        {
            services.AddSingleton(new InternalRequestSigningTarget(
                configuration,
                incomingSecretConfigurationKey,
                incomingLegacyHeaderName,
                incomingSecretConfigurationKey));
            services.AddSingleton(serviceProvider => new InternalNonceRedisConnection(
                configuration.GetConnectionString("SecurityRedis") ?? string.Empty,
                serviceProvider.GetRequiredService<IOptions<InternalRequestSigningOptions>>()
                    .Value.RedisOperationTimeoutMilliseconds));
            services.AddSingleton<IInternalNonceStore, RedisInternalNonceStore>();
            services.AddSingleton<InternalSignatureValidator>();
            services.AddHealthChecks().AddCheck<InternalNonceStoreHealthCheck>(
                "internal_nonce_redis",
                tags: ["ready"]);
        }

        return services;
    }
}
