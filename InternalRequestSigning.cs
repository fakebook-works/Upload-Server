using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

public sealed class InternalRequestSigningOptions
{
    public const string SectionName = "InternalAuth";

    public bool RequireSignature { get; set; }
    public bool SendLegacySecret { get; set; } = true;
    public int ClockSkewSeconds { get; set; } = 300;
    public int NonceRetentionSeconds { get; set; } = 900;
    public int MaxBodyBytes { get; set; } = 2 * 1024 * 1024;
}

public sealed record InternalRequestSigningTarget(
    IConfiguration Configuration,
    string SecretConfigurationKey,
    string LegacyHeaderName)
{
    public string Secret => Configuration[SecretConfigurationKey] ?? string.Empty;
}

public enum InternalSignatureValidationResult
{
    NoSignature,
    Valid,
    Invalid
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
    TimeProvider timeProvider)
{
    private readonly ConcurrentDictionary<string, long> _seenNonces = new(StringComparer.Ordinal);
    private long _validationCount;

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

        if (!TryReserveNonce(nonce, now))
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

    private bool TryReserveNonce(string nonce, long now)
    {
        var expiresAt = checked(now + options.Value.NonceRetentionSeconds);
        while (true)
        {
            if (!_seenNonces.TryGetValue(nonce, out var existingExpiry))
            {
                if (_seenNonces.TryAdd(nonce, expiresAt))
                {
                    break;
                }

                continue;
            }

            if (existingExpiry >= now)
            {
                return false;
            }

            if (_seenNonces.TryUpdate(nonce, expiresAt, existingExpiry))
            {
                break;
            }
        }

        if (Interlocked.Increment(ref _validationCount) % 256 == 0)
        {
            foreach (var pair in _seenNonces)
            {
                if (pair.Value < now)
                {
                    _seenNonces.TryRemove(pair.Key, out _);
                }
            }
        }

        return true;
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

        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        await context.Response.WriteAsJsonAsync(
            new
            {
                error = new
                {
                    code = result == InternalSignatureValidationResult.NoSignature
                        ? "INTERNAL_SIGNATURE_REQUIRED"
                        : "INVALID_INTERNAL_SIGNATURE",
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
                         value.MaxBodyBytes is >= 1024 and <= 16 * 1024 * 1024,
                "InternalAuth signing limits are invalid.")
            .ValidateOnStart();
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<InternalSignatureValidator>();
        services.AddTransient<InternalRequestSigningHandler>();

        if (incomingSecretConfigurationKey is not null && incomingLegacyHeaderName is not null)
        {
            services.AddSingleton(new InternalRequestSigningTarget(
                configuration,
                incomingSecretConfigurationKey,
                incomingLegacyHeaderName));
        }

        return services;
    }
}
