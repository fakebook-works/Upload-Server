using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using IOPath = System.IO.Path;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddOptions<UploadStorageOptions>()
    .Bind(builder.Configuration.GetSection(UploadStorageOptions.SectionName));

builder.Services
    .AddOptions<JwtOptions>()
    .Bind(builder.Configuration.GetSection(JwtOptions.SectionName))
    .Validate(options => !string.IsNullOrWhiteSpace(options.SigningKey), "Jwt:SigningKey is required.")
    .Validate(options => Encoding.UTF8.GetByteCount(options.SigningKey) >= 32, "Jwt:SigningKey must be at least 32 bytes.")
    .ValidateOnStart();

var jwtOptions = builder.Configuration.GetSection(JwtOptions.SectionName).Get<JwtOptions>() ?? new JwtOptions();

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
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.SigningKey)),
            ValidateIssuer = true,
            ValidIssuer = jwtOptions.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtOptions.Audience,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.Zero,
            NameClaimType = "username"
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseCors("Frontend");
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapPost("/media/upload-requests", (
        ClaimsPrincipal user,
        UploadRequest request,
        IOptions<UploadStorageOptions> options) =>
    {
        var metadata = UploadSecurity.ValidateMetadata(request.FileName, request.ContentType, request.Size);
        if (!metadata.IsAllowed)
        {
            return Results.BadRequest(new { error = metadata.Error });
        }

        var id = Guid.NewGuid().ToString("N");
        var ticket = UploadTicket.Create(
            id,
            UserIdFromClaims(user),
            request.FileName.Trim(),
            request.ContentType.Trim(),
            request.Size,
            DateTimeOffset.UtcNow.AddMinutes(options.Value.UploadLinkMinutes));

        UploadTickets.Save(ticket);
        var uploadUrl = $"/media/uploads/{ticket.Id}?token={Uri.EscapeDataString(ticket.Token)}";
        return Results.Created(uploadUrl, new UploadRequestResponse(
            ticket.Id,
            uploadUrl,
            ticket.ExpiresAt,
            UploadSecurity.MaxUploadBytes));
    })
    .RequireAuthorization();

app.MapPut("/media/uploads/{uploadId}", UploadAsync).DisableAntiforgery();
app.MapPost("/media/uploads/{uploadId}", UploadAsync).DisableAntiforgery();

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

static async Task<IResult> UploadAsync(
    string uploadId,
    string token,
    HttpRequest request,
    IOptions<UploadStorageOptions> options,
    CancellationToken cancellationToken)
{
    if (!UploadTickets.TryConsume(uploadId, token, out var ticket))
    {
        return Results.BadRequest(new { error = "Upload link is invalid or expired." });
    }

    if (!request.HasFormContentType)
    {
        return Results.BadRequest(new { error = "multipart/form-data is required." });
    }

    var form = await request.ReadFormAsync(cancellationToken);
    var file = form.Files.GetFile("file");
    if (file is null)
    {
        return Results.BadRequest(new { error = "File field is required." });
    }

    var stored = await UploadSecurity.StoreValidatedFileAsync(file, ticket, options.Value, cancellationToken);
    return stored.IsAllowed && stored.Response is not null
        ? Results.Created(stored.Response.Url, stored.Response)
        : Results.BadRequest(new { error = stored.Error });
}

static string UserIdFromClaims(ClaimsPrincipal user) =>
    user.FindFirst("user_id")?.Value ??
    user.FindFirst(ClaimTypes.NameIdentifier)?.Value ??
    "unknown";

public sealed class JwtOptions
{
    public const string SectionName = "Jwt";
    public string Issuer { get; init; } = "fakebook-auth";
    public string Audience { get; init; } = "fakebook";
    public string SigningKey { get; init; } = string.Empty;
}

public sealed class UploadStorageOptions
{
    public const string SectionName = "UploadStorage";
    public string RootPath { get; init; } = ".data/media";
    public int UploadLinkMinutes { get; init; } = 10;
}

public sealed record UploadRequest(string FileName, string ContentType, long Size);

public sealed record UploadRequestResponse(string UploadId, string UploadUrl, DateTimeOffset ExpiresAt, long MaxSize);

public sealed record MediaUploadResponse(string Url, string Type, string ContentType, long Size, string Name);

public sealed record MessageAttachmentDto(string Url, string Type, string ContentType, long Size, string Name);

internal sealed record UploadTicket(
    string Id,
    string Token,
    string UserId,
    string OriginalName,
    string ContentType,
    long ExpectedSize,
    DateTimeOffset ExpiresAt)
{
    public static UploadTicket Create(
        string id,
        string userId,
        string originalName,
        string contentType,
        long expectedSize,
        DateTimeOffset expiresAt)
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        return new UploadTicket(id, Convert.ToBase64String(bytes), userId, originalName, contentType, expectedSize, expiresAt);
    }
}

internal static class UploadTickets
{
    private static readonly ConcurrentDictionary<string, UploadTicket> Tickets = new();

    public static void Save(UploadTicket ticket) => Tickets[ticket.Id] = ticket;

    public static bool TryConsume(string id, string token, out UploadTicket ticket)
    {
        ticket = null!;
        if (!Tickets.TryRemove(id, out var found) ||
            found.ExpiresAt <= DateTimeOffset.UtcNow ||
            !FixedTimeEquals(found.Token, token))
        {
            return false;
        }

        ticket = found;
        return true;
    }

    private static bool FixedTimeEquals(string left, string right)
    {
        var leftBytes = Encoding.UTF8.GetBytes(left);
        var rightBytes = Encoding.UTF8.GetBytes(right);
        return leftBytes.Length == rightBytes.Length &&
               CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }
}

internal static class UploadSecurity
{
    public const long MaxUploadBytes = 25 * 1024 * 1024;

    private static readonly IReadOnlyDictionary<string, MediaKind> AllowedTypes = new Dictionary<string, MediaKind>(StringComparer.OrdinalIgnoreCase)
    {
        ["image/jpeg"] = new("image", ".jpg", [".jpg", ".jpeg"]),
        ["image/png"] = new("image", ".png", [".png"]),
        ["image/gif"] = new("image", ".gif", [".gif"]),
        ["image/webp"] = new("image", ".webp", [".webp"]),
        ["video/mp4"] = new("video", ".mp4", [".mp4"]),
        ["application/pdf"] = new("file", ".pdf", [".pdf"])
    };

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

        if (size <= 0 || size > MaxUploadBytes)
        {
            return MetadataValidation.Rejected($"File size must be between 1 byte and {MaxUploadBytes} bytes.");
        }

        var normalizedContentType = NormalizeContentType(contentType);
        if (!AllowedTypes.TryGetValue(normalizedContentType, out var mediaKind))
        {
            return MetadataValidation.Rejected("File type is not allowed.");
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
        UploadTicket ticket,
        UploadStorageOptions options,
        CancellationToken cancellationToken)
    {
        var metadata = ValidateMetadata(file.FileName, file.ContentType, file.Length);
        if (!metadata.IsAllowed)
        {
            return UploadValidationResult.Rejected(metadata.Error);
        }

        if (!string.Equals(NormalizeContentType(file.ContentType), NormalizeContentType(ticket.ContentType), StringComparison.OrdinalIgnoreCase))
        {
            return UploadValidationResult.Rejected("Uploaded content type does not match the issued upload link.");
        }

        if (ticket.ExpectedSize > 0 && file.Length != ticket.ExpectedSize)
        {
            return UploadValidationResult.Rejected("Uploaded file size does not match the issued upload link.");
        }

        await using var input = file.OpenReadStream();
        var headLength = (int)Math.Min(8192, file.Length);
        var head = new byte[headLength];
        var read = await input.ReadAsync(head.AsMemory(0, headLength), cancellationToken);
        Array.Resize(ref head, read);

        var contentType = NormalizeContentType(file.ContentType);
        if (!MatchesMagicHeader(contentType, head))
        {
            return UploadValidationResult.Rejected("File content does not match the declared type.");
        }

        var audit = AuditPayload(contentType, head);
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

        await using (var output = File.Create(destination))
        {
            await input.CopyToAsync(output, cancellationToken);
        }

        return UploadValidationResult.Accepted(new MediaUploadResponse(
            $"/media/files/{storedName}",
            kind.Category,
            contentType,
            file.Length,
            IOPath.GetFileName(file.FileName)));
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
            ".mp4" => "video/mp4",
            ".pdf" => "application/pdf",
            _ => "application/octet-stream"
        };

    private static bool MatchesMagicHeader(string contentType, byte[] head) =>
        contentType switch
        {
            "image/jpeg" => head.Length >= 3 && head[0] == 0xFF && head[1] == 0xD8 && head[2] == 0xFF,
            "image/png" => HasPrefix(head, 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A),
            "image/gif" => head.Length >= 6 && (head.AsSpan(0, 6).SequenceEqual("GIF87a"u8) || head.AsSpan(0, 6).SequenceEqual("GIF89a"u8)),
            "image/webp" => head.Length >= 12 && head.AsSpan(0, 4).SequenceEqual("RIFF"u8) && head.AsSpan(8, 4).SequenceEqual("WEBP"u8),
            "video/mp4" => head.Length >= 12 && head.AsSpan(4, 4).SequenceEqual("ftyp"u8),
            "application/pdf" => head.Length >= 5 && head.AsSpan(0, 5).SequenceEqual("%PDF-"u8),
            _ => false
        };

    private static bool HasPrefix(byte[] bytes, params byte[] prefix) =>
        bytes.Length >= prefix.Length && bytes.AsSpan(0, prefix.Length).SequenceEqual(prefix);

    private static string NormalizeContentType(string? contentType) =>
        (contentType ?? string.Empty).Split(';', 2)[0].Trim().ToLowerInvariant();

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
