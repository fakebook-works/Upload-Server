using System.Text.Json;
using Microsoft.Extensions.Options;
using IOPath = System.IO.Path;

public sealed record UploadAssetMetadata(
    string AssetId,
    string StoredName,
    long OwnerUserId,
    string OriginalName,
    string ContentType,
    long Size,
    string State,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt);

public sealed record UploadFinalizeResult(
    int RequestedCount,
    int NormalizedCount,
    int FinalizedCount,
    int MissingFileCount,
    int OwnershipMismatchCount);

public sealed class UploadAssetStore
{
    public const string PendingState = "pending";
    public const string CommittedState = "committed";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly UploadStorageOptions _options;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public UploadAssetStore(IOptions<UploadStorageOptions> options)
    {
        _options = options.Value;
    }

    public async Task<UploadAssetMetadata> RegisterAsync(
        string storedName,
        long ownerUserId,
        string originalName,
        string contentType,
        long size,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var staged = _options.StagedUploadsEnabled;
        var metadata = new UploadAssetMetadata(
            IOPath.GetFileNameWithoutExtension(storedName),
            storedName,
            ownerUserId,
            originalName,
            contentType,
            size,
            staged ? PendingState : CommittedState,
            now,
            staged ? now.AddMinutes(Math.Clamp(_options.PendingLifetimeMinutes, 5, 10_080)) : null);
        await WriteAsync(metadata, cancellationToken);
        return metadata;
    }

    public async Task<int> FinalizeAsync(
        IEnumerable<string> urls,
        long? ownerUserId,
        CancellationToken cancellationToken)
    {
        var result = await FinalizeDetailedAsync(urls, ownerUserId, cancellationToken);
        return result.FinalizedCount;
    }

    /// <summary>
    /// Finalizes a complete lifecycle batch and reports partial completion explicitly.
    /// The legacy integer API remains available for callers that only need the count;
    /// internal HTTP callers use this report to fail closed when storage is inconsistent.
    /// </summary>
    public async Task<UploadFinalizeResult> FinalizeDetailedAsync(
        IEnumerable<string> urls,
        long? ownerUserId,
        CancellationToken cancellationToken)
    {
        var candidates = urls
            .Where(url => !string.IsNullOrWhiteSpace(url))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var storedNames = NormalizeStoredNames(candidates).ToArray();
        var finalized = 0;
        var missingFiles = 0;
        var ownershipMismatches = 0;
        await _gate.WaitAsync(cancellationToken);
        try
        {
            foreach (var storedName in storedNames)
            {
                var path = ResolveAssetPath(storedName);
                if (!File.Exists(path))
                {
                    missingFiles++;
                    continue;
                }
                var metadata = await TryReadUnsafeAsync(storedName, cancellationToken);
                if (metadata is null)
                {
                    // Legacy files predate lifecycle metadata and are already durable.
                    finalized++;
                    continue;
                }
                // A declared owner is authoritative: never extend the life of another
                // user's asset just because a URL string was supplied.
                if (ownerUserId.HasValue && metadata.OwnerUserId != ownerUserId.Value)
                {
                    ownershipMismatches++;
                    continue;
                }
                if (metadata.State != CommittedState || metadata.ExpiresAt is not null)
                {
                    await WriteUnsafeAsync(metadata with { State = CommittedState, ExpiresAt = null }, cancellationToken);
                }
                finalized++;
            }
        }
        finally
        {
            _gate.Release();
        }
        return new UploadFinalizeResult(
            candidates.Length,
            storedNames.Length,
            finalized,
            missingFiles,
            ownershipMismatches);
    }

    public async Task<int> DeleteByUrlsAsync(
        IEnumerable<string> urls,
        long? ownerUserId,
        CancellationToken cancellationToken)
    {
        var deleted = 0;
        await _gate.WaitAsync(cancellationToken);
        try
        {
            foreach (var storedName in NormalizeStoredNames(urls))
            {
                if (ownerUserId.HasValue)
                {
                    // Owner-scoped deletion fails closed: an asset whose ownership cannot
                    // be established is never removed on the strength of a URL alone.
                    var metadata = await TryReadUnsafeAsync(storedName, cancellationToken);
                    if (metadata is null || metadata.OwnerUserId != ownerUserId.Value) continue;
                }
                if (DeleteUnsafe(storedName)) deleted++;
            }
        }
        finally
        {
            _gate.Release();
        }
        return deleted;
    }

    /// <summary>
    /// Returns the subset of <paramref name="urls"/> that <paramref name="ownerUserId"/> may not
    /// reference. Callers use this to reject client-supplied media URLs before persisting them,
    /// so a URL can never be attached to content owned by somebody else.
    /// </summary>
    public async Task<IReadOnlyList<string>> FindUnauthorizedUrlsAsync(
        IEnumerable<string> urls,
        long ownerUserId,
        CancellationToken cancellationToken)
    {
        var unauthorized = new List<string>();
        var candidates = urls
            .Where(url => !string.IsNullOrWhiteSpace(url))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (candidates.Length == 0) return unauthorized;

        await _gate.WaitAsync(cancellationToken);
        try
        {
            foreach (var url in candidates)
            {
                var storedName = NormalizeStoredNames(new[] { url }).FirstOrDefault();
                if (storedName is null)
                {
                    // Not a URL this server serves; the caller must not treat it as owned media.
                    unauthorized.Add(url);
                    continue;
                }
                var metadata = await TryReadUnsafeAsync(storedName, cancellationToken);
                if (metadata is null || metadata.OwnerUserId != ownerUserId) unauthorized.Add(url);
            }
        }
        finally
        {
            _gate.Release();
        }
        return unauthorized;
    }

    public async Task<bool> DeletePendingOwnedAsync(string assetId, long ownerUserId, CancellationToken cancellationToken)
    {
        if (!Guid.TryParseExact(assetId, "N", out _)) return false;
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var metadataPath = ResolveMetadataPathFromAssetId(assetId);
            if (!File.Exists(metadataPath)) return false;
            var metadata = JsonSerializer.Deserialize<UploadAssetMetadata>(
                await File.ReadAllTextAsync(metadataPath, cancellationToken),
                JsonOptions);
            return metadata is not null &&
                   metadata.OwnerUserId == ownerUserId &&
                   metadata.State == PendingState &&
                   DeleteUnsafe(metadata.StoredName);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<int> FinalizeOwnedAsync(IEnumerable<string> assetIds, long ownerUserId, CancellationToken cancellationToken)
    {
        var finalized = 0;
        await _gate.WaitAsync(cancellationToken);
        try
        {
            foreach (var assetId in assetIds.Where(id => Guid.TryParseExact(id, "N", out _)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var metadataPath = ResolveMetadataPathFromAssetId(assetId);
                if (!File.Exists(metadataPath)) continue;
                var metadata = JsonSerializer.Deserialize<UploadAssetMetadata>(
                    await File.ReadAllTextAsync(metadataPath, cancellationToken),
                    JsonOptions);
                if (metadata is null || metadata.OwnerUserId != ownerUserId) continue;
                if (!File.Exists(ResolveAssetPath(metadata.StoredName))) continue;
                if (metadata.State != CommittedState || metadata.ExpiresAt is not null)
                {
                    await WriteUnsafeAsync(metadata with { State = CommittedState, ExpiresAt = null }, cancellationToken);
                }
                finalized++;
            }
        }
        finally
        {
            _gate.Release();
        }
        return finalized;
    }

    public async Task<int> CleanupExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        var deleted = 0;
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var metadataRoot = ResolveMetadataRoot();
            if (!Directory.Exists(metadataRoot)) return 0;
            foreach (var metadataPath in Directory.EnumerateFiles(metadataRoot, "*.json", SearchOption.TopDirectoryOnly))
            {
                cancellationToken.ThrowIfCancellationRequested();
                UploadAssetMetadata? metadata;
                try
                {
                    metadata = JsonSerializer.Deserialize<UploadAssetMetadata>(
                        await File.ReadAllTextAsync(metadataPath, cancellationToken),
                        JsonOptions);
                }
                catch (JsonException)
                {
                    continue;
                }
                if (metadata?.State == PendingState && metadata.ExpiresAt <= now && DeleteUnsafe(metadata.StoredName))
                {
                    deleted++;
                }
            }
        }
        finally
        {
            _gate.Release();
        }
        return deleted;
    }

    private async Task WriteAsync(UploadAssetMetadata metadata, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            await WriteUnsafeAsync(metadata, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task WriteUnsafeAsync(UploadAssetMetadata metadata, CancellationToken cancellationToken)
    {
        var metadataRoot = ResolveMetadataRoot();
        Directory.CreateDirectory(metadataRoot);
        var target = ResolveMetadataPath(metadata.StoredName);
        var temporary = target + ".tmp-" + Guid.NewGuid().ToString("N");
        await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(metadata, JsonOptions), cancellationToken);
        File.Move(temporary, target, overwrite: true);
    }

    /// <summary>
    /// Reads lifecycle metadata for a stored file, returning null when it is absent or unreadable.
    /// Legacy assets predate metadata and non-GUID names are rejected by <see cref="ResolveMetadataPath"/>,
    /// so both are reported as "ownership unknown" rather than throwing.
    /// </summary>
    private async Task<UploadAssetMetadata?> TryReadUnsafeAsync(string storedName, CancellationToken cancellationToken)
    {
        try
        {
            var path = ResolveMetadataPath(storedName);
            if (!File.Exists(path)) return null;
            return JsonSerializer.Deserialize<UploadAssetMetadata>(
                await File.ReadAllTextAsync(path, cancellationToken),
                JsonOptions);
        }
        catch (Exception exception) when (exception is InvalidOperationException or JsonException or IOException)
        {
            return null;
        }
    }

    private bool DeleteUnsafe(string storedName)
    {
        var deleted = false;
        var assetPath = ResolveAssetPath(storedName);
        if (File.Exists(assetPath))
        {
            File.Delete(assetPath);
            deleted = true;
        }
        var metadataPath = ResolveMetadataPath(storedName);
        if (File.Exists(metadataPath)) File.Delete(metadataPath);
        return deleted;
    }

    private string ResolveAssetPath(string storedName)
    {
        if (!UploadSecurity.IsSafeLeafFileName(storedName)) throw new InvalidOperationException("Unsafe stored media name.");
        var root = UploadSecurity.ResolveStorageRoot(_options);
        var path = IOPath.GetFullPath(IOPath.Combine(root, storedName));
        if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Media path escaped storage root.");
        return path;
    }

    private string ResolveMetadataRoot()
    {
        var root = UploadSecurity.ResolveStorageRoot(_options);
        return IOPath.GetFullPath(IOPath.Combine(root, ".metadata"));
    }

    private string ResolveMetadataPath(string storedName) =>
        ResolveMetadataPathFromAssetId(IOPath.GetFileNameWithoutExtension(storedName));

    private string ResolveMetadataPathFromAssetId(string assetId)
    {
        if (!Guid.TryParseExact(assetId, "N", out _)) throw new InvalidOperationException("Invalid media asset identifier.");
        return IOPath.Combine(ResolveMetadataRoot(), assetId + ".json");
    }

    private static IEnumerable<string> NormalizeStoredNames(IEnumerable<string> urls)
    {
        return urls
            .Where(url => !string.IsNullOrWhiteSpace(url))
            .Select(url => Uri.TryCreate(url, UriKind.Absolute, out var absolute) ? absolute.AbsolutePath : url)
            .Where(path => path.StartsWith("/media/files/", StringComparison.OrdinalIgnoreCase))
            .Select(path => Uri.UnescapeDataString(path["/media/files/".Length..].Split('?', '#')[0]))
            .Where(UploadSecurity.IsSafeLeafFileName)
            .Distinct(StringComparer.OrdinalIgnoreCase);
    }
}

public sealed class UploadAssetCleanupService : BackgroundService
{
    private readonly UploadAssetStore _store;
    private readonly UploadStorageOptions _options;
    private readonly ILogger<UploadAssetCleanupService> _logger;

    public UploadAssetCleanupService(
        UploadAssetStore store,
        IOptions<UploadStorageOptions> options,
        ILogger<UploadAssetCleanupService> logger)
    {
        _store = store;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.StagedUploadsEnabled) return;
        var interval = TimeSpan.FromMinutes(Math.Clamp(_options.CleanupIntervalMinutes, 1, 1_440));
        using var timer = new PeriodicTimer(interval);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                var deleted = await _store.CleanupExpiredAsync(DateTimeOffset.UtcNow, stoppingToken);
                if (deleted > 0) _logger.LogInformation("Deleted {Count} expired pending media assets.", deleted);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Pending media cleanup failed.");
            }
        }
    }
}
