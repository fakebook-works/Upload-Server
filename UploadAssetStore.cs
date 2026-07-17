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

    public async Task<int> FinalizeAsync(IEnumerable<string> urls, CancellationToken cancellationToken)
    {
        var finalized = 0;
        await _gate.WaitAsync(cancellationToken);
        try
        {
            foreach (var storedName in NormalizeStoredNames(urls))
            {
                var path = ResolveAssetPath(storedName);
                if (!File.Exists(path)) continue;
                var metadata = await ReadUnsafeAsync(storedName, cancellationToken);
                if (metadata is null)
                {
                    // Legacy files predate lifecycle metadata and are already durable.
                    finalized++;
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
        return finalized;
    }

    public async Task<int> DeleteByUrlsAsync(IEnumerable<string> urls, CancellationToken cancellationToken)
    {
        var deleted = 0;
        await _gate.WaitAsync(cancellationToken);
        try
        {
            foreach (var storedName in NormalizeStoredNames(urls))
            {
                if (DeleteUnsafe(storedName)) deleted++;
            }
        }
        finally
        {
            _gate.Release();
        }
        return deleted;
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

    private async Task<UploadAssetMetadata?> ReadUnsafeAsync(string storedName, CancellationToken cancellationToken)
    {
        var path = ResolveMetadataPath(storedName);
        if (!File.Exists(path)) return null;
        return JsonSerializer.Deserialize<UploadAssetMetadata>(
            await File.ReadAllTextAsync(path, cancellationToken),
            JsonOptions);
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
