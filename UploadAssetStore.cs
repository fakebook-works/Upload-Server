using System.Diagnostics.Metrics;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
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
    DateTimeOffset? ExpiresAt,
    int LifecycleVersion = 0,
    Dictionary<string, DateTimeOffset>? ActiveReferences = null,
    Dictionary<string, DateTimeOffset>? ReleasedReferences = null,
    Dictionary<string, UploadPendingReferenceReservation>? PendingReferences = null,
    // Kept only so existing v2 JSON can be read and conservatively pinned. New code
    // never creates or consults a wildcard watermark because it loses the reference ID
    // needed to order a delayed attach against its exact detach.
    DateTimeOffset? ReleasedReferenceWatermark = null,
    // Safe bounded compaction for exact release history. Unlike the legacy wildcard
    // watermark, this floor is only a fail-closed ordering barrier: an operation at or
    // below it is rejected unless an unexpired reservation for that exact reference
    // proves the parent was authorized before the floor advanced.
    DateTimeOffset? CompactedReleaseFloor = null,
    bool LegacyPinned = false,
    DateTimeOffset? ReservedAt = null,
    DateTimeOffset? ReservationExpiresAt = null,
    string? ReservationKind = null,
    DateTimeOffset? CleanupMarkedAt = null,
    DateTimeOffset? DeleteAfter = null,
    int PrivacyMetadataVersion = 0,
    DateTimeOffset? PrivacyMetadataSanitizedAt = null,
    DateTimeOffset? DeletedAt = null);

public sealed record UploadPendingReferenceReservation(
    DateTimeOffset OperationAt,
    DateTimeOffset ReservedAt,
    DateTimeOffset ExpiresAt);

public sealed record UploadMediaReference(
    string Url,
    string ReferenceId,
    string? AssetId = null);

public sealed record UploadFinalizeResult(
    int RequestedCount,
    int NormalizedCount,
    int FinalizedCount,
    int MissingFileCount,
    int OwnershipMismatchCount,
    int MetadataUnavailableCount = 0);

public sealed record UploadReferenceMutationResult(
    int RequestedCount,
    int NormalizedCount,
    int AppliedCount,
    int MissingFileCount,
    int OwnershipMismatchCount,
    int MetadataUnavailableCount,
    int CapacityExceededCount,
    int StaleCount,
    int InvalidOperationTimeCount = 0);

public sealed record UploadReferenceAuthorizationResult(
    int RequestedCount,
    int NormalizedCount,
    IReadOnlyList<string> UnauthorizedUrls,
    int CapacityExceededCount,
    int InvalidOperationTimeCount = 0);

public sealed class UploadAssetStore
{
    public const string PendingState = "pending";
    public const string CommittedState = "committed";
    public const string DeletedState = "deleted";
    public const int CurrentLifecycleVersion = 3;
    public const int CurrentPrivacyMetadataVersion = 1;
    public const int MaxLifecycleBatchSize = 512;
    private const int MaxReferencesPerAsset = 2_048;
    private const int MaxPendingReferencesPerAsset = 2_048;
    private const int MaxReleasedReferencesPerAsset = 4_096;
    private const int ReleasedReferenceCompactionTarget = 3_072;
    private const long MaxMetadataBytes = 2L * 1024 * 1024;
    private const int LockRetryMilliseconds = 25;
    private const string BrowserReservationKind = "browser";
    private const string LegacyUrlReservationKind = "legacy-url";
    private static readonly TimeSpan MaximumFutureOperationSkew = TimeSpan.FromMinutes(5);
    private static readonly Meter LifecycleMeter = new("Fakebook.Upload.MediaLifecycle", "1.0.0");
    private static readonly Counter<long> PhysicalDeleteFailureCounter =
        LifecycleMeter.CreateCounter<long>("fakebook.upload.physical_delete.failures");

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly UploadStorageOptions _options;
    private readonly ILogger<UploadAssetStore> _logger;

    public UploadAssetStore(
        IOptions<UploadStorageOptions> options,
        ILogger<UploadAssetStore>? logger = null)
    {
        _options = options.Value;
        _logger = logger ?? NullLogger<UploadAssetStore>.Instance;
    }

    public async Task<bool> IsStorageAvailableAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var lease = await AcquireNamedLifecycleLeasesAsync(["readiness"], cancellationToken);
            var probe = IOPath.Combine(ResolveMetadataRoot(), ".ready-" + Guid.NewGuid().ToString("N"));
            try
            {
                await File.WriteAllBytesAsync(probe, Array.Empty<byte>(), cancellationToken);
                return true;
            }
            finally
            {
                if (File.Exists(probe))
                {
                    File.Delete(probe);
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                          TimeoutException or ArgumentException or NotSupportedException or
                                          InvalidOperationException)
        {
            return false;
        }
    }

    /// <summary>
    /// Public serving checks the authoritative tombstone without taking a lifecycle lock.
    /// Metadata writes are atomic replacements, so a reader observes either the old complete
    /// record or the new complete record. Legacy files without metadata remain readable for
    /// compatibility; a present but corrupt managed record fails closed.
    /// </summary>
    public async Task<bool> CanServeAsync(
        string storedName,
        CancellationToken cancellationToken)
    {
        if (!TryGetAssetId(storedName, out _) ||
            !File.Exists(ResolveAssetPath(storedName)))
        {
            return false;
        }
        var metadataPath = ResolveMetadataPath(storedName);
        if (!File.Exists(metadataPath))
        {
            return true;
        }
        var read = await ReadMetadataPathUnsafeAsync(metadataPath, storedName, cancellationToken);
        return read.Status == MetadataReadStatus.Loaded &&
               read.Metadata?.State != DeletedState;
    }

    public async Task<UploadAssetMetadata> RegisterAsync(
        string storedName,
        long ownerUserId,
        string originalName,
        string contentType,
        long size,
        CancellationToken cancellationToken)
    {
        if (!TryGetAssetId(storedName, out var assetId))
        {
            throw new InvalidOperationException("Stored media names must use a generated GUID asset identifier.");
        }
        var now = DateTimeOffset.UtcNow;
        var staged = _options.StagedUploadsEnabled;
        var metadata = new UploadAssetMetadata(
            assetId,
            storedName,
            ownerUserId,
            originalName,
            contentType,
            size,
            staged ? PendingState : CommittedState,
            now,
            staged ? now.AddMinutes(Math.Clamp(_options.PendingLifetimeMinutes, 5, 10_080)) : null,
            CurrentLifecycleVersion,
            new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal),
            new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal),
            new Dictionary<string, UploadPendingReferenceReservation>(StringComparer.Ordinal),
            PrivacyMetadataVersion: contentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase) ||
                                    contentType.StartsWith("video/", StringComparison.OrdinalIgnoreCase) ||
                                    contentType.StartsWith("audio/", StringComparison.OrdinalIgnoreCase)
                ? CurrentPrivacyMetadataVersion
                : 0,
            PrivacyMetadataSanitizedAt: contentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase) ||
                                        contentType.StartsWith("video/", StringComparison.OrdinalIgnoreCase) ||
                                        contentType.StartsWith("audio/", StringComparison.OrdinalIgnoreCase)
                ? now
                : null);
        await using var lease = await AcquireAssetIdLeasesAsync([assetId], cancellationToken);
        if (File.Exists(ResolveMetadataPath(storedName)) || File.Exists(ResolveAssetPath(storedName)))
        {
            throw new IOException("Generated media asset identifier already exists.");
        }
        await WriteUnsafeAsync(metadata, cancellationToken);
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
    /// Compatibility path for lifecycle rows written by an older SocialGraph/Messenger.
    /// Such a finalize is made durable but pinned conservatively because it does not identify
    /// the parent that owns the reference. New callers must use AttachReferencesDetailedAsync.
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
        var storedNames = candidates
            .Select(TryNormalizeStoredName)
            .Where(name => name is not null && TryGetAssetId(name, out _))
            .OfType<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (storedNames.Length != candidates.Length)
        {
            return new UploadFinalizeResult(candidates.Length, storedNames.Length, 0, 0, 0, 0);
        }

        var missingFiles = 0;
        var ownershipMismatches = 0;
        var metadataUnavailable = 0;
        var metadataToFinalize = new List<UploadAssetMetadata>();
        await using var lease = await AcquireAssetLeasesAsync(storedNames, cancellationToken);
        foreach (var storedName in storedNames)
        {
            var path = ResolveAssetPath(storedName);
            if (!File.Exists(path))
            {
                missingFiles++;
                continue;
            }

            var read = await ReadMetadataUnsafeAsync(storedName, cancellationToken);
            if (read.Status != MetadataReadStatus.Loaded || read.Metadata is null)
            {
                // Missing/unreadable metadata is never treated as a durable legacy file.
                // Doing so used to ACK finalize while the real metadata remained pending.
                metadataUnavailable++;
                continue;
            }

            var metadata = read.Metadata;
            if (metadata.State == DeletedState)
            {
                missingFiles++;
                continue;
            }
            if (ownerUserId.HasValue && metadata.OwnerUserId != ownerUserId.Value)
            {
                ownershipMismatches++;
                continue;
            }

            metadataToFinalize.Add(metadata);
        }

        if (missingFiles > 0 || ownershipMismatches > 0 || metadataUnavailable > 0)
        {
            return new UploadFinalizeResult(
                candidates.Length,
                storedNames.Length,
                0,
                missingFiles,
                ownershipMismatches,
                metadataUnavailable);
        }

        foreach (var metadata in metadataToFinalize)
        {
            await WriteUnsafeAsync(metadata with
            {
                State = CommittedState,
                ExpiresAt = null,
                LifecycleVersion = Math.Max(metadata.LifecycleVersion, CurrentLifecycleVersion),
                LegacyPinned = true,
                ReservedAt = null,
                ReservationExpiresAt = null,
                ReservationKind = null,
                CleanupMarkedAt = null,
                DeleteAfter = null
            }, cancellationToken);
        }

        return new UploadFinalizeResult(
            candidates.Length,
            storedNames.Length,
            metadataToFinalize.Count,
            missingFiles,
            ownershipMismatches,
            metadataUnavailable);
    }

    public async Task<UploadReferenceMutationResult> AttachReferencesDetailedAsync(
        IEnumerable<UploadMediaReference> references,
        long? ownerUserId,
        DateTimeOffset? operationAt,
        CancellationToken cancellationToken)
    {
        var requested = references.ToArray();
        var normalized = NormalizeReferences(requested);
        if (normalized.Count != requested.Length)
        {
            return new UploadReferenceMutationResult(
                requested.Length, normalized.Count, 0, 0, 0, 0, 0, 0);
        }
        if (!TryNormalizeRequiredOperationTime(operationAt, out var occurredAt))
        {
            return new UploadReferenceMutationResult(
                requested.Length, normalized.Count, 0, 0, 0, 0, 0, 0, requested.Length);
        }

        var missingFiles = 0;
        var ownershipMismatches = 0;
        var metadataUnavailable = 0;
        var capacityExceeded = 0;
        var tombstoneApplied = 0;
        var tombstoneStale = 0;
        var plans = new List<ReferenceMutationPlan>();

        await using var lease = await AcquireAssetLeasesAsync(
            normalized.Select(reference => reference.StoredName),
            cancellationToken);
        foreach (var assetGroup in normalized.GroupBy(item => item.StoredName, StringComparer.OrdinalIgnoreCase))
        {
            var storedName = assetGroup.Key;
            var fileExists = File.Exists(ResolveAssetPath(storedName));
            var read = await ReadMetadataUnsafeAsync(storedName, cancellationToken);
            if (read.Status != MetadataReadStatus.Loaded || read.Metadata is null)
            {
                if (!fileExists && read.Status == MetadataReadStatus.Missing)
                {
                    missingFiles += assetGroup.Count();
                }
                else
                {
                    metadataUnavailable += assetGroup.Count();
                }
                continue;
            }

            var metadata = read.Metadata;
            if (metadata.State == DeletedState)
            {
                // A durable tombstone is terminal. Exact authorization could not have
                // succeeded after it, and any reservation created before final detach
                // would have prevented the tombstone. ACK a delayed attach as retired
                // without retaining parent IDs in deleted metadata.
                tombstoneApplied += assetGroup.Count();
                tombstoneStale += assetGroup.Count();
                continue;
            }

            if (ownerUserId.HasValue && metadata.OwnerUserId != ownerUserId.Value)
            {
                ownershipMismatches += assetGroup.Count();
                continue;
            }

            if (!fileExists)
            {
                missingFiles += assetGroup.Count();
                continue;
            }

            var active = CopyReferences(metadata.ActiveReferences);
            var released = CopyReferences(metadata.ReleasedReferences);
            var pending = CopyPendingReferences(metadata.PendingReferences);
            RemoveExpiredPendingReferences(pending, DateTimeOffset.UtcNow);
            var additionalReferences = assetGroup.Count(reference =>
                !active.ContainsKey(reference.ReferenceId) &&
                !IsAttachStale(
                    metadata,
                    released,
                    pending,
                    reference.ReferenceId,
                    occurredAt));
            if (active.Count + additionalReferences > MaxReferencesPerAsset)
            {
                capacityExceeded += assetGroup.Count();
                continue;
            }

            plans.Add(new ReferenceMutationPlan(metadata, assetGroup.ToArray()));
        }

        // A signed lifecycle batch is all-or-nothing for validation. In the old path an
        // invalid item near the end could mutate earlier files and then return an error,
        // leaving retries and cleanup to reason about a half-applied event.
        if (missingFiles > 0 || ownershipMismatches > 0 ||
            metadataUnavailable > 0 || capacityExceeded > 0)
        {
            return new UploadReferenceMutationResult(
                requested.Length,
                normalized.Count,
                0,
                missingFiles,
                ownershipMismatches,
                metadataUnavailable,
                capacityExceeded,
                0);
        }

        var applied = tombstoneApplied;
        var stale = tombstoneStale;
        foreach (var plan in plans)
        {
            var metadata = plan.Metadata;
            var active = CopyReferences(metadata.ActiveReferences);
            var released = CopyReferences(metadata.ReleasedReferences);
            var pending = CopyPendingReferences(metadata.PendingReferences);
            var changed = RemoveExpiredPendingReferences(pending, DateTimeOffset.UtcNow);
            var hasLegacyReservation = HasActiveLegacyReservation(metadata, DateTimeOffset.UtcNow);
            if (!hasLegacyReservation &&
                (metadata.ReservedAt is not null || metadata.ReservationExpiresAt is not null))
            {
                changed = true;
            }
            var acceptedReference = false;
            foreach (var reference in plan.References)
            {
                if (IsAttachStale(
                        metadata,
                        released,
                        pending,
                        reference.ReferenceId,
                        occurredAt))
                {
                    // A late retry for a parent already detached is idempotently retired.
                    applied++;
                    stale++;
                    continue;
                }

                acceptedReference = true;
                if (!active.TryGetValue(reference.ReferenceId, out var attachedAt) || attachedAt < occurredAt)
                {
                    active[reference.ReferenceId] = occurredAt;
                    changed = true;
                }
                if (released.Remove(reference.ReferenceId))
                {
                    changed = true;
                }
                if (pending.TryGetValue(reference.ReferenceId, out var reservation) &&
                    reservation.OperationAt <= occurredAt &&
                    pending.Remove(reference.ReferenceId))
                {
                    changed = true;
                }
                applied++;
            }

            var legacyPinned = metadata.LegacyPinned || RequiresConservativePin(metadata);
            var clearBrowserReservation = acceptedReference &&
                                          string.Equals(
                                              metadata.ReservationKind,
                                              BrowserReservationKind,
                                              StringComparison.Ordinal) &&
                                          metadata.ReservedAt <= occurredAt;
            if (changed || clearBrowserReservation || (acceptedReference &&
                (metadata.State != CommittedState || metadata.ExpiresAt is not null ||
                 metadata.CleanupMarkedAt is not null || metadata.DeleteAfter is not null ||
                 metadata.LifecycleVersion != CurrentLifecycleVersion || metadata.LegacyPinned != legacyPinned)))
            {
                await WriteUnsafeAsync(metadata with
                {
                    State = acceptedReference ? CommittedState : metadata.State,
                    ExpiresAt = acceptedReference ? null : metadata.ExpiresAt,
                    LifecycleVersion = CurrentLifecycleVersion,
                    ActiveReferences = active,
                    ReleasedReferences = released,
                    PendingReferences = pending,
                    ReleasedReferenceWatermark = null,
                    LegacyPinned = legacyPinned,
                    ReservedAt = hasLegacyReservation && !clearBrowserReservation ? metadata.ReservedAt : null,
                    ReservationExpiresAt = hasLegacyReservation && !clearBrowserReservation
                        ? metadata.ReservationExpiresAt
                        : null,
                    ReservationKind = hasLegacyReservation && !clearBrowserReservation
                        ? metadata.ReservationKind
                        : null,
                    CleanupMarkedAt = acceptedReference ? null : metadata.CleanupMarkedAt,
                    DeleteAfter = acceptedReference ? null : metadata.DeleteAfter
                }, cancellationToken);
            }
        }

        return new UploadReferenceMutationResult(
            requested.Length,
            normalized.Count,
            applied,
            missingFiles,
            ownershipMismatches,
            metadataUnavailable,
            capacityExceeded,
            stale);
    }

    public async Task<UploadReferenceMutationResult> DetachReferencesDetailedAsync(
        IEnumerable<UploadMediaReference> references,
        long? ownerUserId,
        DateTimeOffset? operationAt,
        CancellationToken cancellationToken)
    {
        var requested = references.ToArray();
        var normalized = NormalizeReferences(requested);
        if (normalized.Count != requested.Length)
        {
            return new UploadReferenceMutationResult(
                requested.Length, normalized.Count, 0, 0, 0, 0, 0, 0);
        }
        if (!TryNormalizeRequiredOperationTime(operationAt, out var occurredAt))
        {
            return new UploadReferenceMutationResult(
                requested.Length, normalized.Count, 0, 0, 0, 0, 0, 0, requested.Length);
        }

        var missingFiles = 0;
        var ownershipMismatches = 0;
        var metadataUnavailable = 0;
        var capacityExceeded = 0;
        var now = DateTimeOffset.UtcNow;
        var deleteAfter = now.AddMinutes(
            Math.Clamp(_options.ReferenceDeleteGraceMinutes, 0, 10_080));
        var plans = new List<ReferenceMutationPlan>();

        await using var lease = await AcquireAssetLeasesAsync(
            normalized.Select(reference => reference.StoredName),
            cancellationToken);
        foreach (var assetGroup in normalized.GroupBy(item => item.StoredName, StringComparer.OrdinalIgnoreCase))
        {
            var storedName = assetGroup.Key;
            var fileExists = File.Exists(ResolveAssetPath(storedName));
            var read = await ReadMetadataUnsafeAsync(storedName, cancellationToken);
            if (read.Status == MetadataReadStatus.Missing && !fileExists)
            {
                // The final delete may be replayed after cleanup; that is already complete.
                missingFiles += assetGroup.Count();
                continue;
            }
            if (read.Status != MetadataReadStatus.Loaded || read.Metadata is null)
            {
                metadataUnavailable += assetGroup.Count();
                continue;
            }

            var metadata = read.Metadata;
            if (metadata.State != DeletedState &&
                ownerUserId.HasValue && metadata.OwnerUserId != ownerUserId.Value)
            {
                ownershipMismatches += assetGroup.Count();
                continue;
            }

            plans.Add(new ReferenceMutationPlan(metadata, assetGroup.ToArray()));
        }

        if (ownershipMismatches > 0 || metadataUnavailable > 0)
        {
            return new UploadReferenceMutationResult(
                requested.Length,
                normalized.Count,
                0,
                missingFiles,
                ownershipMismatches,
                metadataUnavailable,
                capacityExceeded,
                0);
        }

        var applied = missingFiles;
        var stale = 0;
        foreach (var plan in plans)
        {
            var metadata = plan.Metadata;
            if (metadata.State == DeletedState)
            {
                applied += plan.References.Count;
                stale += plan.References.Count;
                if (metadata.LifecycleVersion < CurrentLifecycleVersion ||
                    !IsMinimalDeletedTombstone(metadata))
                {
                    await TombstoneThenDeleteUnsafeAsync(
                        metadata,
                        metadata.DeletedAt ?? now,
                        cancellationToken);
                }
                else
                {
                    TryDeletePhysicalFileUnsafe(metadata.StoredName);
                }
                continue;
            }

            var active = CopyReferences(metadata.ActiveReferences);
            var released = CopyReferences(metadata.ReleasedReferences);
            var pending = CopyPendingReferences(metadata.PendingReferences);
            var compactedReleaseFloor = metadata.CompactedReleaseFloor;
            var changed = RemoveExpiredPendingReferences(pending, now);
            var hasLegacyReservation = HasActiveLegacyReservation(metadata, now);
            if (!hasLegacyReservation &&
                (metadata.ReservedAt is not null || metadata.ReservationExpiresAt is not null))
            {
                changed = true;
            }
            foreach (var reference in plan.References)
            {
                if (active.TryGetValue(reference.ReferenceId, out var attachedAt) && attachedAt > occurredAt)
                {
                    // A strictly newer attach wins. At equal time the stable parent ID
                    // makes detach terminal; acknowledging while retaining that same
                    // parent would otherwise leak the asset forever.
                    applied++;
                    stale++;
                    continue;
                }

                var removedParentState = false;
                if (active.Remove(reference.ReferenceId))
                {
                    changed = true;
                    removedParentState = true;
                }
                if (pending.TryGetValue(reference.ReferenceId, out var reservation) &&
                    reservation.OperationAt <= occurredAt &&
                    pending.Remove(reference.ReferenceId))
                {
                    changed = true;
                    removedParentState = true;
                }

                var alreadyReleased =
                    (released.TryGetValue(reference.ReferenceId, out var priorRelease) &&
                     priorRelease >= occurredAt) ||
                    compactedReleaseFloor >= occurredAt;
                if (!alreadyReleased)
                {
                    released[reference.ReferenceId] = occurredAt;
                    changed = true;
                }
                else if (!removedParentState)
                {
                    stale++;
                }
                applied++;
            }

            var previousCompactedReleaseFloor = compactedReleaseFloor;
            compactedReleaseFloor = CompactReleasedReferences(released, compactedReleaseFloor);
            if (compactedReleaseFloor != previousCompactedReleaseFloor)
            {
                changed = true;
            }

            var legacyPinned = metadata.LegacyPinned || RequiresConservativePin(metadata);
            var hasReservation = hasLegacyReservation || pending.Count > 0;
            var mayDelete = active.Count == 0 && !legacyPinned && !hasReservation;

            if (mayDelete && _options.ReferenceDeleteGraceMinutes <= 0)
            {
                await TombstoneThenDeleteUnsafeAsync(
                    metadata with
                    {
                        ActiveReferences = active,
                        ReleasedReferences = released,
                        PendingReferences = pending,
                        ReleasedReferenceWatermark = null,
                        CompactedReleaseFloor = compactedReleaseFloor,
                        LegacyPinned = legacyPinned
                    },
                    now,
                    cancellationToken);
                continue;
            }

            if (changed || metadata.LifecycleVersion != CurrentLifecycleVersion || metadata.LegacyPinned != legacyPinned ||
                metadata.ReleasedReferenceWatermark is not null ||
                (mayDelete && metadata.DeleteAfter is null))
            {
                await WriteUnsafeAsync(metadata with
                {
                    LifecycleVersion = CurrentLifecycleVersion,
                    ActiveReferences = active,
                    ReleasedReferences = released,
                    PendingReferences = pending,
                    ReleasedReferenceWatermark = null,
                    CompactedReleaseFloor = compactedReleaseFloor,
                    LegacyPinned = legacyPinned,
                    ReservedAt = HasActiveLegacyReservation(metadata, now) ? metadata.ReservedAt : null,
                    ReservationExpiresAt = HasActiveLegacyReservation(metadata, now) ? metadata.ReservationExpiresAt : null,
                    ReservationKind = HasActiveLegacyReservation(metadata, now) ? metadata.ReservationKind : null,
                    CleanupMarkedAt = null,
                    DeleteAfter = mayDelete ? metadata.DeleteAfter ?? deleteAfter : null
                }, cancellationToken);
            }
        }

        return new UploadReferenceMutationResult(
            requested.Length,
            normalized.Count,
            applied,
            missingFiles,
            ownershipMismatches,
            metadataUnavailable,
            capacityExceeded,
            stale);
    }

    /// <summary>
    /// Compatibility delete for old outbox rows. It never destroys an asset that may have
    /// untracked parents; new callers must detach a stable parent reference instead.
    /// </summary>
    public async Task<int> DeleteByUrlsAsync(
        IEnumerable<string> urls,
        long? ownerUserId,
        CancellationToken cancellationToken)
    {
        var scheduled = 0;
        var storedNames = NormalizeStoredNames(urls).ToArray();
        var now = DateTimeOffset.UtcNow;
        var deleteAfter = DateTimeOffset.UtcNow.AddMinutes(
            Math.Clamp(_options.ReferenceDeleteGraceMinutes, 0, 10_080));
        await using var lease = await AcquireAssetLeasesAsync(storedNames, cancellationToken);
        foreach (var storedName in storedNames)
        {
            var read = await ReadMetadataUnsafeAsync(storedName, cancellationToken);
            if (read.Status == MetadataReadStatus.Missing && !File.Exists(ResolveAssetPath(storedName)))
            {
                scheduled++;
                continue;
            }
            if (read.Status != MetadataReadStatus.Loaded || read.Metadata is null)
            {
                continue;
            }
            var metadata = read.Metadata;
            if (metadata.State == DeletedState)
            {
                TryDeletePhysicalFileUnsafe(metadata.StoredName);
                scheduled++;
                continue;
            }
            if (ownerUserId.HasValue && metadata.OwnerUserId != ownerUserId.Value)
            {
                continue;
            }

            var active = CopyReferences(metadata.ActiveReferences);
            var pending = CopyPendingReferences(metadata.PendingReferences);
            RemoveExpiredPendingReferences(pending, now);
            if (RequiresConservativePin(metadata) || metadata.LegacyPinned ||
                active.Count > 0 || pending.Count > 0 || HasActiveLegacyReservation(metadata, now))
            {
                // Fail conservatively for legacy/unreconciled state. Deleting here could
                // destroy a post, profile slot or message unknown to this old URL-only event.
                continue;
            }
            if (metadata.DeleteAfter is null)
            {
                await WriteUnsafeAsync(metadata with
                {
                    PendingReferences = pending,
                    ReservedAt = HasActiveLegacyReservation(metadata, now) ? metadata.ReservedAt : null,
                    ReservationExpiresAt = HasActiveLegacyReservation(metadata, now)
                        ? metadata.ReservationExpiresAt
                        : null,
                    ReservationKind = HasActiveLegacyReservation(metadata, now) ? metadata.ReservationKind : null,
                    DeleteAfter = deleteAfter
                }, cancellationToken);
            }
            scheduled++;
        }
        return scheduled;
    }

    /// <summary>
    /// Authorizes and reserves managed URLs. Reservation is server-to-server only and keeps a
    /// successful domain mutation safe even if its attach outbox is temporarily dead-lettered.
    /// A later reference attach clears the reservation.
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
        if (candidates.Length == 0)
        {
            return unauthorized;
        }

        var validStoredNames = candidates
            .Select(TryNormalizeStoredName)
            .OfType<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        await using var lease = await AcquireAssetLeasesAsync(validStoredNames, cancellationToken);
        var authorizedMetadata = new List<UploadAssetMetadata>();
        foreach (var url in candidates)
        {
            var storedName = TryNormalizeStoredName(url);
            if (storedName is null || !File.Exists(ResolveAssetPath(storedName)))
            {
                unauthorized.Add(url);
                continue;
            }

            var read = await ReadMetadataUnsafeAsync(storedName, cancellationToken);
            if (read.Status != MetadataReadStatus.Loaded || read.Metadata is null ||
                read.Metadata.State == DeletedState ||
                read.Metadata.OwnerUserId != ownerUserId)
            {
                unauthorized.Add(url);
                continue;
            }

            authorizedMetadata.Add(read.Metadata);
        }

        // Never reserve only a prefix of a rejected authorization batch. The domain
        // mutation will not run when any URL is foreign/invalid, so partial leases are
        // pure storage pins with no parent that can ever claim them.
        if (unauthorized.Count > 0)
        {
            return unauthorized;
        }

        var now = DateTimeOffset.UtcNow;
        var reservationExpiresAt = now.AddMinutes(
            Math.Clamp(_options.AuthorizationReservationMinutes, 5, 10_080));
        foreach (var metadata in authorizedMetadata
                     .GroupBy(item => item.StoredName, StringComparer.OrdinalIgnoreCase)
                     .Select(group => group.First()))
        {
            // URL-only authorization is a compatibility lease. It intentionally remains
            // independent from named parent references because an old caller cannot prove
            // which parent will later claim the URL. Never let a later attach clear this
            // lease early; it expires conservatively instead.
            await WriteUnsafeAsync(metadata with
            {
                ReservedAt = now,
                ReservationExpiresAt = reservationExpiresAt,
                ReservationKind = LegacyUrlReservationKind,
                CleanupMarkedAt = null,
                DeleteAfter = null
            }, cancellationToken);
        }
        return unauthorized;
    }

    /// <summary>
    /// New parent-aware authorization. Each stable reference receives its own bounded
    /// reservation, including when the asset already has other active parents. An attach
    /// can only release the reservation carrying the same reference ID and an equal/newer
    /// operation timestamp.
    /// </summary>
    public async Task<UploadReferenceAuthorizationResult> AuthorizeReferencesDetailedAsync(
        IEnumerable<UploadMediaReference> references,
        long ownerUserId,
        DateTimeOffset? operationAt,
        CancellationToken cancellationToken)
    {
        var requested = references.ToArray();
        var normalized = NormalizeReferences(requested);
        if (!TryNormalizeRequiredOperationTime(operationAt, out var occurredAt))
        {
            return new UploadReferenceAuthorizationResult(
                requested.Length,
                normalized.Count,
                Array.Empty<string>(),
                0,
                requested.Length);
        }

        var unauthorized = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (normalized.Count != requested.Length)
        {
            foreach (var reference in requested)
            {
                if (!normalized.Any(item =>
                        string.Equals(item.ReferenceId, reference.ReferenceId, StringComparison.Ordinal) &&
                        string.Equals(item.Url, reference.Url, StringComparison.OrdinalIgnoreCase)))
                {
                    unauthorized.Add(reference.Url ?? string.Empty);
                }
            }
            return new UploadReferenceAuthorizationResult(
                requested.Length,
                normalized.Count,
                unauthorized.ToArray(),
                0);
        }

        await using var lease = await AcquireAssetLeasesAsync(
            normalized.Select(reference => reference.StoredName),
            cancellationToken);
        var plans = new List<(UploadAssetMetadata Metadata, IReadOnlyList<NormalizedReference> References)>();
        var capacityExceeded = 0;
        foreach (var group in normalized.GroupBy(item => item.StoredName, StringComparer.OrdinalIgnoreCase))
        {
            var storedName = group.Key;
            if (!File.Exists(ResolveAssetPath(storedName)))
            {
                foreach (var reference in group) unauthorized.Add(reference.Url);
                continue;
            }
            var read = await ReadMetadataUnsafeAsync(storedName, cancellationToken);
            if (read.Status != MetadataReadStatus.Loaded || read.Metadata is null ||
                read.Metadata.State == DeletedState || read.Metadata.OwnerUserId != ownerUserId)
            {
                foreach (var reference in group) unauthorized.Add(reference.Url);
                continue;
            }
            var metadata = read.Metadata;
            var active = CopyReferences(metadata.ActiveReferences);
            var released = CopyReferences(metadata.ReleasedReferences);
            var pending = CopyPendingReferences(metadata.PendingReferences);
            RemoveExpiredPendingReferences(pending, DateTimeOffset.UtcNow);
            var staleReferences = group
                .Where(reference =>
                    IsAttachStale(
                        metadata,
                        released,
                        pending,
                        reference.ReferenceId,
                        occurredAt))
                .ToArray();
            if (staleReferences.Length > 0)
            {
                foreach (var reference in staleReferences) unauthorized.Add(reference.Url);
                continue;
            }
            var additional = group.Count(reference =>
                !(active.TryGetValue(reference.ReferenceId, out var attachedAt) && attachedAt >= occurredAt) &&
                !pending.ContainsKey(reference.ReferenceId));
            if (pending.Count + additional > MaxPendingReferencesPerAsset)
            {
                capacityExceeded += group.Count();
                continue;
            }
            plans.Add((metadata, group.ToArray()));
        }

        if (unauthorized.Count > 0 || capacityExceeded > 0)
        {
            return new UploadReferenceAuthorizationResult(
                requested.Length,
                normalized.Count,
                unauthorized.ToArray(),
                capacityExceeded);
        }

        var now = DateTimeOffset.UtcNow;
        var reservationExpiresAt = now.AddMinutes(
            Math.Clamp(_options.AuthorizationReservationMinutes, 5, 10_080));
        foreach (var plan in plans)
        {
            var pending = CopyPendingReferences(plan.Metadata.PendingReferences);
            var active = CopyReferences(plan.Metadata.ActiveReferences);
            RemoveExpiredPendingReferences(pending, now);
            foreach (var reference in plan.References)
            {
                if (active.TryGetValue(reference.ReferenceId, out var attachedAt) &&
                    attachedAt >= occurredAt)
                {
                    continue;
                }
                if (!pending.TryGetValue(reference.ReferenceId, out var existing) ||
                    existing.OperationAt <= occurredAt)
                {
                    pending[reference.ReferenceId] = new UploadPendingReferenceReservation(
                        occurredAt,
                        now,
                        reservationExpiresAt);
                }
            }
            await WriteUnsafeAsync(plan.Metadata with
            {
                LifecycleVersion = CurrentLifecycleVersion,
                PendingReferences = pending,
                ReleasedReferenceWatermark = null,
                LegacyPinned = plan.Metadata.LegacyPinned || RequiresConservativePin(plan.Metadata),
                CleanupMarkedAt = null,
                DeleteAfter = null
            }, cancellationToken);
        }

        return new UploadReferenceAuthorizationResult(
            requested.Length,
            normalized.Count,
            Array.Empty<string>(),
            0);
    }

    public async Task<bool> DeletePendingOwnedAsync(
        string assetId,
        long ownerUserId,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParseExact(assetId, "N", out _))
        {
            return false;
        }
        await using var lease = await AcquireAssetIdLeasesAsync([assetId], cancellationToken);
        var read = await ReadMetadataByAssetIdUnsafeAsync(assetId, cancellationToken);
        if (read.Status != MetadataReadStatus.Loaded || read.Metadata is null)
        {
            return false;
        }
        var metadata = read.Metadata;
        var now = DateTimeOffset.UtcNow;
        var pending = CopyPendingReferences(metadata.PendingReferences);
        RemoveExpiredPendingReferences(pending, now);
        if (metadata.OwnerUserId != ownerUserId ||
            metadata.State != PendingState ||
            HasActiveLegacyReservation(metadata, now) ||
            pending.Count > 0 ||
            CopyReferences(metadata.ActiveReferences).Count > 0)
        {
            return false;
        }
        await TombstoneThenDeleteUnsafeAsync(metadata with
        {
            PendingReferences = pending,
            ReservedAt = null,
            ReservationExpiresAt = null,
            ReservationKind = null
        }, now, cancellationToken);
        return true;
    }

    /// <summary>
    /// Browser acknowledgement extends a reservation but does not create a durable anonymous
    /// reference. The owning domain service remains authoritative and attaches a named parent.
    /// </summary>
    public async Task<int> FinalizeOwnedAsync(
        IEnumerable<string> assetIds,
        long ownerUserId,
        CancellationToken cancellationToken)
    {
        var requested = assetIds.ToArray();
        if (requested.Length > MaxLifecycleBatchSize ||
            requested.Any(id => !Guid.TryParseExact(id, "N", out _)))
        {
            return 0;
        }
        var candidates = requested
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var now = DateTimeOffset.UtcNow;
        var reservationExpiresAt = now.AddMinutes(
            Math.Clamp(_options.BrowserReservationMinutes, 5, 1_440));
        var metadataToReserve = new List<UploadAssetMetadata>();
        await using var lease = await AcquireAssetIdLeasesAsync(candidates, cancellationToken);
        foreach (var assetId in candidates)
        {
            var read = await ReadMetadataByAssetIdUnsafeAsync(assetId, cancellationToken);
            if (read.Status != MetadataReadStatus.Loaded || read.Metadata is null)
            {
                return 0;
            }
            var metadata = read.Metadata;
            if (metadata.State == DeletedState || metadata.OwnerUserId != ownerUserId ||
                !File.Exists(ResolveAssetPath(metadata.StoredName)))
            {
                return 0;
            }

            metadataToReserve.Add(metadata);
        }

        foreach (var metadata in metadataToReserve)
        {
            var hasActiveNonBrowserReservation =
                HasActiveLegacyReservation(metadata, now) &&
                !string.Equals(
                    metadata.ReservationKind,
                    BrowserReservationKind,
                    StringComparison.Ordinal);
            await WriteUnsafeAsync(metadata with
            {
                LifecycleVersion = CurrentLifecycleVersion,
                PendingReferences = CopyPendingReferences(metadata.PendingReferences),
                ReleasedReferenceWatermark = null,
                LegacyPinned = metadata.LegacyPinned || RequiresConservativePin(metadata),
                // A browser acknowledgement is weaker than an old URL-only/unknown
                // service reservation. Do not overwrite that conservative lease: a
                // later exact attach is allowed to clear browser state, but cannot prove
                // which parent owns a legacy URL-only reservation.
                ReservedAt = hasActiveNonBrowserReservation ? metadata.ReservedAt : now,
                ReservationExpiresAt = hasActiveNonBrowserReservation
                    ? metadata.ReservationExpiresAt
                    : reservationExpiresAt,
                ReservationKind = hasActiveNonBrowserReservation
                    ? metadata.ReservationKind
                    : BrowserReservationKind,
                CleanupMarkedAt = null,
                DeleteAfter = null
            }, cancellationToken);
        }
        return metadataToReserve.Count;
    }

    public async Task<int> CleanupExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        var deleted = 0;
        var pendingGrace = TimeSpan.FromMinutes(
            Math.Clamp(_options.PendingCleanupGraceMinutes, 5, 10_080));
        var referenceGrace = TimeSpan.FromMinutes(
            Math.Clamp(_options.ReferenceDeleteGraceMinutes, 0, 10_080));
        var tombstoneRetention = TimeSpan.FromMinutes(
            Math.Clamp(_options.DeletedTombstoneRetentionMinutes, 60, 525_600));
        await CleanupOrphanedQuarantineAsync(now, cancellationToken);
        var metadataRoot = ResolveMetadataRoot();
        if (!Directory.Exists(metadataRoot))
        {
            return 0;
        }
        await CleanupStaleMetadataAuxiliaryFilesAsync(metadataRoot, now, cancellationToken);

        // Snapshot names without holding the shared lock, then serialize and re-read one
        // asset at a time. This preserves cross-process correctness while preventing a
        // large/remote store scan from blocking every upload and lifecycle request.
        foreach (var metadataPath in Directory.EnumerateFiles(
                     metadataRoot,
                     "*.json",
                     SearchOption.TopDirectoryOnly))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var assetId = IOPath.GetFileNameWithoutExtension(metadataPath);
            try
            {
                if (!Guid.TryParseExact(assetId, "N", out _))
                {
                    // Temporary/foreign metadata names are never guessed safe to delete.
                    continue;
                }
                await using var lease = await AcquireAssetIdLeasesAsync([assetId], cancellationToken);
                if (!File.Exists(metadataPath))
                {
                    continue;
                }
                var read = await ReadMetadataByAssetIdUnsafeAsync(assetId, cancellationToken);
                if (read.Status != MetadataReadStatus.Loaded || read.Metadata is null)
                {
                    // Corrupt/unreadable and pre-v2 metadata is retained for operator repair;
                    // cleanup must never guess that an existing parent is absent.
                    continue;
                }

                var metadata = read.Metadata;
            if (metadata.State == DeletedState)
            {
                if (metadata.LifecycleVersion < CurrentLifecycleVersion ||
                    !IsMinimalDeletedTombstone(metadata))
                {
                    if (await TombstoneThenDeleteUnsafeAsync(
                            metadata,
                            metadata.DeletedAt ?? now,
                            cancellationToken))
                    {
                        deleted++;
                    }
                    continue;
                }
                // A tombstone is written before the public bytes are removed. If a
                // process/SMB server died in that window, retry the physical delete on
                // every sweep while keeping the tombstone authoritative.
                if (TryDeletePhysicalFileUnsafe(metadata.StoredName))
                {
                    deleted++;
                }
                if (metadata.DeletedAt is { } deletedAt &&
                    deletedAt.Add(tombstoneRetention) <= now &&
                    !File.Exists(ResolveAssetPath(metadata.StoredName)))
                {
                    File.Delete(metadataPath);
                    continue;
                }
                continue;
            }

            if (RequiresConservativePin(metadata) || metadata.LegacyPinned)
            {
                continue;
            }

            var pending = CopyPendingReferences(metadata.PendingReferences);
            var pendingBefore = pending.Count;
            RemoveExpiredPendingReferences(pending, now);
            var hasLegacyReservation = HasActiveLegacyReservation(metadata, now);
            var active = CopyReferences(metadata.ActiveReferences);
            var changed = pending.Count != pendingBefore;
            if (!hasLegacyReservation && (metadata.ReservedAt is not null || metadata.ReservationExpiresAt is not null))
            {
                changed = true;
            }

            if (active.Count > 0 || pending.Count > 0 || hasLegacyReservation)
            {
                if (changed)
                {
                    await WriteUnsafeAsync(metadata with
                    {
                        PendingReferences = pending,
                        ReservedAt = hasLegacyReservation ? metadata.ReservedAt : null,
                        ReservationExpiresAt = hasLegacyReservation ? metadata.ReservationExpiresAt : null,
                        ReservationKind = hasLegacyReservation ? metadata.ReservationKind : null,
                        CleanupMarkedAt = null,
                        DeleteAfter = null
                    }, cancellationToken);
                }
                continue;
            }

            if (metadata.State == PendingState && metadata.ExpiresAt <= now)
            {
                if (metadata.CleanupMarkedAt is null)
                {
                    await WriteUnsafeAsync(metadata with
                    {
                        PendingReferences = pending,
                        ReservedAt = null,
                        ReservationExpiresAt = null,
                        ReservationKind = null,
                        CleanupMarkedAt = now,
                        DeleteAfter = null
                    }, cancellationToken);
                    continue;
                }
                if (metadata.CleanupMarkedAt.Value.Add(pendingGrace) <= now &&
                    await TombstoneThenDeleteUnsafeAsync(metadata with
                    {
                        PendingReferences = pending,
                        ReservedAt = null,
                        ReservationExpiresAt = null,
                        ReservationKind = null
                    }, now, cancellationToken))
                {
                    deleted++;
                }
                continue;
            }

            if (metadata.State == CommittedState && metadata.DeleteAfter is null)
            {
                if (referenceGrace <= TimeSpan.Zero)
                {
                    if (await TombstoneThenDeleteUnsafeAsync(metadata with
                    {
                        PendingReferences = pending,
                        ReservedAt = null,
                        ReservationExpiresAt = null,
                        ReservationKind = null
                    }, now, cancellationToken))
                    {
                        deleted++;
                    }
                }
                else
                {
                    await WriteUnsafeAsync(metadata with
                    {
                        PendingReferences = pending,
                        ReservedAt = null,
                        ReservationExpiresAt = null,
                        ReservationKind = null,
                        DeleteAfter = now.Add(referenceGrace)
                    }, cancellationToken);
                }
                continue;
            }

                if (metadata.State == CommittedState && metadata.DeleteAfter <= now &&
                    await TombstoneThenDeleteUnsafeAsync(metadata with
                    {
                        PendingReferences = pending,
                        ReservedAt = null,
                        ReservationExpiresAt = null,
                        ReservationKind = null
                    }, now, cancellationToken))
                {
                    deleted++;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                // One poisoned or temporarily unwritable asset must not starve every
                // later deletion candidate in deterministic directory order.
                _logger.LogError(
                    exception,
                    "Media cleanup failed for asset {AssetId}; later assets will continue and this asset will retry.",
                    assetId);
            }
        }
        return deleted;
    }

    private List<NormalizedReference> NormalizeReferences(IEnumerable<UploadMediaReference> references)
    {
        var result = new List<NormalizedReference>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var reference in references)
        {
            var storedName = TryNormalizeStoredName(reference.Url);
            if (storedName is null || !TryGetAssetId(storedName, out var assetId) ||
                !IsValidReferenceId(reference.ReferenceId) ||
                (reference.AssetId is not null &&
                 (!Guid.TryParseExact(reference.AssetId, "N", out _) ||
                  !string.Equals(reference.AssetId, assetId, StringComparison.OrdinalIgnoreCase))))
            {
                continue;
            }
            var key = storedName.ToUpperInvariant() + "\n" + reference.ReferenceId;
            if (seen.Add(key))
            {
                result.Add(new NormalizedReference(
                    storedName,
                    reference.ReferenceId,
                    reference.Url ?? string.Empty,
                    assetId));
            }
        }
        return result;
    }

    private static bool IsValidReferenceId(string? referenceId)
    {
        if (string.IsNullOrWhiteSpace(referenceId) || referenceId.Length > 192 ||
            referenceId[0] is < 'a' or > 'z')
        {
            return false;
        }
        foreach (var value in referenceId)
        {
            if (!(char.IsAsciiLetterOrDigit(value) || value is ':' or '-' or '_' or '.'))
            {
                return false;
            }
        }
        return referenceId.Contains(':', StringComparison.Ordinal);
    }

    private IEnumerable<string> NormalizeStoredNames(IEnumerable<string> urls) => urls
        .Where(url => !string.IsNullOrWhiteSpace(url))
        .Select(TryNormalizeStoredName)
        .Where(name => name is not null && TryGetAssetId(name, out _))
        .OfType<string>()
        .Distinct(StringComparer.OrdinalIgnoreCase);

    private static bool TryGetAssetId(string storedName, out string assetId)
    {
        assetId = IOPath.GetFileNameWithoutExtension(storedName);
        return UploadSecurity.IsSafeLeafFileName(storedName) &&
               !string.IsNullOrEmpty(IOPath.GetExtension(storedName)) &&
               Guid.TryParseExact(assetId, "N", out _);
    }

    private string? TryNormalizeStoredName(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return null;
        }

        string path;
        if (Uri.TryCreate(url, UriKind.Absolute, out var absolute))
        {
            if (absolute.Scheme is not ("http" or "https") || !string.IsNullOrEmpty(absolute.UserInfo) ||
                !IsAllowedMediaOrigin(absolute))
            {
                return null;
            }
            path = absolute.AbsolutePath;
        }
        else
        {
            path = url.Split('?', '#')[0];
        }

        if (!path.StartsWith("/media/files/", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        string storedName;
        try
        {
            storedName = Uri.UnescapeDataString(path["/media/files/".Length..]);
        }
        catch (UriFormatException)
        {
            return null;
        }
        return UploadSecurity.IsSafeLeafFileName(storedName) ? storedName : null;
    }

    private bool IsAllowedMediaOrigin(Uri absolute)
    {
        var origin = absolute.GetLeftPart(UriPartial.Authority).TrimEnd('/');
        return (_options.AllowedMediaOrigins ?? Array.Empty<string>())
            .Select(value => value?.Trim().TrimEnd('/'))
            .Any(value => !string.IsNullOrWhiteSpace(value) &&
                          string.Equals(value, origin, StringComparison.OrdinalIgnoreCase));
    }

    private static bool TryNormalizeRequiredOperationTime(
        DateTimeOffset? operationAt,
        out DateTimeOffset normalized)
    {
        normalized = default;
        if (!operationAt.HasValue)
        {
            return false;
        }
        var value = operationAt.Value.ToUniversalTime();
        if (value > DateTimeOffset.UtcNow.Add(MaximumFutureOperationSkew))
        {
            return false;
        }
        normalized = value;
        return true;
    }

    private static bool HasActiveLegacyReservation(UploadAssetMetadata metadata, DateTimeOffset now) =>
        metadata.ReservedAt is not null &&
        (metadata.ReservationExpiresAt is null || metadata.ReservationExpiresAt > now);

    private static Dictionary<string, DateTimeOffset> CopyReferences(
        Dictionary<string, DateTimeOffset>? source) =>
        source is null
            ? new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal)
            : new Dictionary<string, DateTimeOffset>(source, StringComparer.Ordinal);

    private static Dictionary<string, UploadPendingReferenceReservation> CopyPendingReferences(
        Dictionary<string, UploadPendingReferenceReservation>? source) =>
        source is null
            ? new Dictionary<string, UploadPendingReferenceReservation>(StringComparer.Ordinal)
            : new Dictionary<string, UploadPendingReferenceReservation>(source, StringComparer.Ordinal);

    private static bool IsAttachStale(
        UploadAssetMetadata metadata,
        IReadOnlyDictionary<string, DateTimeOffset> released,
        IReadOnlyDictionary<string, UploadPendingReferenceReservation> pending,
        string referenceId,
        DateTimeOffset operationAt)
    {
        if (released.TryGetValue(referenceId, out var releasedAt) && releasedAt >= operationAt)
        {
            return true;
        }
        if (metadata.CompactedReleaseFloor is not { } floor || floor < operationAt)
        {
            return false;
        }

        // The floor deliberately loses reference IDs and therefore may reject an old but
        // unrelated operation. The only safe exception is proof that this exact parent was
        // reserved before compaction advanced past it. Detach removes that reservation, so
        // this cannot resurrect a parent that was already released.
        return !pending.TryGetValue(referenceId, out var reservation) ||
               reservation.OperationAt > operationAt;
    }

    private static DateTimeOffset? CompactReleasedReferences(
        Dictionary<string, DateTimeOffset> released,
        DateTimeOffset? compactedFloor)
    {
        if (compactedFloor is { } existingFloor)
        {
            foreach (var covered in released
                         .Where(item => item.Value <= existingFloor)
                         .Select(item => item.Key)
                         .ToArray())
            {
                released.Remove(covered);
            }
        }
        if (released.Count <= MaxReleasedReferencesPerAsset)
        {
            return compactedFloor;
        }

        var removeCount = released.Count - ReleasedReferenceCompactionTarget;
        var oldest = released
            .OrderBy(item => item.Value)
            .ThenBy(item => item.Key, StringComparer.Ordinal)
            .Take(removeCount)
            .ToArray();
        foreach (var item in oldest)
        {
            if (compactedFloor is null || item.Value > compactedFloor.Value)
            {
                compactedFloor = item.Value;
            }
            released.Remove(item.Key);
        }

        // Entries tied with the cutoff are covered by the same floor. Removing them too
        // keeps the representation canonical and prevents equal-timestamp churn from
        // immediately filling the map again.
        if (compactedFloor is { } newFloor)
        {
            foreach (var covered in released
                         .Where(item => item.Value <= newFloor)
                         .Select(item => item.Key)
                         .ToArray())
            {
                released.Remove(covered);
            }
        }
        return compactedFloor;
    }

    private static bool RemoveExpiredPendingReferences(
        Dictionary<string, UploadPendingReferenceReservation> pending,
        DateTimeOffset now)
    {
        var changed = false;
        foreach (var item in pending
                     .Where(item => item.Value.ExpiresAt <= now)
                     .Select(item => item.Key)
                     .ToArray())
        {
            changed |= pending.Remove(item);
        }
        return changed;
    }

    private static bool RequiresConservativePin(UploadAssetMetadata metadata) =>
        metadata.LifecycleVersion < 2 || metadata.ReleasedReferenceWatermark is not null;

    private static bool IsMinimalDeletedTombstone(UploadAssetMetadata metadata) =>
        metadata.State == DeletedState &&
        metadata.OwnerUserId == 0 &&
        metadata.Size == 0 &&
        string.IsNullOrEmpty(metadata.OriginalName) &&
        string.IsNullOrEmpty(metadata.ContentType) &&
        metadata.DeletedAt is not null &&
        CopyReferences(metadata.ActiveReferences).Count == 0 &&
        CopyReferences(metadata.ReleasedReferences).Count == 0 &&
        CopyPendingReferences(metadata.PendingReferences).Count == 0 &&
        metadata.ReleasedReferenceWatermark is null &&
        metadata.CompactedReleaseFloor is null &&
        !metadata.LegacyPinned &&
        metadata.ReservedAt is null &&
        metadata.ReservationExpiresAt is null &&
        metadata.ReservationKind is null;

    private async Task CleanupOrphanedQuarantineAsync(
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var quarantineRoot = IOPath.Combine(
            UploadSecurity.ResolveStorageRoot(_options),
            ".quarantine");
        if (!Directory.Exists(quarantineRoot))
        {
            return;
        }
        var cutoff = now.Subtract(TimeSpan.FromMinutes(
            Math.Clamp(_options.QuarantineRetentionMinutes, 30, 10_080)));
        foreach (var path in Directory.EnumerateFiles(
                     quarantineRoot,
                     "*",
                     SearchOption.TopDirectoryOnly))
        {
            cancellationToken.ThrowIfCancellationRequested();
            DateTimeOffset lastWrite;
            try
            {
                lastWrite = File.GetLastWriteTimeUtc(path);
            }
            catch (IOException)
            {
                continue;
            }
            if (lastWrite > cutoff)
            {
                continue;
            }
            try
            {
                // An in-flight sanitizer owns the file with FileShare.None. Never race it
                // by deleting a file that can still be open in another process.
                await using var probe = new FileStream(
                    path,
                    FileMode.Open,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    1,
                    FileOptions.Asynchronous);
                await probe.FlushAsync(cancellationToken);
                await probe.DisposeAsync();
                File.Delete(path);
            }
            catch (FileNotFoundException)
            {
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private static async Task CleanupStaleMetadataAuxiliaryFilesAsync(
        string metadataRoot,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var cutoff = now.Subtract(TimeSpan.FromMinutes(30));
        foreach (var pattern in new[] { "*.tmp-*", ".ready-*" })
        {
            foreach (var path in Directory.EnumerateFiles(
                         metadataRoot,
                         pattern,
                         SearchOption.TopDirectoryOnly))
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    if (File.GetLastWriteTimeUtc(path) > cutoff)
                    {
                        continue;
                    }
                    await using var probe = new FileStream(
                        path,
                        FileMode.Open,
                        FileAccess.ReadWrite,
                        FileShare.None,
                        1,
                        FileOptions.Asynchronous);
                    await probe.FlushAsync(cancellationToken);
                    await probe.DisposeAsync();
                    File.Delete(path);
                }
                catch (FileNotFoundException)
                {
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }
        }
    }

    private bool TryDeletePhysicalFileUnsafe(string storedName)
    {
        var assetPath = ResolveAssetPath(storedName);
        if (!File.Exists(assetPath))
        {
            return false;
        }
        try
        {
            File.Delete(assetPath);
            return true;
        }
        catch (IOException)
        {
            RecordPhysicalDeleteFailure(storedName, "io");
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            RecordPhysicalDeleteFailure(storedName, "unauthorized");
            return false;
        }
    }

    private void RecordPhysicalDeleteFailure(string storedName, string reason)
    {
        var assetId = TryGetAssetId(storedName, out var parsedAssetId)
            ? parsedAssetId
            : "invalid";
        PhysicalDeleteFailureCounter.Add(1, new KeyValuePair<string, object?>("reason", reason));
        _logger.LogWarning(
            "Physical media deletion failed for asset {AssetId} ({Reason}); its tombstone remains non-serving and cleanup will retry.",
            assetId,
            reason);
    }

    private async Task<LifecycleLease> AcquireAssetLeasesAsync(
        IEnumerable<string> storedNames,
        CancellationToken cancellationToken)
    {
        var assetIds = new List<string>();
        foreach (var storedName in storedNames)
        {
            if (!TryGetAssetId(storedName, out var assetId))
            {
                throw new InvalidOperationException("Invalid media asset identifier.");
            }
            assetIds.Add(assetId);
        }
        return await AcquireAssetIdLeasesAsync(assetIds, cancellationToken);
    }

    private Task<LifecycleLease> AcquireAssetIdLeasesAsync(
        IEnumerable<string> assetIds,
        CancellationToken cancellationToken)
    {
        var buckets = new List<string>();
        foreach (var assetId in assetIds)
        {
            if (!Guid.TryParseExact(assetId, "N", out _))
            {
                throw new InvalidOperationException("Invalid media asset identifier.");
            }
            // A bounded set of shared lock files avoids one permanent lock inode per
            // uploaded asset while still allowing unrelated buckets to progress in
            // parallel. Multi-asset operations acquire buckets in sorted order.
            buckets.Add("asset-" + assetId[..2].ToLowerInvariant());
        }
        return AcquireNamedLifecycleLeasesAsync(buckets, cancellationToken);
    }

    private async Task<LifecycleLease> AcquireNamedLifecycleLeasesAsync(
        IEnumerable<string> lockNames,
        CancellationToken cancellationToken)
    {
        var names = lockNames
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();
        var streams = new List<FileStream>(names.Length);
        var timeoutSeconds = Math.Clamp(_options.LifecycleLockTimeoutSeconds, 1, 120);
        var deadline = DateTimeOffset.UtcNow.AddSeconds(timeoutSeconds);
        var lockRoot = IOPath.Combine(ResolveMetadataRoot(), ".locks");

        try
        {
            try
            {
                Directory.CreateDirectory(lockRoot);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                throw new TimeoutException("Shared media lifecycle storage is unavailable.", exception);
            }
            foreach (var name in names)
            {
                if (!IsSafeLockName(name))
                {
                    throw new InvalidOperationException("Invalid media lifecycle lock identifier.");
                }
                var lockPath = IOPath.Combine(lockRoot, name + ".lock");
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (DateTimeOffset.UtcNow >= deadline)
                    {
                        throw new TimeoutException("Timed out acquiring shared media lifecycle locks.");
                    }
                    try
                    {
                        streams.Add(new FileStream(
                            lockPath,
                            FileMode.OpenOrCreate,
                            FileAccess.ReadWrite,
                            FileShare.None,
                            1,
                            FileOptions.Asynchronous | FileOptions.WriteThrough));
                        break;
                    }
                    catch (IOException)
                    {
                        var remaining = deadline - DateTimeOffset.UtcNow;
                        if (remaining <= TimeSpan.Zero)
                        {
                            throw new TimeoutException("Timed out acquiring shared media lifecycle locks.");
                        }
                        await Task.Delay(
                            remaining < TimeSpan.FromMilliseconds(LockRetryMilliseconds)
                                ? remaining
                                : TimeSpan.FromMilliseconds(LockRetryMilliseconds),
                            cancellationToken);
                    }
                    catch (UnauthorizedAccessException exception)
                    {
                        throw new TimeoutException("Shared media lifecycle storage is unavailable.", exception);
                    }
                }
            }
            return new LifecycleLease(streams);
        }
        catch
        {
            for (var index = streams.Count - 1; index >= 0; index--)
            {
                await streams[index].DisposeAsync();
            }
            throw;
        }
    }

    private static bool IsSafeLockName(string value) =>
        value.Length is > 0 and <= 64 &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    private async Task WriteUnsafeAsync(UploadAssetMetadata metadata, CancellationToken cancellationToken)
    {
        var metadataRoot = ResolveMetadataRoot();
        Directory.CreateDirectory(metadataRoot);
        var target = ResolveMetadataPath(metadata.StoredName);
        var temporary = target + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var stream = new FileStream(
                             temporary,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             16 * 1024,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, metadata, JsonOptions, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, target, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private Task<MetadataReadResult> ReadMetadataUnsafeAsync(
        string storedName,
        CancellationToken cancellationToken) =>
        ReadMetadataPathUnsafeAsync(ResolveMetadataPath(storedName), storedName, cancellationToken);

    private Task<MetadataReadResult> ReadMetadataByAssetIdUnsafeAsync(
        string assetId,
        CancellationToken cancellationToken) =>
        ReadMetadataPathUnsafeAsync(ResolveMetadataPathFromAssetId(assetId), null, cancellationToken);

    private static async Task<MetadataReadResult> ReadMetadataPathUnsafeAsync(
        string metadataPath,
        string? expectedStoredName,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(metadataPath))
        {
            return new MetadataReadResult(MetadataReadStatus.Missing, null);
        }
        try
        {
            if (new FileInfo(metadataPath).Length is <= 0 or > MaxMetadataBytes)
            {
                return new MetadataReadResult(MetadataReadStatus.Unreadable, null);
            }
            UploadAssetMetadata? metadata;
            await using (var stream = new FileStream(
                             metadataPath,
                             FileMode.Open,
                             FileAccess.Read,
                             FileShare.ReadWrite | FileShare.Delete,
                             16 * 1024,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                metadata = await JsonSerializer.DeserializeAsync<UploadAssetMetadata>(
                    stream,
                    JsonOptions,
                    cancellationToken);
            }
            if (metadata is null ||
                !UploadSecurity.IsSafeLeafFileName(metadata.StoredName) ||
                !Guid.TryParseExact(metadata.AssetId, "N", out _) ||
                metadata.State is not (PendingState or CommittedState or DeletedState) ||
                !string.Equals(
                    metadata.AssetId,
                    IOPath.GetFileNameWithoutExtension(metadata.StoredName),
                    StringComparison.OrdinalIgnoreCase) ||
                (metadata.ActiveReferences?.Count ?? 0) > MaxReferencesPerAsset ||
                (metadata.ReleasedReferences?.Count ?? 0) > MaxReleasedReferencesPerAsset ||
                (metadata.PendingReferences?.Count ?? 0) > MaxPendingReferencesPerAsset ||
                (metadata.ActiveReferences?.Keys.Any(key => !IsValidReferenceId(key)) ?? false) ||
                (metadata.ReleasedReferences?.Keys.Any(key => !IsValidReferenceId(key)) ?? false) ||
                (metadata.PendingReferences?.Keys.Any(key => !IsValidReferenceId(key)) ?? false) ||
                (metadata.PendingReferences?.Values.Any(value =>
                    value is null || value.ExpiresAt <= value.ReservedAt ||
                    value.OperationAt > value.ReservedAt.Add(MaximumFutureOperationSkew)) ?? false) ||
                (metadata.ReservationKind is not null &&
                    metadata.ReservationKind != BrowserReservationKind &&
                    metadata.ReservationKind != LegacyUrlReservationKind) ||
                (metadata.ReservationKind is not null &&
                    (metadata.ReservedAt is null || metadata.ReservationExpiresAt is null)) ||
                (metadata.State != DeletedState && metadata.OwnerUserId <= 0) ||
                (metadata.State == DeletedState && metadata.LifecycleVersion >= CurrentLifecycleVersion &&
                    (metadata.OwnerUserId != 0 || metadata.Size != 0 ||
                     !string.IsNullOrEmpty(metadata.OriginalName) ||
                     !string.IsNullOrEmpty(metadata.ContentType) ||
                     metadata.DeletedAt is null ||
                     (metadata.ActiveReferences?.Count ?? 0) != 0 ||
                     (metadata.PendingReferences?.Count ?? 0) != 0 ||
                     metadata.ReservedAt is not null ||
                     metadata.ReservationExpiresAt is not null)) ||
                (!string.IsNullOrEmpty(expectedStoredName) &&
                 !string.Equals(metadata.StoredName, expectedStoredName, StringComparison.OrdinalIgnoreCase)))
            {
                return new MetadataReadResult(MetadataReadStatus.Unreadable, null);
            }
            return new MetadataReadResult(MetadataReadStatus.Loaded, metadata);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception is InvalidOperationException or JsonException or IOException or UnauthorizedAccessException)
        {
            return new MetadataReadResult(MetadataReadStatus.Unreadable, null);
        }
    }

    private async Task<bool> TombstoneThenDeleteUnsafeAsync(
        UploadAssetMetadata metadata,
        DateTimeOffset deletedAt,
        CancellationToken cancellationToken)
    {
        // Write the authoritative tombstone first. Public serving checks this state,
        // and the next cleanup sweep retries deletion if the process dies after this
        // durable write but before the bytes can be removed.
        var tombstone = metadata with
        {
            OwnerUserId = 0,
            OriginalName = string.Empty,
            ContentType = string.Empty,
            Size = 0,
            State = DeletedState,
            CreatedAt = deletedAt,
            ExpiresAt = null,
            ActiveReferences = new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal),
            ReleasedReferences = new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal),
            PendingReferences = new Dictionary<string, UploadPendingReferenceReservation>(StringComparer.Ordinal),
            ReleasedReferenceWatermark = null,
            CompactedReleaseFloor = null,
            LegacyPinned = false,
            ReservedAt = null,
            ReservationExpiresAt = null,
            ReservationKind = null,
            CleanupMarkedAt = null,
            DeleteAfter = null,
            PrivacyMetadataVersion = 0,
            PrivacyMetadataSanitizedAt = null,
            DeletedAt = deletedAt,
            LifecycleVersion = CurrentLifecycleVersion
        };
        await WriteUnsafeAsync(tombstone, cancellationToken);
        return TryDeletePhysicalFileUnsafe(metadata.StoredName);
    }

    private string ResolveAssetPath(string storedName)
    {
        if (!UploadSecurity.IsSafeLeafFileName(storedName))
        {
            throw new InvalidOperationException("Unsafe stored media name.");
        }
        var root = UploadSecurity.ResolveStorageRoot(_options);
        var path = IOPath.GetFullPath(IOPath.Combine(root, storedName));
        if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Media path escaped storage root.");
        }
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
        if (!Guid.TryParseExact(assetId, "N", out _))
        {
            throw new InvalidOperationException("Invalid media asset identifier.");
        }
        return IOPath.Combine(ResolveMetadataRoot(), assetId + ".json");
    }

    private sealed record NormalizedReference(
        string StoredName,
        string ReferenceId,
        string Url,
        string AssetId);
    private sealed record ReferenceMutationPlan(
        UploadAssetMetadata Metadata,
        IReadOnlyList<NormalizedReference> References);
    private sealed record MetadataReadResult(MetadataReadStatus Status, UploadAssetMetadata? Metadata);
    private enum MetadataReadStatus { Missing, Loaded, Unreadable }

    private sealed class LifecycleLease(IReadOnlyList<FileStream> streams) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            for (var index = streams.Count - 1; index >= 0; index--)
            {
                await streams[index].DisposeAsync();
            }
        }
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
        // Cleanup is also the crash-recovery path for committed/tombstoned assets.
        // Disabling browser staging must not disable physical-delete retries.
        if (!_options.CleanupEnabled)
        {
            return;
        }
        var interval = TimeSpan.FromMinutes(Math.Clamp(_options.CleanupIntervalMinutes, 1, 1_440));
        using var timer = new PeriodicTimer(interval);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var deleted = await _store.CleanupExpiredAsync(DateTimeOffset.UtcNow, stoppingToken);
                if (deleted > 0)
                {
                    if (_options.ReferenceDeleteGraceMinutes <= 0)
                    {
                        _logger.LogInformation(
                            "Deleted {Count} unreferenced media assets during lifecycle cleanup.",
                            deleted);
                    }
                    else
                    {
                        _logger.LogInformation(
                            "Deleted {Count} unreferenced media assets after lifecycle grace.",
                            deleted);
                    }
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Pending media cleanup failed.");
            }

            try
            {
                if (!await timer.WaitForNextTickAsync(stoppingToken))
                {
                    break;
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }
}
