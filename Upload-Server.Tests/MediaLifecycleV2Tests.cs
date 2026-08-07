using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

public sealed class MediaLifecycleV2Tests
{
    private const long Owner = 42;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task Detaching_one_parent_never_deletes_an_asset_reused_by_another_parent()
    {
        await WithStoresAsync(async (first, _, root) =>
        {
            var asset = await CreateAssetAsync(first, root, Owner);
            var now = DateTimeOffset.UtcNow;
            await AssertAttachedAsync(first, asset.Url, "social:media:post-a", now);
            await AssertAttachedAsync(first, asset.Url, "social:media:post-b", now.AddSeconds(1));

            var detached = await first.DetachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, "social:media:post-a")],
                Owner,
                now.AddSeconds(2),
                CancellationToken.None);
            Assert.Equal(1, detached.AppliedCount);

            await first.CleanupExpiredAsync(now.AddDays(2), CancellationToken.None);
            Assert.True(File.Exists(asset.Path));

            await first.DetachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, "social:media:post-b")],
                Owner,
                now.AddSeconds(3),
                CancellationToken.None);
            await first.CleanupExpiredAsync(DateTimeOffset.UtcNow.AddMinutes(6), CancellationToken.None);
            Assert.False(File.Exists(asset.Path));

            var lateAttach = await first.AttachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, "social:media:post-b")],
                Owner,
                now.AddSeconds(2),
                CancellationToken.None);
            Assert.Equal(1, lateAttach.AppliedCount);
            Assert.Equal(1, lateAttach.StaleCount);
            Assert.Equal(0, lateAttach.MissingFileCount);
        });
    }

    [Fact]
    public async Task Late_delete_for_old_parent_cannot_remove_new_parent_reusing_same_url()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            var now = DateTimeOffset.UtcNow;
            await AssertAttachedAsync(store, asset.Url, "social:media:old", now);
            await store.DetachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, "social:media:old")],
                Owner,
                now.AddSeconds(1),
                CancellationToken.None);
            await AssertAttachedAsync(store, asset.Url, "social:media:new", now.AddSeconds(2));

            await store.CleanupExpiredAsync(now.AddDays(2), CancellationToken.None);

            Assert.True(File.Exists(asset.Path));
            var metadata = await ReadMetadataAsync(root, asset.StoredName);
            Assert.Contains("social:media:new", metadata.ActiveReferences!.Keys);
        });
    }

    [Fact]
    public async Task Detach_before_stale_attach_is_terminal_for_that_parent_version()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            var now = DateTimeOffset.UtcNow;
            await store.DetachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, "messenger:message:abc:attachment:0")],
                Owner,
                now,
                CancellationToken.None);

            Assert.False(File.Exists(asset.Path));
            Assert.Equal(
                UploadAssetStore.DeletedState,
                (await ReadMetadataAsync(root, asset.StoredName)).State);

            var attach = await store.AttachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, "messenger:message:abc:attachment:0")],
                Owner,
                now,
                CancellationToken.None);

            Assert.Equal(1, attach.AppliedCount);
            Assert.Equal(1, attach.StaleCount);
            var metadata = await ReadMetadataAsync(root, asset.StoredName);
            Assert.Empty(metadata.ActiveReferences!);
        }, referenceDeleteGraceMinutes: 0);
    }

    [Fact]
    public async Task Equal_timestamp_detach_wins_over_an_already_attached_stable_parent()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            var operationAt = DateTimeOffset.UtcNow;
            const string referenceId = "socialgraph:media:equal-time";
            await AssertAttachedAsync(store, asset.Url, referenceId, operationAt);

            var detach = await store.DetachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, referenceId)],
                Owner,
                operationAt,
                CancellationToken.None);

            Assert.Equal(1, detach.AppliedCount);
            Assert.Equal(0, detach.StaleCount);
            Assert.False(File.Exists(asset.Path));
            var tombstone = await ReadMetadataAsync(root, asset.StoredName);
            Assert.Equal(UploadAssetStore.DeletedState, tombstone.State);
            Assert.Empty(tombstone.ReleasedReferences!);

            var replay = await store.DetachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, referenceId)],
                Owner,
                operationAt,
                CancellationToken.None);
            Assert.Equal(1, replay.AppliedCount);
            Assert.Equal(1, replay.StaleCount);
            var replayedTombstone = await ReadMetadataAsync(root, asset.StoredName);
            Assert.Equal(tombstone.DeletedAt, replayedTombstone.DeletedAt);
            Assert.Equal(tombstone.CreatedAt, replayedTombstone.CreatedAt);
            Assert.Empty(replayedTombstone.ReleasedReferences!);

            await store.CleanupExpiredAsync(
                tombstone.DeletedAt!.Value.AddMinutes(59),
                CancellationToken.None);
            Assert.True(File.Exists(MetadataPath(root, asset.StoredName)));
            await store.CleanupExpiredAsync(
                tombstone.DeletedAt.Value.AddMinutes(61),
                CancellationToken.None);
            Assert.False(File.Exists(MetadataPath(root, asset.StoredName)));
        }, referenceDeleteGraceMinutes: 0);
    }

    [Fact]
    public async Task Invalid_attach_batch_does_not_mutate_valid_prefix()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var own = await CreateAssetAsync(store, root, Owner);
            var foreign = await CreateAssetAsync(store, root, Owner + 1);

            var result = await store.AttachReferencesDetailedAsync(
                [
                    new UploadMediaReference(own.Url, "social:media:one"),
                    new UploadMediaReference(foreign.Url, "social:media:two")
                ],
                Owner,
                DateTimeOffset.UtcNow,
                CancellationToken.None);

            Assert.Equal(0, result.AppliedCount);
            Assert.Equal(1, result.OwnershipMismatchCount);
            Assert.Empty((await ReadMetadataAsync(root, own.StoredName)).ActiveReferences!);
        });
    }

    [Fact]
    public async Task Failed_authorization_batch_does_not_pin_valid_prefix()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var own = await CreateAssetAsync(store, root, Owner);
            var foreign = await CreateAssetAsync(store, root, Owner + 1);

            var unauthorized = await store.FindUnauthorizedUrlsAsync(
                [own.Url, foreign.Url], Owner, CancellationToken.None);

            Assert.Single(unauthorized);
            var metadata = await ReadMetadataAsync(root, own.StoredName);
            Assert.Null(metadata.ReservedAt);
            Assert.Null(metadata.ReservationExpiresAt);
        });
    }

    [Fact]
    public async Task Exact_authorization_default_reservation_covers_a_seven_day_outage()
    {
        var root = Path.Combine(Path.GetTempPath(), $"fakebook-upload-exact-lease-{Guid.NewGuid():N}");
        var options = Options.Create(new UploadStorageOptions
        {
            RootPath = root,
            StagedUploadsEnabled = true,
            AllowedMediaOrigins = ["https://fakebook.tech"]
        });
        try
        {
            var store = new UploadAssetStore(options);
            var asset = await CreateAssetAsync(store, root, Owner);
            var authorization = await store.AuthorizeReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, "socialgraph:media:seven-day-lease")],
                Owner,
                DateTimeOffset.UtcNow,
                CancellationToken.None);
            Assert.Empty(authorization.UnauthorizedUrls);

            var reservation = (await ReadMetadataAsync(root, asset.StoredName))
                .PendingReferences!["socialgraph:media:seven-day-lease"];
            Assert.Equal(TimeSpan.FromDays(7), reservation.ExpiresAt - reservation.ReservedAt);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Authorization_lease_prevents_two_store_cleanup_race_and_attach_claims_it()
    {
        await WithStoresAsync(async (first, second, root) =>
        {
            var asset = await CreateAssetAsync(first, root, Owner);
            Assert.Empty(await first.FindUnauthorizedUrlsAsync([asset.Url], Owner, CancellationToken.None));

            await Task.WhenAll(
                second.CleanupExpiredAsync(DateTimeOffset.UtcNow.AddDays(2), CancellationToken.None),
                first.AttachReferencesDetailedAsync(
                    [new UploadMediaReference(asset.Url, "social:media:race")],
                    Owner,
                    DateTimeOffset.UtcNow,
                    CancellationToken.None));

            await second.CleanupExpiredAsync(DateTimeOffset.UtcNow.AddDays(3), CancellationToken.None);
            Assert.True(File.Exists(asset.Path));
            Assert.Contains(
                "social:media:race",
                (await ReadMetadataAsync(root, asset.StoredName)).ActiveReferences!.Keys);
        });
    }

    [Fact]
    public async Task Expired_unclaimed_authorization_is_eventually_cleaned_in_two_phases()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            Assert.Empty(await store.FindUnauthorizedUrlsAsync([asset.Url], Owner, CancellationToken.None));

            var future = DateTimeOffset.UtcNow.AddDays(2);
            Assert.Equal(0, await store.CleanupExpiredAsync(future, CancellationToken.None));
            Assert.True(File.Exists(asset.Path));
            Assert.Equal(1, await store.CleanupExpiredAsync(future.AddMinutes(6), CancellationToken.None));
            Assert.False(File.Exists(asset.Path));
        });
    }

    [Fact]
    public async Task Corrupt_metadata_is_never_acknowledged_or_deleted()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            await File.WriteAllTextAsync(MetadataPath(root, asset.StoredName), "{broken");

            var finalize = await store.FinalizeDetailedAsync([asset.Url], Owner, CancellationToken.None);
            Assert.Equal(1, finalize.MetadataUnavailableCount);
            Assert.Equal(0, finalize.FinalizedCount);

            Assert.Equal(0, await store.CleanupExpiredAsync(DateTimeOffset.UtcNow.AddYears(1), CancellationToken.None));
            Assert.True(File.Exists(asset.Path));
        });
    }

    [Fact]
    public async Task Pre_v2_metadata_is_never_guessed_safe_for_cleanup()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            var metadata = await ReadMetadataAsync(root, asset.StoredName);
            await File.WriteAllTextAsync(
                MetadataPath(root, asset.StoredName),
                JsonSerializer.Serialize(metadata with
                {
                    LifecycleVersion = 1,
                    ActiveReferences = null,
                    ReleasedReferences = null,
                    LegacyPinned = false,
                    ExpiresAt = DateTimeOffset.UtcNow.AddDays(-30)
                }, JsonOptions));

            Assert.Equal(0, await store.CleanupExpiredAsync(
                DateTimeOffset.UtcNow.AddYears(1), CancellationToken.None));
            Assert.True(File.Exists(asset.Path));
        });
    }

    [Fact]
    public async Task Authorization_rejects_metadata_whose_physical_file_is_missing()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            File.Delete(asset.Path);

            var unauthorized = await store.FindUnauthorizedUrlsAsync(
                [asset.Url], Owner, CancellationToken.None);

            Assert.Single(unauthorized);
        });
    }

    [Fact]
    public async Task Absolute_media_url_must_match_configured_origin()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            var allowed = "https://fakebook.tech" + asset.Url;
            var attacker = "https://example.invalid" + asset.Url;

            Assert.Empty(await store.FindUnauthorizedUrlsAsync([allowed], Owner, CancellationToken.None));
            Assert.Contains(attacker, await store.FindUnauthorizedUrlsAsync([attacker], Owner, CancellationToken.None));
        });
    }

    [Fact]
    public async Task Exact_pending_reference_protects_reuse_even_while_an_old_parent_is_active()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            var now = DateTimeOffset.UtcNow;
            await AssertAttachedAsync(store, asset.Url, "socialgraph:media:old", now);

            var authorization = await store.AuthorizeReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, "socialgraph:media:new", asset.StoredName[..32])],
                Owner,
                now.AddSeconds(1),
                CancellationToken.None);
            Assert.Empty(authorization.UnauthorizedUrls);
            var reserved = await ReadMetadataAsync(root, asset.StoredName);
            Assert.Contains("socialgraph:media:old", reserved.ActiveReferences!.Keys);
            Assert.Contains("socialgraph:media:new", reserved.PendingReferences!.Keys);

            await store.DetachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, "socialgraph:media:old")],
                Owner,
                now.AddSeconds(2),
                CancellationToken.None);
            Assert.True(File.Exists(asset.Path));
            Assert.Contains(
                "socialgraph:media:new",
                (await ReadMetadataAsync(root, asset.StoredName)).PendingReferences!.Keys);

            await AssertAttachedAsync(store, asset.Url, "socialgraph:media:new", now.AddSeconds(1));
            var attached = await ReadMetadataAsync(root, asset.StoredName);
            Assert.Empty(attached.PendingReferences!);
            Assert.Contains("socialgraph:media:new", attached.ActiveReferences!.Keys);

            await store.DetachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, "socialgraph:media:new")],
                Owner,
                now.AddSeconds(3),
                CancellationToken.None);
            Assert.False(File.Exists(asset.Path));
            Assert.Equal(UploadAssetStore.DeletedState, (await ReadMetadataAsync(root, asset.StoredName)).State);
        }, referenceDeleteGraceMinutes: 0);
    }

    [Fact]
    public async Task Exact_attach_claims_browser_finalize_lease_so_final_detach_can_delete_promptly()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            var assetId = Path.GetFileNameWithoutExtension(asset.StoredName);
            Assert.Equal(1, await store.FinalizeOwnedAsync([assetId], Owner, CancellationToken.None));
            Assert.NotNull((await ReadMetadataAsync(root, asset.StoredName)).ReservedAt);

            var now = DateTimeOffset.UtcNow;
            await AssertAttachedAsync(store, asset.Url, "socialgraph:media:browser", now);
            var attached = await ReadMetadataAsync(root, asset.StoredName);
            Assert.Null(attached.ReservedAt);
            Assert.Null(attached.ReservationKind);

            await store.DetachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, "socialgraph:media:browser")],
                Owner,
                now.AddSeconds(1),
                CancellationToken.None);
            Assert.False(File.Exists(asset.Path));
            Assert.Equal(UploadAssetStore.DeletedState, (await ReadMetadataAsync(root, asset.StoredName)).State);
        }, referenceDeleteGraceMinutes: 0);
    }

    [Fact]
    public async Task Older_attach_cannot_clear_a_newer_browser_finalize_lease()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            var assetId = Path.GetFileNameWithoutExtension(asset.StoredName);
            Assert.Equal(1, await store.FinalizeOwnedAsync([assetId], Owner, CancellationToken.None));
            var reserved = await ReadMetadataAsync(root, asset.StoredName);

            await AssertAttachedAsync(
                store,
                asset.Url,
                "socialgraph:media:older-attach",
                reserved.ReservedAt!.Value.AddSeconds(-1));

            var metadata = await ReadMetadataAsync(root, asset.StoredName);
            Assert.Equal(reserved.ReservedAt, metadata.ReservedAt);
            Assert.Equal("browser", metadata.ReservationKind);
            await store.DetachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, "socialgraph:media:older-attach")],
                Owner,
                reserved.ReservedAt!.Value.AddMilliseconds(-500),
                CancellationToken.None);
            Assert.True(File.Exists(asset.Path));
        }, referenceDeleteGraceMinutes: 0);
    }

    [Fact]
    public async Task Browser_finalize_does_not_overwrite_an_active_legacy_url_reservation()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            Assert.Empty(await store.FindUnauthorizedUrlsAsync(
                [asset.Url],
                Owner,
                CancellationToken.None));
            var legacy = await ReadMetadataAsync(root, asset.StoredName);
            Assert.Equal("legacy-url", legacy.ReservationKind);

            var assetId = Path.GetFileNameWithoutExtension(asset.StoredName);
            Assert.Equal(1, await store.FinalizeOwnedAsync([assetId], Owner, CancellationToken.None));

            var finalized = await ReadMetadataAsync(root, asset.StoredName);
            Assert.Equal("legacy-url", finalized.ReservationKind);
            Assert.Equal(legacy.ReservedAt, finalized.ReservedAt);
            Assert.Equal(legacy.ReservationExpiresAt, finalized.ReservationExpiresAt);
        });
    }

    [Fact]
    public async Task Attach_clears_only_the_matching_pending_reference()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            var now = DateTimeOffset.UtcNow;
            var authorization = await store.AuthorizeReferencesDetailedAsync(
                [
                    new UploadMediaReference(asset.Url, "socialgraph:media:one"),
                    new UploadMediaReference(asset.Url, "socialgraph:media:two")
                ],
                Owner,
                now,
                CancellationToken.None);
            Assert.Empty(authorization.UnauthorizedUrls);

            await AssertAttachedAsync(store, asset.Url, "socialgraph:media:one", now);

            var metadata = await ReadMetadataAsync(root, asset.StoredName);
            Assert.DoesNotContain("socialgraph:media:one", metadata.PendingReferences!.Keys);
            Assert.Contains("socialgraph:media:two", metadata.PendingReferences.Keys);
        });
    }

    [Fact]
    public async Task Cleanup_service_retries_a_lingering_tombstoned_file_immediately_on_start()
    {
        var root = Path.Combine(Path.GetTempPath(), $"fakebook-upload-startup-cleanup-{Guid.NewGuid():N}");
        var options = Options.Create(new UploadStorageOptions
        {
            RootPath = root,
            StagedUploadsEnabled = false,
            CleanupEnabled = true,
            CleanupIntervalMinutes = 1_440,
            PendingLifetimeMinutes = 5,
            PendingCleanupGraceMinutes = 5,
            ReferenceDeleteGraceMinutes = 0,
            AuthorizationReservationMinutes = 5,
            BrowserReservationMinutes = 5,
            DeletedTombstoneRetentionMinutes = 60,
            QuarantineRetentionMinutes = 30,
            LifecycleLockTimeoutSeconds = 5,
            AllowedMediaOrigins = ["https://fakebook.tech"]
        });
        try
        {
            var store = new UploadAssetStore(options);
            var asset = await CreateAssetAsync(store, root, Owner);
            var now = DateTimeOffset.UtcNow;
            await AssertAttachedAsync(store, asset.Url, "socialgraph:media:startup-cleanup", now);
            await store.DetachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, "socialgraph:media:startup-cleanup")],
                Owner,
                now.AddSeconds(1),
                CancellationToken.None);
            Assert.False(File.Exists(asset.Path));

            // Simulate a process/remote-share failure after the durable tombstone was
            // written but before the physical bytes remained deleted.
            await File.WriteAllBytesAsync(asset.Path, [1, 2, 3, 4]);
            using var service = new UploadAssetCleanupService(
                store,
                options,
                NullLogger<UploadAssetCleanupService>.Instance);
            await service.StartAsync(CancellationToken.None);

            var deadline = DateTimeOffset.UtcNow.AddSeconds(3);
            while (File.Exists(asset.Path) && DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(25);
            }
            await service.StopAsync(CancellationToken.None);

            Assert.False(File.Exists(asset.Path));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Stale_authorize_after_exact_detach_is_rejected_without_cancelling_deletion()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            var now = DateTimeOffset.UtcNow;
            const string referenceId = "socialgraph:media:retired";
            await AssertAttachedAsync(store, asset.Url, referenceId, now);
            await store.DetachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, referenceId)],
                Owner,
                now.AddSeconds(2),
                CancellationToken.None);
            var scheduled = await ReadMetadataAsync(root, asset.StoredName);
            Assert.NotNull(scheduled.DeleteAfter);

            var authorization = await store.AuthorizeReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, referenceId)],
                Owner,
                now.AddSeconds(1),
                CancellationToken.None);

            Assert.Contains(asset.Url, authorization.UnauthorizedUrls);
            var unchanged = await ReadMetadataAsync(root, asset.StoredName);
            Assert.Empty(unchanged.PendingReferences!);
            Assert.Equal(scheduled.DeleteAfter, unchanged.DeleteAfter);
        });
    }

    [Fact]
    public async Task Reference_lifecycle_requires_operation_time_and_rejects_future_skew()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            var reference = new UploadMediaReference(asset.Url, "socialgraph:media:clock");

            var missing = await store.AttachReferencesDetailedAsync(
                [reference], Owner, null, CancellationToken.None);
            var future = await store.AttachReferencesDetailedAsync(
                [reference], Owner, DateTimeOffset.UtcNow.AddMinutes(6), CancellationToken.None);

            Assert.Equal(1, missing.InvalidOperationTimeCount);
            Assert.Equal(1, future.InvalidOperationTimeCount);
            Assert.Empty((await ReadMetadataAsync(root, asset.StoredName)).ActiveReferences!);
        });
    }

    [Fact]
    public async Task Legacy_wildcard_watermark_is_never_used_to_retire_an_unrelated_reference()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            var metadata = await ReadMetadataAsync(root, asset.StoredName);
            var now = DateTimeOffset.UtcNow;
            await File.WriteAllTextAsync(
                MetadataPath(root, asset.StoredName),
                JsonSerializer.Serialize(metadata with
                {
                    LifecycleVersion = 2,
                    ReleasedReferenceWatermark = now
                }, JsonOptions));

            var result = await store.AttachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, "socialgraph:media:not-in-watermark")],
                Owner,
                now.AddSeconds(-1),
                CancellationToken.None);

            Assert.Equal(1, result.AppliedCount);
            Assert.Equal(0, result.StaleCount);
            var upgraded = await ReadMetadataAsync(root, asset.StoredName);
            Assert.Contains("socialgraph:media:not-in-watermark", upgraded.ActiveReferences!.Keys);
            Assert.True(upgraded.LegacyPinned);
            Assert.Null(upgraded.ReleasedReferenceWatermark);
        });
    }

    [Fact]
    public async Task Tombstone_precedes_physical_delete_and_cleanup_retries_lingering_bytes()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            var now = DateTimeOffset.UtcNow;
            await AssertAttachedAsync(store, asset.Url, "socialgraph:media:delete", now);
            await store.DetachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, "socialgraph:media:delete")],
                Owner,
                now.AddSeconds(1),
                CancellationToken.None);

            var tombstone = await ReadMetadataAsync(root, asset.StoredName);
            Assert.Equal(UploadAssetStore.DeletedState, tombstone.State);
            Assert.Equal(0, tombstone.OwnerUserId);
            Assert.Equal(string.Empty, tombstone.OriginalName);
            Assert.Equal(0, tombstone.Size);
            Assert.Empty(tombstone.ActiveReferences!);
            Assert.Empty(tombstone.ReleasedReferences!);
            Assert.Empty(tombstone.PendingReferences!);
            Assert.Null(tombstone.CompactedReleaseFloor);

            // Existing deployments may already have tombstones containing parent IDs.
            // The next cleanup pass must migrate them to the data-minimized form.
            await File.WriteAllTextAsync(
                MetadataPath(root, asset.StoredName),
                JsonSerializer.Serialize(tombstone with
                {
                    ReleasedReferences = new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal)
                    {
                        ["messenger:conversation:sensitive:message:42"] = now
                    },
                    CompactedReleaseFloor = now
                }, JsonOptions));

            // Simulate a crash/SMB failure after the durable tombstone but before the
            // physical unlink. Serving and authorization must still fail immediately.
            await File.WriteAllBytesAsync(asset.Path, [9, 9, 9]);
            Assert.False(await store.CanServeAsync(asset.StoredName, CancellationToken.None));
            Assert.Contains(asset.Url, await store.FindUnauthorizedUrlsAsync(
                [asset.Url], Owner, CancellationToken.None));

            await store.CleanupExpiredAsync(now.AddMinutes(1), CancellationToken.None);
            Assert.False(File.Exists(asset.Path));
            var scrubbedTombstone = await ReadMetadataAsync(root, asset.StoredName);
            Assert.Empty(scrubbedTombstone.ReleasedReferences!);
            Assert.Null(scrubbedTombstone.CompactedReleaseFloor);

            // A replayed detach must acknowledge the already durable tombstone. Otherwise
            // callers would retry the same outbox row forever after a successful deletion.
            var replay = await store.DetachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, "socialgraph:media:delete")],
                Owner,
                now.AddSeconds(2),
                CancellationToken.None);
            Assert.Equal(1, replay.RequestedCount);
            Assert.Equal(1, replay.NormalizedCount);
            Assert.Equal(1, replay.AppliedCount);
            Assert.Equal(0, replay.MetadataUnavailableCount);
        }, referenceDeleteGraceMinutes: 0);
    }

    [Fact]
    public async Task Pending_expiry_keeps_a_minimal_tombstone_and_late_detach_is_idempotent()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            var future = DateTimeOffset.UtcNow.AddDays(2);

            Assert.Equal(0, await store.CleanupExpiredAsync(future, CancellationToken.None));
            Assert.Equal(1, await store.CleanupExpiredAsync(future.AddMinutes(6), CancellationToken.None));
            var tombstone = await ReadMetadataAsync(root, asset.StoredName);
            Assert.Equal(UploadAssetStore.DeletedState, tombstone.State);
            Assert.Equal(0, tombstone.OwnerUserId);
            Assert.True(File.Exists(MetadataPath(root, asset.StoredName)));

            await store.CleanupExpiredAsync(future.AddMinutes(67), CancellationToken.None);
            Assert.False(File.Exists(MetadataPath(root, asset.StoredName)));
            var detach = await store.DetachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, "socialgraph:media:late")],
                Owner,
                DateTimeOffset.UtcNow,
                CancellationToken.None);
            Assert.Equal(1, detach.AppliedCount);
            Assert.Equal(1, detach.MissingFileCount);
        });
    }

    [Fact]
    public async Task Expected_asset_id_mismatch_rejects_the_reference_before_mutation()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            var result = await store.AttachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, "socialgraph:media:mismatch", Guid.NewGuid().ToString("N"))],
                Owner,
                DateTimeOffset.UtcNow,
                CancellationToken.None);

            Assert.Equal(1, result.RequestedCount);
            Assert.Equal(0, result.NormalizedCount);
            Assert.Empty((await ReadMetadataAsync(root, asset.StoredName)).ActiveReferences!);
        });
    }

    [Fact]
    public async Task Cleanup_removes_only_old_unlocked_quarantine_files()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            await AssertAttachedAsync(store, asset.Url, "socialgraph:media:keep", DateTimeOffset.UtcNow);
            var quarantine = Path.Combine(root, ".quarantine");
            Directory.CreateDirectory(quarantine);
            var old = Path.Combine(quarantine, "old.source");
            var fresh = Path.Combine(quarantine, "fresh.source");
            await File.WriteAllBytesAsync(old, [1]);
            await File.WriteAllBytesAsync(fresh, [2]);
            File.SetLastWriteTimeUtc(old, DateTime.UtcNow.AddHours(-2));

            await store.CleanupExpiredAsync(DateTimeOffset.UtcNow, CancellationToken.None);

            Assert.False(File.Exists(old));
            Assert.True(File.Exists(fresh));
        }, quarantineRetentionMinutes: 30);
    }

    [Fact]
    public async Task Released_reference_churn_compacts_and_final_detach_still_tombstones()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            var now = DateTimeOffset.UtcNow;
            const string guardReference = "socialgraph:media:live-guard";
            await AssertAttachedAsync(store, asset.Url, guardReference, now.AddMinutes(-1));

            var metadata = await ReadMetadataAsync(root, asset.StoredName);
            var releaseBase = now.AddHours(-2);
            var released = Enumerable.Range(0, 4_096).ToDictionary(
                index => $"socialgraph:media:released-{index}",
                index => releaseBase.AddMilliseconds(index),
                StringComparer.Ordinal);
            await File.WriteAllTextAsync(
                MetadataPath(root, asset.StoredName),
                JsonSerializer.Serialize(metadata with { ReleasedReferences = released }, JsonOptions));

            var churn = Enumerable.Range(0, 512)
                .Select(index => new UploadMediaReference(
                    asset.Url,
                    $"socialgraph:media:churn-{index}"))
                .ToArray();
            var churnResult = await store.DetachReferencesDetailedAsync(
                churn,
                Owner,
                now.AddSeconds(-1),
                CancellationToken.None);
            Assert.Equal(512, churnResult.AppliedCount);
            Assert.Equal(0, churnResult.CapacityExceededCount);
            Assert.True(File.Exists(asset.Path));

            var compacted = await ReadMetadataAsync(root, asset.StoredName);
            Assert.NotNull(compacted.CompactedReleaseFloor);
            Assert.InRange(compacted.ReleasedReferences!.Count, 1, 4_096);
            Assert.Null(compacted.ReleasedReferenceWatermark);

            var finalDetach = await store.DetachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, guardReference)],
                Owner,
                now,
                CancellationToken.None);
            Assert.Equal(1, finalDetach.AppliedCount);
            Assert.Equal(0, finalDetach.CapacityExceededCount);
            Assert.False(File.Exists(asset.Path));

            var tombstone = await ReadMetadataAsync(root, asset.StoredName);
            Assert.Equal(UploadAssetStore.DeletedState, tombstone.State);
            Assert.Null(tombstone.CompactedReleaseFloor);
            Assert.Empty(tombstone.ReleasedReferences!);

            var replay = await store.DetachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, guardReference)],
                Owner,
                now,
                CancellationToken.None);
            Assert.Equal(1, replay.AppliedCount);
            Assert.Equal(1, replay.StaleCount);
        }, referenceDeleteGraceMinutes: 0);
    }

    [Fact]
    public async Task Compacted_release_floor_rejects_unreserved_stale_authorize_and_attach()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            var floor = DateTimeOffset.UtcNow.AddSeconds(-1);
            var metadata = await ReadMetadataAsync(root, asset.StoredName);
            await File.WriteAllTextAsync(
                MetadataPath(root, asset.StoredName),
                JsonSerializer.Serialize(metadata with { CompactedReleaseFloor = floor }, JsonOptions));

            const string referenceId = "socialgraph:media:below-floor";
            var operationAt = floor.AddSeconds(-1);
            var authorization = await store.AuthorizeReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, referenceId)],
                Owner,
                operationAt,
                CancellationToken.None);
            Assert.Contains(asset.Url, authorization.UnauthorizedUrls);

            var attach = await store.AttachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, referenceId)],
                Owner,
                operationAt,
                CancellationToken.None);
            Assert.Equal(1, attach.AppliedCount);
            Assert.Equal(1, attach.StaleCount);
            Assert.Empty((await ReadMetadataAsync(root, asset.StoredName)).ActiveReferences!);
        });
    }

    [Fact]
    public async Task Exact_pending_reservation_can_attach_after_compaction_floor_advances_past_it()
    {
        await WithStoresAsync(async (store, _, root) =>
        {
            var asset = await CreateAssetAsync(store, root, Owner);
            var operationAt = DateTimeOffset.UtcNow.AddMinutes(-1);
            const string referenceId = "socialgraph:media:reserved-before-floor";
            var authorization = await store.AuthorizeReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, referenceId)],
                Owner,
                operationAt,
                CancellationToken.None);
            Assert.Empty(authorization.UnauthorizedUrls);

            var metadata = await ReadMetadataAsync(root, asset.StoredName);
            await File.WriteAllTextAsync(
                MetadataPath(root, asset.StoredName),
                JsonSerializer.Serialize(
                    metadata with { CompactedReleaseFloor = operationAt.AddSeconds(30) },
                    JsonOptions));

            var authorizationRetry = await store.AuthorizeReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, referenceId)],
                Owner,
                operationAt,
                CancellationToken.None);
            Assert.Empty(authorizationRetry.UnauthorizedUrls);

            var attach = await store.AttachReferencesDetailedAsync(
                [new UploadMediaReference(asset.Url, referenceId)],
                Owner,
                operationAt,
                CancellationToken.None);
            Assert.Equal(1, attach.AppliedCount);
            Assert.Equal(0, attach.StaleCount);
            var attached = await ReadMetadataAsync(root, asset.StoredName);
            Assert.Contains(referenceId, attached.ActiveReferences!.Keys);
            Assert.DoesNotContain(referenceId, attached.PendingReferences!.Keys);
        });
    }

    private static async Task AssertAttachedAsync(
        UploadAssetStore store,
        string url,
        string referenceId,
        DateTimeOffset at)
    {
        var result = await store.AttachReferencesDetailedAsync(
            [new UploadMediaReference(url, referenceId)], Owner, at, CancellationToken.None);
        Assert.Equal(1, result.AppliedCount);
        Assert.Equal(0, result.MissingFileCount);
        Assert.Equal(0, result.MetadataUnavailableCount);
    }

    private static async Task<TestAsset> CreateAssetAsync(
        UploadAssetStore store,
        string root,
        long owner)
    {
        var storedName = $"{Guid.NewGuid():N}.png";
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, storedName);
        await store.RegisterAsync(storedName, owner, "photo.png", "image/png", 4, CancellationToken.None);
        await File.WriteAllBytesAsync(path, [1, 2, 3, 4]);
        return new TestAsset(storedName, $"/media/files/{storedName}", path);
    }

    private static async Task<UploadAssetMetadata> ReadMetadataAsync(string root, string storedName) =>
        JsonSerializer.Deserialize<UploadAssetMetadata>(
            await File.ReadAllTextAsync(MetadataPath(root, storedName)),
            JsonOptions)!;

    private static string MetadataPath(string root, string storedName) =>
        Path.Combine(root, ".metadata", Path.GetFileNameWithoutExtension(storedName) + ".json");

    private static async Task WithStoresAsync(
        Func<UploadAssetStore, UploadAssetStore, string, Task> body,
        int referenceDeleteGraceMinutes = 5,
        int quarantineRetentionMinutes = 30)
    {
        var root = Path.Combine(Path.GetTempPath(), $"fakebook-upload-v2-{Guid.NewGuid():N}");
        var options = Options.Create(new UploadStorageOptions
        {
            RootPath = root,
            StagedUploadsEnabled = true,
            PendingLifetimeMinutes = 5,
            PendingCleanupGraceMinutes = 5,
            ReferenceDeleteGraceMinutes = referenceDeleteGraceMinutes,
            AuthorizationReservationMinutes = 5,
            BrowserReservationMinutes = 5,
            DeletedTombstoneRetentionMinutes = 60,
            QuarantineRetentionMinutes = quarantineRetentionMinutes,
            LifecycleLockTimeoutSeconds = 5,
            AllowedMediaOrigins = ["https://fakebook.tech"]
        });
        try
        {
            await body(new UploadAssetStore(options), new UploadAssetStore(options), root);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private sealed record TestAsset(string StoredName, string Url, string Path);
}
