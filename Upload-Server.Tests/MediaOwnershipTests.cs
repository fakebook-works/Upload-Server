using Microsoft.Extensions.Options;
using Xunit;

/// <summary>
/// Regression coverage for owner-scoped media lifecycle operations.
/// Before this was enforced, any authenticated user could permanently destroy another user's
/// media by storing its URL on their own profile and then replacing it, because the internal
/// delete endpoint removed files by URL without consulting the recorded owner.
/// </summary>
public sealed class MediaOwnershipTests
{
    private const long Owner = 42;
    private const long Attacker = 99;

    [Fact]
    public async Task Delete_refuses_an_asset_owned_by_another_user()
    {
        await WithStoreAsync(async (store, root) =>
        {
            var (url, path) = await CreateAssetAsync(store, root, Owner);

            var deleted = await store.DeleteByUrlsAsync([url], Attacker, CancellationToken.None);

            Assert.Equal(0, deleted);
            Assert.True(File.Exists(path), "Another user's media must survive an owner-scoped delete.");
        });
    }

    [Fact]
    public async Task Delete_removes_an_asset_owned_by_the_declared_user()
    {
        await WithStoreAsync(async (store, root) =>
        {
            var (url, path) = await CreateAssetAsync(store, root, Owner);

            var deleted = await store.DeleteByUrlsAsync([url], Owner, CancellationToken.None);

            Assert.Equal(1, deleted);
            Assert.False(File.Exists(path));
        });
    }

    [Fact]
    public async Task Delete_without_a_declared_owner_still_performs_cascade_cleanup()
    {
        await WithStoreAsync(async (store, root) =>
        {
            var (url, path) = await CreateAssetAsync(store, root, Owner);

            var deleted = await store.DeleteByUrlsAsync([url], null, CancellationToken.None);

            Assert.Equal(1, deleted);
            Assert.False(File.Exists(path));
        });
    }

    [Fact]
    public async Task Delete_fails_closed_when_ownership_cannot_be_established()
    {
        await WithStoreAsync(async (store, root) =>
        {
            // A legacy file with no lifecycle metadata: ownership is unknown, so an
            // owner-scoped delete must refuse rather than assume the caller is entitled.
            var storedName = $"{Guid.NewGuid():N}.png";
            var path = Path.Combine(root, storedName);
            Directory.CreateDirectory(root);
            await File.WriteAllTextAsync(path, "legacy");

            var deleted = await store.DeleteByUrlsAsync(
                [$"/media/files/{storedName}"],
                Owner,
                CancellationToken.None);

            Assert.Equal(0, deleted);
            Assert.True(File.Exists(path));
        });
    }

    [Fact]
    public async Task Finalize_refuses_to_commit_another_users_pending_asset()
    {
        await WithStoreAsync(async (store, root) =>
        {
            var (url, _) = await CreateAssetAsync(store, root, Owner);

            var finalized = await store.FinalizeAsync([url], Attacker, CancellationToken.None);

            Assert.Equal(0, finalized);
        });
    }

    [Fact]
    public async Task Finalize_detailed_reports_missing_storage_without_acknowledging_it()
    {
        await WithStoreAsync(async (store, root) =>
        {
            var (url, path) = await CreateAssetAsync(store, root, Owner);
            File.Delete(path);

            var result = await store.FinalizeDetailedAsync([url], Owner, CancellationToken.None);

            Assert.Equal(1, result.RequestedCount);
            Assert.Equal(1, result.NormalizedCount);
            Assert.Equal(0, result.FinalizedCount);
            Assert.Equal(1, result.MissingFileCount);
            Assert.Equal(0, result.OwnershipMismatchCount);
        });
    }

    [Fact]
    public async Task Finalize_detailed_reports_owner_mismatch_without_committing()
    {
        await WithStoreAsync(async (store, root) =>
        {
            var (url, _) = await CreateAssetAsync(store, root, Owner);

            var result = await store.FinalizeDetailedAsync([url], Attacker, CancellationToken.None);

            Assert.Equal(0, result.FinalizedCount);
            Assert.Equal(1, result.OwnershipMismatchCount);
            Assert.Equal(0, result.MissingFileCount);
        });
    }

    [Fact]
    public async Task FindUnauthorizedUrls_reports_foreign_unknown_and_off_server_urls()
    {
        await WithStoreAsync(async (store, root) =>
        {
            var (ownUrl, _) = await CreateAssetAsync(store, root, Owner);
            var (foreignUrl, _) = await CreateAssetAsync(store, root, Attacker);
            var unknownUrl = $"/media/files/{Guid.NewGuid():N}.png";
            const string offServerUrl = "https://example.invalid/photo.png";

            var unauthorized = await store.FindUnauthorizedUrlsAsync(
                [ownUrl, foreignUrl, unknownUrl, offServerUrl],
                Owner,
                CancellationToken.None);

            Assert.DoesNotContain(ownUrl, unauthorized);
            Assert.Contains(foreignUrl, unauthorized);
            Assert.Contains(unknownUrl, unauthorized);
            Assert.Contains(offServerUrl, unauthorized);
        });
    }

    [Fact]
    public async Task FindUnauthorizedUrls_accepts_an_empty_request()
    {
        await WithStoreAsync(async (store, _) =>
        {
            var unauthorized = await store.FindUnauthorizedUrlsAsync([], Owner, CancellationToken.None);

            Assert.Empty(unauthorized);
        });
    }

    private static async Task<(string Url, string Path)> CreateAssetAsync(
        UploadAssetStore store,
        string root,
        long ownerUserId)
    {
        var storedName = $"{Guid.NewGuid():N}.png";
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, storedName);
        await File.WriteAllTextAsync(path, "asset");
        await store.RegisterAsync(storedName, ownerUserId, "photo.png", "image/png", 5, CancellationToken.None);
        return ($"/media/files/{storedName}", path);
    }

    private static async Task WithStoreAsync(Func<UploadAssetStore, string, Task> body)
    {
        var root = Path.Combine(Path.GetTempPath(), $"fakebook-upload-{Guid.NewGuid():N}");
        try
        {
            var store = new UploadAssetStore(Options.Create(new UploadStorageOptions
            {
                RootPath = root,
                StagedUploadsEnabled = true,
                PendingLifetimeMinutes = 60
            }));
            await body(store, root);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}
