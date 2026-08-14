using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// The <c>local_only</c> claim purge drops every cached proxy version of a name across both
/// catalogues and deletes the blobs those rows dereferenced. On the legacy uploaded plane —
/// <c>package_versions</c> rows carrying <c>origin = 'proxy'</c>, written before proxy fetches
/// moved to the cache plane — the blob key is the content-addressed <c>proxy/{sha256}</c>, which
/// has no org segment: every tenant whose upstream served byte-identical content records the
/// identical key. Deleting it on one org's claim transition therefore reaches bytes another
/// tenant's <c>cache_artifact</c> / <c>tenant_artifact_access</c> rows still point at, turning
/// that tenant's cached artifact into a serve-time 404 it never asked for.
///
/// These tests pin the refcount guard that closes it — and its adversarial twin, that a key
/// nobody else references is still reclaimed, so the guard is not a blanket "stop deleting".
/// </summary>
[Trait("Category", "Unit")]
public sealed class ClaimsPurgeSharedBlobTests
{
    private const string SharedSha = "1111111111111111111111111111111111111111111111111111111111111111";
    private const string SoloSha = "2222222222222222222222222222222222222222222222222222222222222222";

    private static async Task SeedLegacyProxyVersionAsync(
        ControllerScenarioResult b, string packageId, string version, string blobKey)
    {
        await PackageSeeder.InsertVersionAsync(
            b.Db, packageId, version, $"pkg:npm/{Guid.NewGuid():N}/leftpad@{version}",
            origin: "proxy", blobKey: blobKey);
    }

    // A cache-plane row in ANOTHER org that names the same content-addressed key — exactly what a
    // second tenant proxying the same artifact from its own upstream records.
    private static async Task SeedForeignCacheReferenceAsync(
        ControllerScenarioResult b, string foreignOrgId, string blobKey, string sha)
    {
        await using var conn = await b.Db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes,
                 first_cached_at, last_accessed_at)
            VALUES (@id, 'npm', 'leftpad', '1.0.0', 'leftpad-1.0.0.tgz', @blobKey, @sha, 128,
                    '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')
            """,
            new { id = "ca-shared", blobKey, sha });
        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_artifact_access
                (org_id, cache_artifact_id, first_accessed_at, last_accessed_at, access_count)
            VALUES (@orgId, 'ca-shared', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 1)
            """,
            new { orgId = foreignOrgId });
    }

    [Fact]
    public async Task LocalOnlyPurge_Mixed_SharedProxyBlobRetained_UnreferencedProxyBlobDeleted()
    {
        // Mixed partial-failure in one purge: two legacy proxy rows go away together, but only the
        // blob nobody else references may be deleted. One delete proceeds, one is refused, in the
        // same call — proving the guard keys on live references rather than suppressing deletes.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        await s.WithOrgAsync("victim");
        var b = await s.BuildAsync();

        string victimOrgId;
        await using (var lookup = await b.Db.OpenAsync())
        {
            victimOrgId = await lookup.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'victim'")
                ?? throw new InvalidOperationException("victim org not seeded");
        }

        string sharedKey = BlobKeys.Proxy(SharedSha);
        string soloKey = BlobKeys.Proxy(SoloSha);

        string packageId = await PackageSeeder.InsertAsync(b.Db, b.PrimaryOrgId, "npm", "leftpad", isProxy: true);
        await SeedLegacyProxyVersionAsync(b, packageId, "1.0.0", sharedKey);
        await SeedLegacyProxyVersionAsync(b, packageId, "2.0.0", soloKey);
        await SeedForeignCacheReferenceAsync(b, victimOrgId, sharedKey, SharedSha);

        await b.Blobs.PutAsync(sharedKey, new MemoryStream([1, 2, 3]), default);
        await b.Blobs.PutAsync(soloKey, new MemoryStream([4, 5, 6]), default);

        var result = await b.ClaimsController.Create(
            new CreateClaimRequest("npm", "leftpad", "local_only", "confusion defence"),
            CancellationToken.None);
        Assert.IsType<CreatedResult>(result);

        // Both legacy rows are purged — the claim transition is unaffected by the guard.
        await using var conn = await b.Db.OpenAsync();
        long remaining = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE package_id = @packageId", new { packageId });
        Assert.Equal(0, remaining);

        // The shared key still backs the victim org's cache row, so its bytes survive.
        Assert.True(await b.Blobs.ExistsAsync(sharedKey, default));

        // The key nothing else references is reclaimed, exactly as before the guard.
        Assert.False(await b.Blobs.ExistsAsync(soloKey, default));
    }

    [Fact]
    public async Task LocalOnlyPurge_OrgNamespacedBlob_StillDeletedUnconditionally()
    {
        // A hosted/{orgId}/… key belongs to this org alone — no other tenant can reference it, so
        // the guard must not make its reclamation conditional on a cache-plane row that will never
        // exist for it.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        string hostedKey = BlobKeys.Hosted(b.PrimaryOrgId, "npm", "leftpad", "3.0.0", "leftpad-3.0.0.tgz");

        string packageId = await PackageSeeder.InsertAsync(b.Db, b.PrimaryOrgId, "npm", "leftpad", isProxy: true);
        await SeedLegacyProxyVersionAsync(b, packageId, "3.0.0", hostedKey);
        await b.Blobs.PutAsync(hostedKey, new MemoryStream([7, 8, 9]), default);

        var result = await b.ClaimsController.Create(
            new CreateClaimRequest("npm", "leftpad", "local_only", "confusion defence"),
            CancellationToken.None);
        Assert.IsType<CreatedResult>(result);

        Assert.False(await b.Blobs.ExistsAsync(hostedKey, default));
    }
}
