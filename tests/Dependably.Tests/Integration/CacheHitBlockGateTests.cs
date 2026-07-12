using System.Net;
using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Cache-hit block-gate coverage for the ecosystems whose proxy serve paths previously served
/// cached bytes without ever evaluating <see cref="Dependably.Protocol.BlockGateService"/>:
/// cargo, golang, rpm, and apk. Each case seeds a cached proxy artifact on the global plane
/// (<c>cache_artifact</c> + <c>tenant_artifact_access</c>), manually blocks one coordinate via
/// <c>tenant_artifact_access.manual_block_state</c>, and asserts the blocked coordinate now
/// returns 403 while a clean sibling still serves 200 in the same fixture.
///
/// Fail-before/pass-after: on the old code these serve paths had no gate call, so a manually
/// blocked (or OSV-flagged) cached artifact served 200 forever after its first fetch. The
/// mixed/partial-failure shape (one blocked, one served) is the primary case per house style.
/// </summary>
[Trait("Category", "Integration")]
public sealed class CacheHitBlockGateTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public CacheHitBlockGateTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Cargo_CacheHit_BlockedCoordinate403_CleanCoordinate200()
    {
        await SetAnonymousPullAsync(true);
        try
        {
            string orgId = await DefaultOrgIdAsync();
            string name = $"blkcrate{Guid.NewGuid():N}"[..15].ToLowerInvariant();

            // Blocked 1.0.0 and clean 2.0.0 — cargo serves from BlobKeys.Cargo on a cache hit.
            await SeedCargoCachedAsync(orgId, name, "1.0.0", blocked: true);
            await SeedCargoCachedAsync(orgId, name, "2.0.0", blocked: false);

            using var client = _factory.CreateClient();

            var blocked = await client.GetAsync($"/cargo/api/v1/crates/{name}/1.0.0/download");
            Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);

            var ok = await client.GetAsync($"/cargo/api/v1/crates/{name}/2.0.0/download");
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    [Fact]
    public async Task Go_CacheHit_BlockedZip403_CleanZip200()
    {
        await SetAnonymousPullAsync(true);
        try
        {
            string orgId = await DefaultOrgIdAsync();
            string module = $"example.com/blk{Guid.NewGuid():N}"[..24].ToLowerInvariant();

            await SeedGoZipCachedAsync(orgId, module, "v1.0.0", blocked: true);
            await SeedGoZipCachedAsync(orgId, module, "v2.0.0", blocked: false);

            using var client = _factory.CreateClient();

            var blocked = await client.GetAsync($"/go/{module}/@v/v1.0.0.zip");
            Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);

            var ok = await client.GetAsync($"/go/{module}/@v/v2.0.0.zip");
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    [Fact]
    public async Task Rpm_GlobalPlaneCacheHit_BlockedNevra403_CleanNevra200()
    {
        await SetAnonymousPullAsync(true);
        try
        {
            string orgId = await DefaultOrgIdAsync();
            string name = $"blkrpm{Guid.NewGuid():N}"[..12].ToLowerInvariant();

            string blockedFile = $"{name}-1.0-1.x86_64.rpm";
            string cleanFile = $"{name}-2.0-1.x86_64.rpm";
            await SeedRpmCachedAsync(orgId, name, "1.0-1", blockedFile, blocked: true);
            await SeedRpmCachedAsync(orgId, name, "2.0-1", cleanFile, blocked: false);

            using var client = _factory.CreateClient();

            var blocked = await client.GetAsync($"/rpm/packages/{blockedFile}");
            Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);

            var ok = await client.GetAsync($"/rpm/packages/{cleanFile}");
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    [Fact]
    public async Task Apk_GlobalPlaneCacheHit_BlockedPackage403_CleanPackage200()
    {
        await SetAnonymousPullAsync(true);
        try
        {
            string orgId = await DefaultOrgIdAsync();
            string name = $"blkapk{Guid.NewGuid():N}"[..12].ToLowerInvariant();
            const string release = "v3.22";
            const string repo = "main";
            const string arch = "x86_64";

            string blockedFile = $"{name}-1.0-r0.apk";
            string cleanFile = $"{name}-2.0-r0.apk";
            await SeedApkCachedAsync(orgId, release, repo, arch, name, "1.0-r0", blockedFile, blocked: true);
            await SeedApkCachedAsync(orgId, release, repo, arch, name, "2.0-r0", cleanFile, blocked: false);

            using var client = _factory.CreateClient();

            var blocked = await client.GetAsync($"/apk/{release}/{repo}/{arch}/{blockedFile}");
            Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);

            var ok = await client.GetAsync($"/apk/{release}/{repo}/{arch}/{cleanFile}");
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }
        finally
        {
            await SetAnonymousPullAsync(false);
        }
    }

    // ── seeding helpers ───────────────────────────────────────────────────────

    private async Task SeedCargoCachedAsync(string orgId, string name, string version, bool blocked)
    {
        // cargo serves the cache hit from BlobKeys.Cargo; StoreKey is identity for that key.
        string blobKey = BlobKeys.Cargo(orgId, name, version);
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes($"crate-{name}-{version}");
        await _factory.BlobStore.PutAsync(BlobKeys.StoreKey(blobKey), new MemoryStream(bytes));
        await InsertGlobalPlaneAsync(orgId, "cargo", name, version, $"{name}-{version}.crate", blobKey, bytes, blocked);
    }

    private async Task SeedGoZipCachedAsync(string orgId, string module, string version, bool blocked)
    {
        // Go serves the .zip cache hit directly from BlobKeys.Go.
        string blobKey = BlobKeys.Go(orgId, module, version, "zip");
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes($"zip-{module}-{version}");
        await _factory.BlobStore.PutAsync(blobKey, new MemoryStream(bytes));
        await InsertGlobalPlaneAsync(orgId, "golang", module, version, $"{version}.zip", blobKey, bytes, blocked);
    }

    private async Task SeedRpmCachedAsync(string orgId, string name, string version, string file, bool blocked)
    {
        // The global-plane RPM serve reads BlobKeys.StoreKey(cache_artifact.blob_key) from the
        // cache tier; a non-proxy-shaped key makes StoreKey the identity.
        string blobKey = $"rpmproxy/{file}";
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes($"rpm-{file}");
        await _factory.BlobStore.PutAsync(BlobKeys.StoreKey(blobKey), new MemoryStream(bytes));
        await InsertGlobalPlaneAsync(orgId, "rpm", name, version, file, blobKey, bytes, blocked);
    }

    private async Task SeedApkCachedAsync(
        string orgId, string release, string repo, string arch, string name, string version, string file, bool blocked)
    {
        // apk serves the cache hit directly from BlobKeys.Apk; the global-plane coordinate
        // filename folds in repo+arch (ApkController.ApkCoordinateFilename) since apk filenames
        // carry no arch segment of their own.
        string blobKey = BlobKeys.Apk(orgId, release, repo, arch, file);
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes($"apk-{name}-{version}");
        await _factory.BlobStore.PutAsync(blobKey, new MemoryStream(bytes));
        await InsertGlobalPlaneAsync(orgId, "apk", name, version, $"{repo}/{arch}/{file}", blobKey, bytes, blocked);
    }

    // Inserts a cache_artifact row and the per-tenant tenant_artifact_access row, optionally
    // pre-set to manual_block_state='blocked'.
    private async Task InsertGlobalPlaneAsync(
        string orgId, string ecosystem, string name, string version, string filename,
        string blobKey, byte[] bytes, bool blocked)
    {
        string contentHash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        string caId = Guid.NewGuid().ToString("N");
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes, purl)
            VALUES
                (@caId, @ecosystem, @name, @version, @filename, @blobKey, @contentHash, @size, @purl)
            """,
            new
            {
                caId,
                ecosystem,
                name,
                version,
                filename,
                blobKey,
                contentHash,
                size = bytes.Length,
                purl = $"pkg:{ecosystem}/{name}@{version}",
            });
        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, manual_block_state)
            VALUES (@orgId, @caId, @state)
            """,
            new { orgId, caId, state = blocked ? "blocked" : null });
    }

    private async Task<string> DefaultOrgIdAsync()
    {
        _factory.CreateClient().Dispose();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1"))!;
    }

    private async Task SetAnonymousPullAsync(bool enabled)
    {
        string orgId = await DefaultOrgIdAsync();
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = @v WHERE org_id = @orgId",
            new { v = enabled ? 1 : 0, orgId });
        _factory.Services.GetRequiredService<OrgRepository>().InvalidateSettingsCache(orgId);
    }
}
