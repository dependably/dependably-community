using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Refcount behaviour of the management delete path for a shared OCI manifest blob. OCI blob keys
/// are content-addressed with no org segment, so two orgs pushing the same digest share one physical
/// blob. The path is two production steps and both are exercised here in the order
/// <c>OrgController.DeleteVersion</c> runs them:
/// <c>PackageRepository.DeleteOciManifestShadowAndResolveUploadedBlobAsync</c> drops only this org's
/// shadow rows and names the uploaded blob, then <c>OciOrphanBlobDeleter</c> removes the file only
/// when no other org's row still references it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciManifestDeleteRefcountTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _registry = new();
    private readonly InMemoryBlobStore _cache = new();
    private PackageRepository _packages = null!;
    private OciOrphanBlobDeleter _orphanBlobs = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _packages = new PackageRepository(_db);
        _orphanBlobs = new OciOrphanBlobDeleter(
            _db, new TieredBlobStorage(_cache, _registry), new OciBlobKeyLock());
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private async Task SeedManifestAsync(
        string orgId, string digest, string blobKey, string origin = "uploaded",
        string repo = "library/img", string tag = "latest")
    {
        await _registry.PutAsync(blobKey, new MemoryStream(new byte[10]));
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT OR IGNORE INTO orgs (id, slug) VALUES (@orgId, @orgId)", new { orgId });
        await conn.ExecuteAsync(
            "INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin) " +
            "VALUES (@digest, @orgId, 'application/vnd.oci.image.manifest.v1+json', 10, @blobKey, @origin)",
            new { digest, orgId, blobKey, origin });
        await conn.ExecuteAsync(
            "INSERT INTO oci_tags (org_id, repository, tag, digest) VALUES (@orgId, @repo, @tag, @digest)",
            new { orgId, repo, tag, digest });
    }

    [Fact]
    public async Task SharedDigest_OneOrgDeletes_KeepsBlobAndTheOtherOrgsShadowRows()
    {
        string digest = "sha256:" + new string('a', 64);
        string blobKey = BlobKeys.OciBlob("sha256", new string('a', 64));
        await SeedManifestAsync("o-a", digest, blobKey);
        await SeedManifestAsync("o-b", digest, blobKey);

        // Org A deletes: the blob is an uploaded candidate, but org B still references it.
        string? candidate = await _packages.DeleteOciManifestShadowAndResolveUploadedBlobAsync("o-a", "library/img", digest);
        Assert.Equal(blobKey, candidate);
        Assert.False(await _orphanBlobs.DeleteIfUnreferencedAsync(candidate!));
        Assert.True(await _registry.ExistsAsync(blobKey), "org B still references the shared blob");

        await using var conn = await _db.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM oci_blobs WHERE org_id = 'o-a' AND digest = @digest", new { digest }));
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM oci_tags WHERE org_id = 'o-a' AND digest = @digest", new { digest }));
        // Org B's shadow rows are untouched — its image still resolves.
        Assert.Equal(1, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM oci_blobs WHERE org_id = 'o-b' AND digest = @digest", new { digest }));
        Assert.Equal(1, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM oci_tags WHERE org_id = 'o-b' AND digest = @digest", new { digest }));
    }

    [Fact]
    public async Task LastReference_PhysicallyDeletesTheBlob()
    {
        string digest = "sha256:" + new string('c', 64);
        string blobKey = BlobKeys.OciBlob("sha256", new string('c', 64));
        await SeedManifestAsync("o-solo", digest, blobKey);

        // Sole reference → the blob is orphaned and the file goes.
        string? candidate = await _packages.DeleteOciManifestShadowAndResolveUploadedBlobAsync("o-solo", "library/img", digest);
        Assert.Equal(blobKey, candidate);
        Assert.True(await _orphanBlobs.DeleteIfUnreferencedAsync(candidate!));
        Assert.False(await _registry.ExistsAsync(blobKey));

        await using var conn = await _db.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM oci_blobs WHERE digest = @digest", new { digest }));
    }

    [Fact]
    public async Task ProxyOriginManifest_IsNeverPhysicallyDeleted_EvenAsLastReference()
    {
        string digest = "sha256:" + new string('d', 64);
        string blobKey = BlobKeys.OciBlob("sha256", new string('d', 64));
        await SeedManifestAsync("o-proxy", digest, blobKey, origin: "proxy");

        // Proxy-tier blobs are reclaimed by cache GC, never physically deleted through this path:
        // the repository resolves no candidate, so the deleter is never reached.
        string? candidate = await _packages.DeleteOciManifestShadowAndResolveUploadedBlobAsync("o-proxy", "library/img", digest);
        Assert.Null(candidate);
        Assert.True(await _registry.ExistsAsync(blobKey));

        await using var conn = await _db.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM oci_blobs WHERE digest = @digest", new { digest }));
    }
}
