using Dapper;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Regression coverage for the OCI manifest-delete "permanent UI zombie": DELETE
/// /v2/{repo}/manifests/{digest} must clear the catalogue shadow a manifest casts, whichever
/// shadow that is, or the digest survives forever in <see cref="ArtifactInventoryRepository.ListServeableVersionsAsync"/>
/// / <c>artifact_inventory</c> — OCI has no eviction sweep to reclaim it later.
///
/// Drives the real production entry point, <see cref="OciController.Delete"/> (which dispatches
/// to <c>HandleManifestDeleteAsync</c>), not a test-local re-implementation of its cleanup.
/// Assertions read back through the same production repositories the management package page and
/// inventory read (<see cref="ArtifactInventoryRepository"/>, <see cref="PackageRepository"/>),
/// not raw SQL alone — including that the parent <c>packages</c> row itself is reclaimed once
/// neither catalogue references it, so a delete never leaves a zero-version "empty package" card.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciManifestDeleteShadowCleanupTests : IAsyncLifetime
{
    private const string Repository = "library/zombie";

    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _registry = new();
    private readonly InMemoryBlobStore _cache = new();

    private OrgRepository _orgs = null!;
    private PackageRepository _packages = null!;
    private TokenRepository _tokens = null!;
    private AuditRepository _audit = null!;
    private CacheArtifactRepository _cacheArtifacts = null!;
    private TenantArtifactAccessRepository _tenantAccess = null!;
    private ArtifactInventoryRepository _inventory = null!;
    private string _orgId = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgs = new OrgRepository(_db);
        _packages = new PackageRepository(_db);
        _tokens = new TokenRepository(_db, TimeProvider.System);
        _audit = new AuditRepository(_db);
        _cacheArtifacts = new CacheArtifactRepository(_db);
        _tenantAccess = new TenantArtifactAccessRepository(_db);
        var vulns = new VulnerabilityRepository(_db, TimeProvider.System);
        _inventory = new ArtifactInventoryRepository(_db, _packages, _cacheArtifacts, vulns);

        _orgId = await OrgSeeder.InsertAsync(_db, "oci-zombie-org");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task HostedPushDelete_RemovesPackageVersionsShadow_FromInventoryAndServeableList()
    {
        string digest = "sha256:" + new string('1', 64);
        string blobKey = BlobKeys.OciBlob("sha256", new string('1', 64));

        string packageId = await SeedUploadedManifestAsync(digest, blobKey);

        // Sanity: the digest is visible before the delete, through both production read paths.
        var before = await _inventory.ListServeableVersionsAsync(_orgId, packageId, "oci", Repository);
        Assert.Contains(before, v => v.Version == digest);
        var beforeInventory = await _inventory.ListForPackageAsync(_orgId, "oci", Repository);
        Assert.Contains(beforeInventory, r => r.Version == digest);

        var controller = BuildController(_orgId, await SeedYankTokenAsync(_orgId));
        var result = await controller.Delete($"{Repository}/manifests/{digest}", default);

        Assert.IsType<NoContentResult>(result);

        // package_versions shadow is gone, and since it was the package's only version, the parent
        // packages row is reclaimed too — otherwise it survives forever as a zero-version "empty
        // package" card (OCI has no eviction sweep to reclaim it later).
        var pkgAfter = await _packages.GetByPurlNameAsync(_orgId, "oci", Repository);
        Assert.Null(pkgAfter);
        var afterInventory = await _inventory.ListForPackageAsync(_orgId, "oci", Repository);
        Assert.DoesNotContain(afterInventory, r => r.Version == digest);
    }

    [Fact]
    public async Task ProxyPullDelete_RemovesTenantArtifactAccessShadow_FromInventoryAndServeableList_ButKeepsSharedRow()
    {
        string digest = "sha256:" + new string('2', 64);
        string blobKey = BlobKeys.OciBlob("sha256", new string('2', 64));

        string packageId = await SeedProxiedManifestAsync(digest, blobKey);

        var before = await _inventory.ListServeableVersionsAsync(_orgId, packageId, "oci", Repository);
        Assert.Contains(before, v => v.Version == digest);
        var beforeInventory = await _inventory.ListForPackageAsync(_orgId, "oci", Repository);
        Assert.Contains(beforeInventory, r => r.Version == digest);

        var controller = BuildController(_orgId, await SeedYankTokenAsync(_orgId));
        var result = await controller.Delete($"{Repository}/manifests/{digest}", default);

        Assert.IsType<NoContentResult>(result);

        // tenant_artifact_access shadow is gone for this org, so neither read path serves the digest.
        var after = await _inventory.ListServeableVersionsAsync(_orgId, packageId, "oci", Repository);
        Assert.DoesNotContain(after, v => v.Version == digest);
        var afterInventory = await _inventory.ListForPackageAsync(_orgId, "oci", Repository);
        Assert.DoesNotContain(afterInventory, r => r.Version == digest);

        // A proxy-only manifest never had a package_versions row, so this org's packages row is
        // reclaimed purely on the tenant_artifact_access drop — the GC check must not skip over
        // this case just because there was no package_versions delete to trigger it.
        var pkgAfter = await _packages.GetByPurlNameAsync(_orgId, "oci", Repository);
        Assert.Null(pkgAfter);

        // The shared cache_artifact row survives — OCI is excluded from cache-plane reclamation
        // everywhere else, and this delete path does not special-case that policy.
        var stillShared = await _cacheArtifacts.GetByCoordinateAsync("oci", Repository, digest, "manifest");
        Assert.NotNull(stillShared);
    }

    [Fact]
    public async Task DigestCastBothShadows_DeleteClearsBoth()
    {
        // An image can be proxy-pulled first (cache_artifact/tenant_artifact_access) and later
        // pushed to the same digest (package_versions) — oci_blobs.origin never rewrites once set,
        // so this delete cannot rely on it to decide which shadow(s) exist. Both must be cleared by
        // one call.
        string digest = "sha256:" + new string('3', 64);
        string blobKey = BlobKeys.OciBlob("sha256", new string('3', 64));

        string packageId = await SeedUploadedManifestAsync(digest, blobKey);
        await SeedProxyShadowOnlyAsync(digest, blobKey);

        var controller = BuildController(_orgId, await SeedYankTokenAsync(_orgId));
        var result = await controller.Delete($"{Repository}/manifests/{digest}", default);

        Assert.IsType<NoContentResult>(result);

        await using var conn = await _db.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE package_id = @packageId AND version = @digest",
            new { packageId, digest }));
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM tenant_artifact_access taa
            JOIN cache_artifact ca ON ca.id = taa.cache_artifact_id
            WHERE taa.org_id = @orgId AND ca.ecosystem = 'oci' AND ca.name = @repo AND ca.version = @digest
            """,
            new { orgId = _orgId, repo = Repository, digest }));

        var afterInventory = await _inventory.ListForPackageAsync(_orgId, "oci", Repository);
        Assert.DoesNotContain(afterInventory, r => r.Version == digest);

        // Both shadows are gone, so the parent packages row is reclaimed too: the GC check must run
        // after both drops land, not race ahead of the tenant_artifact_access removal and observe a
        // still-referenced row.
        var pkgAfter = await _packages.GetByPurlNameAsync(_orgId, "oci", Repository);
        Assert.Null(pkgAfter);
    }

    // ── Seeding ──────────────────────────────────────────────────────────────────

    // Mirrors OciUploadService's tag-push catalogue write: oci_blobs + oci_tags (protocol plane)
    // plus packages + package_versions (catalogue plane).
    private async Task<string> SeedUploadedManifestAsync(string digest, string blobKey)
    {
        await _registry.PutAsync(blobKey, new MemoryStream(new byte[10]));
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
            VALUES (@digest, @orgId, 'application/vnd.oci.image.manifest.v1+json', 10, @blobKey, 'uploaded')
            """,
            new { digest, orgId = _orgId, blobKey });
        await conn.ExecuteAsync(
            "INSERT INTO oci_tags (org_id, repository, tag, digest) VALUES (@orgId, @repo, 'v1', @digest)",
            new { orgId = _orgId, repo = Repository, digest });

        string packageId = await PackageSeeder.InsertAsync(_db, _orgId, "oci", Repository);
        await PackageSeeder.InsertVersionAsync(
            _db, packageId, digest, $"pkg:oci/{Repository}@{digest}", origin: "uploaded", blobKey: blobKey);
        return packageId;
    }

    // Mirrors OciUpstreamResolver's proxy-pull catalogue write: oci_blobs (origin='proxy') plus
    // packages (isProxy=true) + a global cache_artifact row + this org's tenant_artifact_access row.
    private async Task<string> SeedProxiedManifestAsync(string digest, string blobKey)
    {
        await _registry.PutAsync(blobKey, new MemoryStream(new byte[10]));
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
            VALUES (@digest, @orgId, 'application/vnd.oci.image.manifest.v1+json', 10, @blobKey, 'proxy')
            """,
            new { digest, orgId = _orgId, blobKey });

        string packageId = await PackageSeeder.InsertAsync(_db, _orgId, "oci", Repository, isProxy: true);
        await SeedProxyShadowOnlyAsync(digest, blobKey);
        return packageId;
    }

    // Just the cache_artifact/tenant_artifact_access pair, for the mixed-shadow test where the
    // packages row already exists from an earlier hosted seed.
    private async Task SeedProxyShadowOnlyAsync(string digest, string blobKey)
    {
        var artifact = await _cacheArtifacts.InsertAsync(new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("N"),
            Ecosystem = "oci",
            Name = Repository,
            Version = digest,
            Filename = "manifest",
            BlobKey = blobKey,
            ContentHash = digest,
            SizeBytes = 10,
            FirstCachedAt = TestTime.KnownNow,
            LastAccessedAt = TestTime.KnownNow,
        });
        await _tenantAccess.UpsertAsync(_orgId, artifact.Id, TestTime.KnownNow, TenantContentBinding.None);
    }

    private async Task<string> SeedYankTokenAsync(string orgId)
    {
        var (rawToken, _) = await _tokens.CreateServiceTokenAsync(
            orgId, "zombie-yank", """["yank:oci","read:artifact"]""", expiresAt: null);
        return rawToken;
    }

    // ── Controller construction ──────────────────────────────────────────────────

    private OciController BuildController(string orgId, string rawToken)
    {
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Request.Host = new HostString("oci-zombie-org.example.test");
        http.Request.Headers.Authorization = $"Bearer {rawToken}";
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(orgId, "oci-zombie-org");
        var services = new ServiceCollection();
        services.AddLogging();
        http.RequestServices = services.BuildServiceProvider();

        var tiered = new TieredBlobStorage(_cache, _registry);
        var svc = new OciControllerServices(
            Tokens: _tokens,
            Audit: _audit,
            Orgs: _orgs,
            BlobStore: tiered,
            Db: _db,
            Upstream: null!,
            Uploads: null!,
            OrphanBlobs: new OciOrphanBlobDeleter(_db, tiered, new OciBlobKeyLock()),
            BlockGate: null!,
            EdgeGuard: Dependably.Tests.Infrastructure.TestEdgeMode.DisabledPublishGuard(),
            Packages: _packages,
            TenantArtifactAccess: _tenantAccess);

        return new OciController(svc, NullLogger<OciController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }
}
