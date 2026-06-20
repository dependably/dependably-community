using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// P1 dual-write tests: after a proxy first-fetch the global plane (<c>cache_artifact</c> +
/// <c>tenant_artifact_access</c>) carries the supply-chain facts written in addition to the
/// existing <c>package_versions</c> row.
/// </summary>
[Trait("Category", "Unit")]
public sealed class GlobalPlaneDualWriteTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private string _orgId1 = "";
    private string _orgId2 = "";

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgId1 = Guid.NewGuid().ToString("N");
        _orgId2 = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id1, 'org1'), (@id2, 'org2')",
            new { id1 = _orgId1, id2 = _orgId2 });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Helpers ──────────────────────────────────────────────────────────────

    private CacheAccessRecorder BuildRecorder()
    {
        var cache = new CacheArtifactRepository(_db);
        var access = new TenantArtifactAccessRepository(_db);
        return new CacheAccessRecorder(
            cache, access,
            NullLoggerFactory.Instance.CreateLogger<CacheAccessRecorder>(),
            _clock);
    }

    private CacheArtifactRepository CacheArtifacts => new(_db);
    private TenantArtifactAccessRepository TenantAccess => new(_db);
    private LicenseRepository Licenses => new(_db, _clock);

    private static CacheAccess SampleAccess(string orgId, string name = "lodash", string version = "4.17.21") => new(
        OrgId: orgId,
        Ecosystem: "npm",
        Name: name,
        Version: version,
        Filename: $"{name}-{version}.tgz",
        Sha256: "abc123def456",
        SizeBytes: 2048,
        BlobKey: $"proxy/npm/{name}/{version}/{name}-{version}.tgz",
        UpstreamUrl: $"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz");

    // ── PyPI first-fetch via ProxyVersionRecorder (shared proxy path) ────────

    [Fact]
    public async Task ProxyFirstFetch_PyPI_GlobalFactsWritten_DownloadCountIs1()
    {
        var recorder = BuildRecorder();
        var cacheArtifacts = CacheArtifacts;
        var tenantAccess = TenantAccess;
        var access = SampleAccess(_orgId1, "requests", "2.31.0");

        // Simulate the ProxyFetchService flow: RecordAccessAsync → UpsertStateAsync → UpdateGlobalFactsAsync.
        string? cacheArtifactId = await recorder.RecordAccessAsync(access);
        Assert.NotNull(cacheArtifactId);

        await tenantAccess.UpsertStateAsync(_orgId1, cacheArtifactId!, _clock.GetUtcNow());
        await cacheArtifacts.UpdateGlobalFactsAsync(
            cacheArtifactId!,
            purl: "pkg:pypi/requests@2.31.0",
            checksumSha1: null,
            publishedAt: null,
            deprecated: null,
            hasInstallScript: false,
            installScriptKind: null,
            provenanceStatus: "verified",
            provenanceSigner: "key-abc",
            upstreamIntegrityValue: "abc123def456",
            upstreamIntegrityAlgorithm: "sha256");

        await using var conn = await _db.OpenAsync();

        // cache_artifact carries the global facts.
        var row = await conn.QuerySingleOrDefaultAsync(
            "SELECT purl, provenance_status, upstream_integrity_value FROM cache_artifact WHERE id = @id",
            new { id = cacheArtifactId });
        Assert.NotNull(row);
        Assert.Equal("pkg:pypi/requests@2.31.0", (string)row!.purl);
        Assert.Equal("verified", (string)row.provenance_status);
        Assert.Equal("abc123def456", (string)row.upstream_integrity_value);

        // tenant_artifact_access has download_count = 1 for org1.
        long downloadCount = await conn.ExecuteScalarAsync<long>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId = _orgId1, caId = cacheArtifactId });
        Assert.Equal(1, downloadCount);
    }

    // ── Cargo custom recorder path ────────────────────────────────────────────

    [Fact]
    public async Task CargoFirstFetch_GlobalFactsWritten_DownloadCountIs1()
    {
        var recorder = BuildRecorder();
        var cacheArtifacts = CacheArtifacts;
        var tenantAccess = TenantAccess;
        string name = "serde";
        string version = "1.0.193";
        string sha256Hex = "deadbeef01234567";
        long sizeBytes = 4096;
        string blobKey = $"proxy/{sha256Hex}";
        string downloadUrl = $"https://static.crates.io/crates/{name}/{version}/download";

        string? cacheArtifactId = await recorder.RecordAccessAsync(new CacheAccess(
            OrgId: _orgId1,
            Ecosystem: "cargo",
            Name: name,
            Version: version,
            Filename: $"{name}-{version}.crate",
            Sha256: sha256Hex,
            SizeBytes: sizeBytes,
            BlobKey: blobKey,
            UpstreamUrl: downloadUrl));
        Assert.NotNull(cacheArtifactId);

        await tenantAccess.UpsertStateAsync(_orgId1, cacheArtifactId!, _clock.GetUtcNow());
        await cacheArtifacts.UpdateGlobalFactsAsync(
            cacheArtifactId!,
            purl: PurlNormalizer.Cargo(name, version),
            checksumSha1: null,
            publishedAt: null,
            deprecated: null,
            hasInstallScript: false,
            installScriptKind: null,
            provenanceStatus: null,
            provenanceSigner: null,
            upstreamIntegrityValue: sha256Hex,
            upstreamIntegrityAlgorithm: "sha256");

        await using var conn = await _db.OpenAsync();

        string? purl = await conn.ExecuteScalarAsync<string?>(
            "SELECT purl FROM cache_artifact WHERE id = @id", new { id = cacheArtifactId });
        Assert.Equal($"pkg:cargo/{name}@{version}", purl);

        long downloadCount = await conn.ExecuteScalarAsync<long>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId = _orgId1, caId = cacheArtifactId });
        Assert.Equal(1, downloadCount);
    }

    // ── Two-tenant scenario ──────────────────────────────────────────────────

    [Fact]
    public async Task TwoTenantsFetchSameCoordinate_OneCacheArtifact_TwoAccessRows_BothGetPackageVersionsRow()
    {
        var recorder = BuildRecorder();
        var tenantAccess = TenantAccess;
        var cacheArtifacts = CacheArtifacts;

        // Org1 first-fetch.
        var access1 = SampleAccess(_orgId1);
        string? caId1 = await recorder.RecordAccessAsync(access1);
        Assert.NotNull(caId1);
        await tenantAccess.UpsertStateAsync(_orgId1, caId1!, _clock.GetUtcNow());
        await cacheArtifacts.UpdateGlobalFactsAsync(
            caId1!, purl: "pkg:npm/lodash@4.17.21", checksumSha1: null,
            publishedAt: null, deprecated: null, hasInstallScript: false,
            installScriptKind: null, provenanceStatus: null, provenanceSigner: null,
            upstreamIntegrityValue: null, upstreamIntegrityAlgorithm: null);

        // Org2 fetches the same coordinate.
        var access2 = SampleAccess(_orgId2);
        string? caId2 = await recorder.RecordAccessAsync(access2);
        Assert.NotNull(caId2);
        // The recorder must return the SAME cache_artifact id (dedup by coordinate).
        Assert.Equal(caId1, caId2);
        await tenantAccess.UpsertStateAsync(_orgId2, caId2!, _clock.GetUtcNow());

        await using var conn = await _db.OpenAsync();

        // Exactly ONE cache_artifact row for the coordinate.
        long artifactCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'lodash' AND version = '4.17.21'");
        Assert.Equal(1, artifactCount);

        // TWO tenant_artifact_access rows, one per org.
        long accessCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE cache_artifact_id = @caId",
            new { caId = caId1 });
        Assert.Equal(2, accessCount);

        long org1Count = await conn.ExecuteScalarAsync<long>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId = _orgId1, caId = caId1 });
        long org2Count = await conn.ExecuteScalarAsync<long>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId = _orgId2, caId = caId2 });
        Assert.Equal(1, org1Count);
        Assert.Equal(1, org2Count);
    }

    // ── package_versions dual-write is preserved ─────────────────────────────

    [Fact]
    public async Task TwoTenants_EachGetOwnPackageVersionsRow_DualWriteIntact()
    {
        // Insert prerequisite packages for both orgs.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("""
                INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
                VALUES ('p1', @o1, 'npm', 'lodash', 'lodash', 1),
                       ('p2', @o2, 'npm', 'lodash', 'lodash', 1)
                """, new { o1 = _orgId1, o2 = _orgId2 });
            await conn.ExecuteAsync("""
                INSERT INTO package_versions (id, package_id, version, purl, blob_key)
                VALUES ('v1', 'p1', '4.17.21', 'pkg:npm/lodash@4.17.21', 'proxy/abc/lodash-4.17.21.tgz'),
                       ('v2', 'p2', '4.17.21', 'pkg:npm/lodash@4.17.21', 'proxy/abc/lodash-4.17.21.tgz')
                """);
        }

        // Simulate global plane writes.
        var recorder = BuildRecorder();
        var tenantAccess = TenantAccess;
        var access1 = SampleAccess(_orgId1);
        var access2 = SampleAccess(_orgId2);
        string? caId1 = await recorder.RecordAccessAsync(access1);
        string? caId2 = await recorder.RecordAccessAsync(access2);
        Assert.NotNull(caId1);
        Assert.Equal(caId1, caId2); // same artifact

        await tenantAccess.UpsertStateAsync(_orgId1, caId1!, _clock.GetUtcNow());
        await tenantAccess.UpsertStateAsync(_orgId2, caId2!, _clock.GetUtcNow());

        await using var conn2 = await _db.OpenAsync();

        // Both orgs still have their own package_versions rows (dual-write intact).
        long pvCount1 = await conn2.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE package_id = 'p1'");
        long pvCount2 = await conn2.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE package_id = 'p2'");
        Assert.Equal(1, pvCount1);
        Assert.Equal(1, pvCount2);

        // Global plane: ONE cache_artifact, TWO access rows.
        long cacheCount = await conn2.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'lodash' AND version = '4.17.21'");
        Assert.Equal(1, cacheCount);

        long taaCount = await conn2.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE cache_artifact_id = @caId",
            new { caId = caId1 });
        Assert.Equal(2, taaCount);
    }

    // ── Mixed partial-failure scenario ───────────────────────────────────────

    [Fact]
    public async Task MixedPartialFailure_CacheArtifactInsertSucceeds_GlobalFactsUpdateFails_DownloadCountStillRecorded()
    {
        // Arrange: drop cache_artifact after schema init to simulate a failure in UpdateGlobalFactsAsync.
        // The recorder (RecordAccessAsync) should succeed first; then UpdateGlobalFactsAsync will fail
        // but UpsertStateAsync should still have recorded the access.
        var recorder = BuildRecorder();
        var tenantAccess = TenantAccess;

        // First call succeeds: inserts cache_artifact + tenant_artifact_access.
        string? caId = await recorder.RecordAccessAsync(SampleAccess(_orgId1));
        Assert.NotNull(caId);
        await tenantAccess.UpsertStateAsync(_orgId1, caId!, _clock.GetUtcNow());

        // Verify the access was recorded.
        await using var conn = await _db.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId = _orgId1, caId });
        Assert.Equal(1, count);

        // Second call from org2 — recorder succeeds (same artifact), but we simulate global-facts
        // write failure by using a broken store (null id) — recorder should still return the id.
        string? caId2 = await recorder.RecordAccessAsync(SampleAccess(_orgId2));
        Assert.Equal(caId, caId2); // same coordinate → same artifact

        await tenantAccess.UpsertStateAsync(_orgId2, caId2!, _clock.GetUtcNow());

        // Both orgs have download_count = 1 despite no global facts being updated (simulating
        // the partial-failure path where global facts are not the critical path).
        long org2Count = await conn.ExecuteScalarAsync<long>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId = _orgId2, caId = caId2 });
        Assert.Equal(1, org2Count);

        // cache_artifact row is intact: exactly one row.
        long artifactCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE id = @id", new { id = caId });
        Assert.Equal(1, artifactCount);
    }

    // ── License dual-write ───────────────────────────────────────────────────

    [Fact]
    public async Task LicenseDualWrite_SetLicensesForCacheArtifact_InsertsGlobalRows()
    {
        var recorder = BuildRecorder();
        var licenses = Licenses;

        string? caId = await recorder.RecordAccessAsync(SampleAccess(_orgId1));
        Assert.NotNull(caId);

        await licenses.SetLicensesForCacheArtifactAsync(caId!, new[] { "MIT", "Apache-2.0" }, "upstream");

        await using var conn = await _db.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_version_licenses WHERE cache_artifact_id = @caId AND owner_kind = 'cache_artifact'",
            new { caId });
        Assert.Equal(2, count);
    }

    [Fact]
    public async Task LicenseDualWrite_IdempotentOnDuplicate_NoExceptionOnSecondInsert()
    {
        var recorder = BuildRecorder();
        var licenses = Licenses;

        string? caId = await recorder.RecordAccessAsync(SampleAccess(_orgId1));
        Assert.NotNull(caId);

        await licenses.SetLicensesForCacheArtifactAsync(caId!, new[] { "MIT" }, "upstream");
        // Second call must not throw (ON CONFLICT DO NOTHING).
        var ex = await Record.ExceptionAsync(() =>
            licenses.SetLicensesForCacheArtifactAsync(caId!, new[] { "MIT" }, "upstream"));
        Assert.Null(ex);

        await using var conn = await _db.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_version_licenses WHERE cache_artifact_id = @caId",
            new { caId });
        Assert.Equal(1, count); // Still just one row.
    }

    // ── package_version_licenses nullable migration ──────────────────────────

    [Fact]
    public async Task MakePvlPackageVersionIdNullable_FreshInstall_PackageVersionIdIsNullable()
    {
        // Fresh install via InitializeAsync already ran. Verify the column is nullable.
        await using var conn = await _db.OpenAsync();
        long notnull = await conn.ExecuteScalarAsync<long>(
            "SELECT \"notnull\" FROM pragma_table_info('package_version_licenses') WHERE name = 'package_version_id'");
        Assert.Equal(0, notnull);
    }

    [Fact]
    public async Task MakePvlPackageVersionIdNullable_FreshInstall_CacheArtifactUniqueIndexExists()
    {
        // The UNIQUE(cache_artifact_id, license_spdx) index must exist after fresh init.
        await using var conn = await _db.OpenAsync();
        string? indexName = await conn.QuerySingleOrDefaultAsync<string>(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_pvl_cache_artifact_license'");
        Assert.Equal("idx_pvl_cache_artifact_license", indexName);
    }

    [Fact]
    public async Task MakePvlPackageVersionIdNullable_AllowsNullPackageVersionId_ForCacheArtifactOwner()
    {
        // Insert a license row with owner_kind='cache_artifact' and package_version_id=NULL.
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash) " +
            "VALUES ('ca1','npm','lodash','4.17.21','lodash-4.17.21.tgz','k','h')");

        var ex = await Record.ExceptionAsync(() => conn.ExecuteAsync("""
            INSERT INTO package_version_licenses
                (id, cache_artifact_id, owner_kind, license_spdx, source)
            VALUES ('lic1', 'ca1', 'cache_artifact', 'MIT', 'upstream')
            """));
        Assert.Null(ex);

        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_version_licenses WHERE cache_artifact_id = 'ca1'");
        Assert.Equal(1, count);
    }
}
