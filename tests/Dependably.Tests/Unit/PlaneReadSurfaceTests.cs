using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// An artifact reaches an org through either plane — a hosted push writes a <c>package_versions</c>
/// row, a proxy fetch writes a <c>cache_artifact</c> row the org reaches through
/// <c>tenant_artifact_access</c> — and a read surface that enumerates only one of them is blind to
/// half the org's inventory. These cover the three surfaces that were.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PlaneReadSurfaceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id) VALUES ('o1')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── The storage counter agrees with the storage the operator is shown ────────

    [Fact]
    public async Task Storage_quota_baseline_matches_what_the_admin_tenant_list_reports()
    {
        await using var conn = await _db.OpenAsync();

        // Hosted bytes, proxied bytes, and an OCI image whose layers dwarf its manifest. A baseline
        // computed from package_versions alone sees only the first — and for the image, only the
        // manifest — so an org well over its quota could be baselined at almost nothing.
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES " +
            "('p1', 'o1', 'npm', 'hosted', 'hosted', 0), " +
            "('p2', 'o1', 'oci', 'library/nginx', 'library/nginx', 0)");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, origin) VALUES " +
            "('v1', 'p1', '1.0.0', 'pkg:npm/hosted@1.0.0', 'registry/v1', 1000, 'uploaded'), " +
            "('v2', 'p2', 'sha256:abc', 'pkg:oci/nginx@sha256:abc', 'oci/sha256/abc', 5, 'uploaded')");
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes) " +
            "VALUES ('ca1', 'npm', 'proxied', '1.0.0', 'proxied-1.0.0.tgz', 'proxy/ca1', 'ca1', 2000)");
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1', 'ca1')");
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, blob_key, size_bytes, media_type) VALUES
              ('sha256:abc', 'o1', 'oci/sha256/abc', 5,      'application/vnd.oci.image.manifest.v1+json'),
              ('sha256:def', 'o1', 'oci/sha256/def', 900000, 'application/vnd.oci.image.layer.v1.tar+gzip')
            """);

        var orgs = new OrgRepository(_db);
        long enforced = await orgs.GetLiveStorageBytesAsync("o1");
        var (items, _) = await orgs.ListOrgsAsync(limit: 10, offset: 0);
        long reported = items.Single(i => i.Id == "o1").StorageBytes;

        // Tying the number the quota gate enforces against to the number the operator is shown is
        // the assertion that matters — a magic constant on either side would let the two
        // definitions drift apart again without failing.
        Assert.Equal(reported, enforced);

        // 1000 hosted + 2000 proxied + 5 manifest + 900000 layer. The layer bytes are the ones a
        // package_versions-only reading could never see.
        Assert.Equal(903005, enforced);
    }

    // ── The vuln report keeps a proxied artifact with no packages row ────────────

    [Fact]
    public async Task Vuln_report_includes_a_proxied_artifact_that_has_no_packages_row()
    {
        await using var conn = await _db.OpenAsync();

        // An org reaches a cache_artifact through tenant_artifact_access alone; the packages row is
        // a best-effort convenience and can be missing. Joining it INNER drops the artifact — and
        // its advisories — out of the report entirely.
        await conn.ExecuteAsync(
            "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, purl) " +
            "VALUES ('ca1', 'npm', 'orphan', '1.0.0', 'orphan-1.0.0.tgz', 'proxy/ca1', 'ca1', 'pkg:npm/orphan@1.0.0')");
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1', 'ca1')");
        await conn.ExecuteAsync(
            "INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity) " +
            "VALUES ('vu1', 'CVE-2026-1', 'npm', 'orphan', 'HIGH')");
        await conn.ExecuteAsync(
            "INSERT INTO package_version_vulns (id, cache_artifact_id, vuln_id, owner_kind, checked_at) " +
            "VALUES ('pvv1', 'ca1', 'vu1', 'cache_artifact', '2026-06-15T12:00:00Z')");

        var vulns = new VulnerabilityRepository(_db, _clock);
        var (rows, total) = await vulns.GetVulnReportAsync(
            new VulnReportQuery("o1", Limit: 50, Offset: 0, Sort: "severity", Dir: "desc"));

        Assert.Equal(1, total);
        var row = Assert.Single(rows);
        Assert.Equal("CVE-2026-1", row.OsvId);
        // With no packages row to name it, the artifact's own name stands in.
        Assert.Equal("orphan", row.PackageName);
    }
}
