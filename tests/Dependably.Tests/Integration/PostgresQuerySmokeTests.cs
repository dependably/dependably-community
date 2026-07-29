using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Integration;

/// <summary>
/// Postgres is a supported provider, but until now the only <c>Category=SchemaPostgres</c>
/// coverage applied the DDL (<see cref="PostgresSchemaApplyTests"/>) — no test ever executed a
/// query against a live server. A Postgres-only query defect (a subquery alias PG&lt;=16 requires,
/// a SQLite-only function like <c>strftime</c>, a SQLite-only collation like <c>COLLATE NOCASE</c>)
/// could ship undetected because SQLite, which every other test runs against, tolerates all three.
///
/// This seeds ONE org with every artifact shape a tenant can hold — a hosted version, a proxied
/// version with a matching <c>packages</c> row, a proxied artifact with none, a pushed OCI image,
/// a proxied OCI image, and a by-digest OCI layer with no catalogue row at all — then executes
/// (not merely prepares) every union-shaped / view-backed read surface against a live server. The
/// primary value is that these statements run to completion on Postgres; the assertions on top are
/// real numbers derived from the seed, not just "did not throw".
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class PostgresQuerySmokeTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    private const string OrgId = "o1";

    // package_versions / cache_artifact byte sizes, named so the expected totals below are
    // derived arithmetic, not a magic constant that could silently drift from the seed.
    private const long HostedNpmBytes = 1000;
    private const long ProxiedNpmMatchedBytes = 2000;
    private const long ProxiedNpmOrphanBytes = 500;
    private const long OciManifestPushedBytes = 5;
    private const long OciConfigPushedBytes = 300;
    private const long OciLayerPushedBytes = 700_000;
    private const long OciManifestProxiedBytes = 6;
    private const long OciLayerProxiedBytes = 800_000;
    private const long OciByDigestLayerBytes = 123_456;

    private const long TotalOciBlobBytes =
        OciManifestPushedBytes + OciConfigPushedBytes + OciLayerPushedBytes +
        OciManifestProxiedBytes + OciLayerProxiedBytes + OciByDigestLayerBytes;

    private const long TotalStorageBytes =
        HostedNpmBytes + ProxiedNpmMatchedBytes + ProxiedNpmOrphanBytes + TotalOciBlobBytes;

    [Fact]
    public async Task Every_canonical_read_surface_executes_against_live_postgres()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        await SeedEveryArtifactShapeAsync(store);

        var clock = TestTime.Frozen();

        // ── OrgRepository ────────────────────────────────────────────────────
        var orgs = new OrgRepository(store);

        var (orgItems, orgTotal) = await orgs.ListOrgsAsync(limit: 10, offset: 0);
        Assert.Equal(1, orgTotal);
        var orgItem = Assert.Single(orgItems);
        Assert.Equal(OrgId, orgItem.Id);
        Assert.Equal(TotalStorageBytes, orgItem.StorageBytes);

        // The quota gate's one reading of "bytes this org holds" must execute against live
        // Postgres and total every plane — hosted, cache, and OCI.
        Assert.Equal(TotalStorageBytes, await orgs.GetLiveStorageBytesAsync(OrgId));
        using (var reservation = await orgs.TryReserveStorageAsync(OrgId, delta: 0, quota: null))
        {
            Assert.NotNull(reservation);
        }

        // ── PackageAnalyticsRepository ──────────────────────────────────────
        var analytics = new PackageAnalyticsRepository(store, samlConfig: null, time: clock);
        var stats = await analytics.GetOrgStatsAsync(OrgId);

        Assert.Equal(2, stats.PackagesByEcosystem.Count(c => c.Count > 0));
        Assert.Contains(stats.VulnsByEcosystemAndSeverity, r => r.Ecosystem == "npm" && r.Severity == "HIGH" && r.Count == 1);
        Assert.Contains(stats.VulnsByEcosystemAndSeverity, r => r.Ecosystem == "npm" && r.Severity == "CRITICAL" && r.Count == 1);
        Assert.Contains(stats.DiskByEcosystem, d => d.Ecosystem == "oci" && d.TotalBytes == TotalOciBlobBytes);
        Assert.Contains(stats.DiskByEcosystem, d => d.Ecosystem == "npm"
            && d.TotalBytes == HostedNpmBytes + ProxiedNpmMatchedBytes + ProxiedNpmOrphanBytes);
        Assert.Equal(TotalStorageBytes, stats.TotalDiskBytes);
        Assert.Equal(2, stats.NewVulns.Day);
        Assert.Equal(2, stats.NewVulns.Week);
        Assert.Equal(2, stats.NewVulns.Month);
        Assert.Equal(2, stats.HostedPackages);
        Assert.Equal(1, stats.ProxiedPackages);
        // pv1 (npm, versions_behind 7) and ca1 (npm, versions_behind 6) both clear the threshold-5
        // dashboard tile, as two distinct (ecosystem, name) packages.
        Assert.Equal(2, stats.OperationalRiskPackageCount);
        // pv2 (oci, no license row), ca2 (npm proxy orphan, no license row), ca3 (oci proxy, no
        // license row) are "unknown"; pv1 (MIT) and ca1 (Apache-2.0) both carry a license that is
        // on neither list, so neither counts.
        Assert.Equal(3, stats.LicenseRiskVersionCount);

        var (opRows, opTotal, opPackageCount) = await analytics.ListOperationalRiskAsync(
            OrgId, ecosystem: null, limit: 50, offset: 0);
        Assert.Equal(2, opTotal);
        Assert.Equal(2, opPackageCount);
        Assert.Equal(2, opRows.Count);

        var (licRows, licTotal) = await analytics.ListLicenseRiskAsync(
            OrgId, ecosystem: null, reason: null, limit: 50, offset: 0);
        Assert.Equal(3, licTotal);
        Assert.All(licRows, r => Assert.Equal("unknown", r.Reason));

        // ── VulnerabilityRepository.GetVulnReportAsync ──────────────────────
        var vulns = new VulnerabilityRepository(store, clock);

        var (defaultRows, defaultTotal) = await vulns.GetVulnReportAsync(new VulnReportQuery(OrgId, Limit: 50, Offset: 0));
        Assert.Equal(2, defaultTotal);
        // Default sort is severity desc: CRITICAL (the proxy-plane row) before HIGH.
        Assert.Equal("CRITICAL", defaultRows[0].Severity);
        Assert.Equal("HIGH", defaultRows[1].Severity);

        // Explicitly exercises the "package" sort column, which used to be `COLLATE NOCASE` — a
        // SQLite-only collation name that errors on Postgres. It is now LOWER(), which both
        // engines support identically.
        var (byPackage, _) = await vulns.GetVulnReportAsync(
            new VulnReportQuery(OrgId, Limit: 50, Offset: 0, Sort: "package", Dir: "asc"));
        Assert.Equal("left-pad", byPackage[0].PackageName);
        Assert.Equal("proxied-pkg", byPackage[1].PackageName);

        // ── PackageRepository.ListPaginatedAsync — plain sort (page-then-hydrate) ──
        var packages = new PackageRepository(store, time: clock);
        var (byName, byNameTotal) = await packages.ListPaginatedAsync(
            new PackageListQuery(OrgId, Limit: 50, Offset: 0, Ecosystem: null, SortBy: "name", SortDir: "asc"));
        Assert.Equal(3, byNameTotal);
        Assert.Equal(["left-pad", "library/nginx", "proxied-pkg"], byName.Select(p => p.Name));

        // ── PackageRepository.ListPaginatedAsync — search predicate ─────────
        // The search filter LOWER()s both the column and the pattern so the two providers agree.
        // This is the one assertion that can prove it: SQLite's LIKE folds ASCII case by itself,
        // so the SQLite tests pass with or without the LOWER() — only a live Postgres run, whose
        // LIKE is case-sensitive, fails when it is missing. Without it 'LEFT-PAD' matches nothing.
        var (byUpper, byUpperTotal) = await packages.ListPaginatedAsync(
            new PackageListQuery(OrgId, Limit: 50, Offset: 0, Ecosystem: null, Search: "LEFT-PAD"));
        Assert.Equal(1, byUpperTotal);
        Assert.Equal("left-pad", Assert.Single(byUpper).Name);

        // Substring, not prefix: 'library/nginx' carries a repository prefix the user does not
        // type, the same shape as an npm scope or a Maven groupId. A prefix-anchored pattern
        // returns nothing for 'nginx'.
        var (byMidName, byMidNameTotal) = await packages.ListPaginatedAsync(
            new PackageListQuery(OrgId, Limit: 50, Offset: 0, Ecosystem: null, Search: "nginx"));
        Assert.Equal(1, byMidNameTotal);
        Assert.Equal("library/nginx", Assert.Single(byMidName).Name);

        // ── PackageRepository.ListPaginatedAsync — aggregate sort (FullCteSqlFor) ──
        var (byVulns, byVulnsTotal) = await packages.ListPaginatedAsync(
            new PackageListQuery(OrgId, Limit: 50, Offset: 0, Ecosystem: null, SortBy: "vulns", SortDir: "desc"));
        Assert.Equal(3, byVulnsTotal);
        // proxied-pkg carries the CRITICAL cache_artifact vuln (weight 1000), left-pad the HIGH
        // package_version vuln (weight 100), library/nginx none — exercising the previously
        // unaliased CriticalCount/HighCount/MediumCount/LowCount derived tables on both planes.
        Assert.Equal(["proxied-pkg", "left-pad", "library/nginx"], byVulns.Select(p => p.Name));
        Assert.Equal(1, byVulns.Single(p => p.Name == "proxied-pkg").CriticalCount);
        Assert.Equal(1, byVulns.Single(p => p.Name == "left-pad").HighCount);

        // ── LicenseRepository.GetReviewQueueAsync ───────────────────────────
        var normalizer = new LicenseNormalizer(store, NullLogger<LicenseNormalizer>.Instance);
        var licenseRepo = new LicenseRepository(store, clock, normalizer);
        var reviewQueue = await licenseRepo.GetReviewQueueAsync(OrgId, includeDeprecated: false);
        Assert.Contains(reviewQueue, e => e.LicenseSpdx == "MIT");
        Assert.Contains(reviewQueue, e => e.LicenseSpdx == "Apache-2.0");

        // ── ArtifactInventoryRepository ──────────────────────────────────────
        var cacheArtifacts = new CacheArtifactRepository(store);
        var inventory = new ArtifactInventoryRepository(store, packages, cacheArtifacts, vulns);

        Assert.Equal(TotalStorageBytes, await inventory.ComputeStorageBytesAsync(OrgId));

        var hostedOnly = await inventory.ListServeableVersionsAsync(OrgId, "p1", "npm", "left-pad");
        Assert.Equal("1.0.0", Assert.Single(hostedOnly).Version);

        var proxiedOnly = await inventory.ListServeableVersionsAsync(OrgId, "p3", "npm", "proxied-pkg");
        Assert.Equal("2.0.0", Assert.Single(proxiedOnly).Version);

        // ── InviteRepository — upsert against a partial unique index ────────
        // CreateAsync names idx_invites_unique_pending as its conflict target
        // (ON CONFLICT (org_id, email) WHERE accepted_at IS NULL). Postgres has to infer the
        // partial index from that predicate; a mismatch is a runtime error SQLite never raises.
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO users (id, tenant_id, email, password_hash) VALUES ('u1', @OrgId, 'inviter@smoke.test', 'x')",
                new { OrgId });
        }

        var invites = new InviteRepository(store, clock);
        Assert.NotNull(await invites.CreateAsync(OrgId, "invitee@smoke.test", "u1"));
        Assert.True(await invites.HasPendingAsync(OrgId, "invitee@smoke.test"));
        // Second create for the same pending address resolves to a zero-row no-op, not an error.
        Assert.Null(await invites.CreateAsync(OrgId, "invitee@smoke.test", "u1"));
        Assert.Single(await invites.ListAsync(OrgId));
        // A different address in the same tenant is unaffected by the conflict target.
        Assert.NotNull(await invites.CreateAsync(OrgId, "other@smoke.test", "u1"));
        Assert.False(await invites.HasPendingAsync(OrgId, "absent@smoke.test"));

        // ── Direct SELECT from each canonical view ──────────────────────────
        await using (var conn = await store.OpenAsync())
        {
            long inventoryRows = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM artifact_inventory WHERE org_id = @OrgId", new { OrgId });
            Assert.Equal(5, inventoryRows);

            long licenseRows = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM artifact_license WHERE org_id = @OrgId", new { OrgId });
            Assert.Equal(2, licenseRows);

            long storageBytes = await conn.ExecuteScalarAsync<long>(
                "SELECT total_bytes FROM org_storage_bytes WHERE org_id = @OrgId", new { OrgId });
            Assert.Equal(TotalStorageBytes, storageBytes);
        }
    }

    /// <summary>
    /// Seeds every artifact shape a tenant can hold: a hosted npm version, a proxied npm version
    /// whose (ecosystem, name) matches a <c>packages</c> row, a proxied npm artifact with no
    /// matching row at all, a pushed OCI image (catalogued in <c>package_versions</c>, keyed by
    /// manifest digest), a proxied OCI image (catalogued in <c>cache_artifact</c>), and a bare
    /// by-digest OCI layer that casts no catalogue row in either plane — plus a license and a
    /// vulnerability on each of the two non-OCI planes.
    /// </summary>
    private static async Task SeedEveryArtifactShapeAsync(NpgsqlMetadataStore store)
    {
        await using var conn = await store.OpenAsync();
        string now = TestTime.KnownNow.ToUtcIso();

        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@OrgId, 'smoke-org')", new { OrgId });
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id) VALUES (@OrgId)", new { OrgId });

        // p1: hosted npm package/version. p2: pushed OCI image. p3: a proxy-target marker package
        // whose (ecosystem, purl_name) matches ca1, so ca1 exercises the LEFT JOIN's
        // matched-package_id path while ca2 exercises the no-match (NULL package_id) path.
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) VALUES
              ('p1', @OrgId, 'npm', 'left-pad',       'left-pad',       0),
              ('p2', @OrgId, 'oci', 'library/nginx',  'library/nginx',  0),
              ('p3', @OrgId, 'npm', 'proxied-pkg',     'proxied-pkg',    1)
            """,
            new { OrgId });

        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key, size_bytes, origin, versions_behind)
            VALUES
              ('v1', 'p1', '1.0.0',      'pkg:npm/left-pad@1.0.0',            'npm/registry/left-pad/1.0.0/left-pad-1.0.0.tgz', @HostedNpmBytes,       'uploaded', 7),
              ('v2', 'p2', 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                                          'pkg:oci/nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                                                                              'oci/sha256/aaaa',                                 @OciManifestPushedBytes, 'uploaded', NULL)
            """,
            new { HostedNpmBytes, OciManifestPushedBytes });

        // ca1: proxied npm version matched by p3 above. ca2: proxied npm artifact with no
        // matching packages row at all. ca3: proxied OCI image.
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes, versions_behind)
            VALUES
              ('ca1', 'npm', 'proxied-pkg', '2.0.0',
                  'proxied-pkg-2.0.0.tgz', 'proxy/ca1', 'hash-ca1', @ProxiedNpmMatchedBytes, 6),
              ('ca2', 'npm', 'orphan-pkg', '3.0.0',
                  'orphan-pkg-3.0.0.tgz',  'proxy/ca2', 'hash-ca2', @ProxiedNpmOrphanBytes, NULL),
              ('ca3', 'oci', 'library/redis',
                  'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'manifest.json',
                  'proxy/ca3', 'hash-ca3', @OciManifestProxiedBytes, NULL)
            """,
            new { ProxiedNpmMatchedBytes, ProxiedNpmOrphanBytes, OciManifestProxiedBytes });

        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES
              (@OrgId, 'ca1'), (@OrgId, 'ca2'), (@OrgId, 'ca3')
            """,
            new { OrgId });

        // OCI blobs: the pushed image's manifest/config/layer, the proxied image's
        // manifest/layer, and a standalone by-digest layer with no catalogue row anywhere.
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, blob_key, size_bytes, media_type) VALUES
              ('sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', @OrgId, 'oci/sha256/aaaa', @OciManifestPushedBytes, 'application/vnd.oci.image.manifest.v1+json'),
              ('sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', @OrgId, 'oci/sha256/cccc', @OciConfigPushedBytes,   'application/vnd.oci.image.config.v1+json'),
              ('sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', @OrgId, 'oci/sha256/dddd', @OciLayerPushedBytes,    'application/vnd.oci.image.layer.v1.tar+gzip'),
              ('sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', @OrgId, 'oci/sha256/bbbb', @OciManifestProxiedBytes, 'application/vnd.oci.image.manifest.v1+json'),
              ('sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', @OrgId, 'oci/sha256/eeee', @OciLayerProxiedBytes,    'application/vnd.oci.image.layer.v1.tar+gzip'),
              ('sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', @OrgId, 'oci/sha256/ffff', @OciByDigestLayerBytes,   'application/vnd.oci.image.layer.v1.tar+gzip')
            """,
            new
            {
                OrgId,
                OciManifestPushedBytes,
                OciConfigPushedBytes,
                OciLayerPushedBytes,
                OciManifestProxiedBytes,
                OciLayerProxiedBytes,
                OciByDigestLayerBytes,
            });

        // One license on each of the two non-OCI planes.
        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_licenses (id, package_version_id, license_spdx, source, owner_kind)
            VALUES ('pvl1', 'v1', 'MIT', 'upstream', 'package_version')
            """);
        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_licenses (id, cache_artifact_id, license_spdx, source, owner_kind)
            VALUES ('pvl2', 'ca1', 'Apache-2.0', 'upstream', 'cache_artifact')
            """);

        // One vulnerability on each of the two non-OCI planes, checked "now" so all three
        // NewVulns windows (day/week/month) count both.
        await conn.ExecuteAsync(
            """
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity, cvss_score)
            VALUES
              ('vuln1', 'GHSA-smoke-0001', 'npm', 'left-pad', 'HIGH', 7.5),
              ('vuln2', 'GHSA-smoke-0002', 'npm', 'proxied-pkg', 'CRITICAL', 9.8)
            """);
        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_vulns (id, package_version_id, vuln_id, owner_kind, checked_at)
            VALUES ('pvv1', 'v1', 'vuln1', 'package_version', @now)
            """,
            new { now });
        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_vulns (id, cache_artifact_id, vuln_id, owner_kind, checked_at)
            VALUES ('pvv2', 'ca1', 'vuln2', 'cache_artifact', @now)
            """,
            new { now });
    }
}
