using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Integration;

/// <summary>
/// Live-Postgres twin of the alias-fallback coverage in <c>VulnerabilityReportAliasTests</c>. The
/// fallback is correlated-subquery SQL with <c>SUBSTR</c>, <c>TRIM</c> and <c>||</c> inside
/// <c>LIKE</c> patterns, so Postgres earns its own live assertion rather than inheriting SQLite's.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class PostgresVulnReportAliasTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    [Fact]
    public async Task Report_FillsSortsSearchesAndCounts_OnBothPlanes_AgainstLivePostgres()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        string orgId = await OrgSeeder.InsertAsync(store, "pg-alias-org");
        string pkgId = await PackageSeeder.InsertAsync(store, orgId, "pypi", "django");
        string verId = await PackageSeeder.InsertVersionAsync(store, pkgId, "5.0.6", "pkg:pypi/django@5.0.6");
        string ghsaId = await VulnerabilitySeeder.InsertVulnAsync(store, "GHSA-pg-1", "PyPI", "django", "HIGH", 8.7);
        string pysecId = await VulnerabilitySeeder.InsertVulnAsync(
            store, "PYSEC-pg-1", "PyPI", "django", severity: null, cvssScore: null, aliases: "[\"GHSA-pg-1\"]");
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE vulnerabilities SET summary = 'Django SQL injection' WHERE id = @ghsaId", new { ghsaId });
        }

        await VulnerabilitySeeder.LinkAsync(store, verId, ghsaId);
        await VulnerabilitySeeder.LinkAsync(store, verId, pysecId);

        // The cache plane: one proxied artefact reachable by this org and a second org, carrying a
        // GHSA and a PYSEC of its own.
        string otherOrg = await OrgSeeder.InsertAsync(store, "pg-alias-org-2");
        string caId = Guid.NewGuid().ToString("N");
        string ghsaCaId = await VulnerabilitySeeder.InsertVulnAsync(store, "GHSA-pg-2", "PyPI", "flask", "CRITICAL", 9.1);
        string pysecCaId = await VulnerabilitySeeder.InsertVulnAsync(
            store, "PYSEC-pg-2", "PyPI", "flask", severity: null, cvssScore: null, aliases: "[\"GHSA-pg-2\"]");
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes, purl)
                VALUES (@caId, 'pypi', 'flask', '3.0.0', 'flask.whl', @blobKey, @hash, 0, 'pkg:pypi/flask@3.0.0')
                """,
                new { caId, blobKey = $"proxy/pypi/flask/3.0.0/{caId}", hash = $"sha256:{caId}" });
            foreach (string org in new[] { orgId, otherOrg })
            {
                await conn.ExecuteAsync(
                    "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@org, @caId)",
                    new { org, caId });
            }
        }

        await VulnerabilitySeeder.LinkToCacheArtifactAsync(store, caId, ghsaCaId);
        await VulnerabilitySeeder.LinkToCacheArtifactAsync(store, caId, pysecCaId);

        var repo = new VulnerabilityRepository(store, TimeProvider.System);
        var (items, total) = await repo.GetVulnReportAsync(new VulnReportQuery(orgId, Sort: "score", Dir: "desc"));
        Assert.Equal(4, total);
        Assert.DoesNotContain(items, i => i.Severity is null);
        Assert.Equal(9.1, items.Single(i => i.OsvId == "PYSEC-pg-2").CvssScore);
        Assert.Equal(8.7, items.Single(i => i.OsvId == "PYSEC-pg-1").CvssScore);

        var (searched, searchedTotal) = await repo.GetVulnReportAsync(new VulnReportQuery(orgId, Search: "sql injection"));
        Assert.Equal(2, searchedTotal);
        Assert.Equal(2, searched.Count);

        var summary = await repo.GetVulnSummaryAsync(orgId, CancellationToken.None);
        Assert.DoesNotContain(summary.Rows, r => r.Severity is null);
        var instanceWide = await repo.GetVulnSummaryAsync(null, CancellationToken.None);
        Assert.DoesNotContain(instanceWide.Rows, r => r.Severity is null);
    }

    [Fact]
    public async Task ResolvedDonorValues_AnswerTheSameAsTheFallback_AgainstLivePostgres()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        string orgId = await OrgSeeder.InsertAsync(store, "pg-resolve-org");
        string pkgId = await PackageSeeder.InsertAsync(store, orgId, "pypi", "django");
        string verId = await PackageSeeder.InsertVersionAsync(store, pkgId, "5.0.6", "pkg:pypi/django@5.0.6");
        string ghsaId = await VulnerabilitySeeder.InsertVulnAsync(store, "GHSA-pg-r1", "PyPI", "django", "HIGH", 8.7);
        string pysecId = await VulnerabilitySeeder.InsertVulnAsync(
            store, "PYSEC-pg-r1", "PyPI", "django", severity: null, cvssScore: null, aliases: "[\"GHSA-pg-r1\"]");
        string sameDbId = await VulnerabilitySeeder.InsertVulnAsync(
            store, "GHSA-pg-r2", "PyPI", "django", severity: null, cvssScore: null, aliases: "[\"GHSA-pg-r1\"]");
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE vulnerabilities SET summary = 'Django SQL injection' WHERE id = @ghsaId", new { ghsaId });
        }

        // Direct inserts leave the links unresolved, so the first report is the query's own donor lookup.
        foreach (string vulnId in new[] { ghsaId, pysecId, sameDbId })
        {
            await VulnerabilitySeeder.LinkAsync(store, verId, vulnId);
        }

        var repo = new VulnerabilityRepository(store, TimeProvider.System);
        var (fallbackItems, fallbackTotal) = await repo.GetVulnReportAsync(new VulnReportQuery(orgId, Search: "sql injection"));
        var fallbackSummary = await repo.GetVulnSummaryAsync(null, CancellationToken.None);

        await using (var conn = await store.OpenAsync())
        {
            Assert.Equal(3, await VulnerabilityRepository.ResolveStaleAliasDonorsAsync(conn, TimeProvider.System));
            Assert.Equal(3L, await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM package_version_vulns WHERE alias_resolved_at IS NOT NULL"));
            Assert.Equal("HIGH", await conn.ExecuteScalarAsync<string>(
                "SELECT alias_severity FROM package_version_vulns WHERE vuln_id = @pysecId", new { pysecId }));
            Assert.Null(await conn.ExecuteScalarAsync<string?>(
                "SELECT alias_severity FROM package_version_vulns WHERE vuln_id = @sameDbId", new { sameDbId }));
        }

        var (resolvedItems, resolvedTotal) = await repo.GetVulnReportAsync(new VulnReportQuery(orgId, Search: "sql injection"));
        Assert.Equal(fallbackTotal, resolvedTotal);
        Assert.Equal(
            fallbackItems.OrderBy(i => i.OsvId).Select(i => (i.OsvId, i.Severity, i.CvssScore, i.Summary)),
            resolvedItems.OrderBy(i => i.OsvId).Select(i => (i.OsvId, i.Severity, i.CvssScore, i.Summary)));
        Assert.Equal(fallbackSummary.Rows, (await repo.GetVulnSummaryAsync(null, CancellationToken.None)).Rows);

        // A write after the sweep keeps the columns current: the donor's severity changes.
        await repo.UpsertVulnerabilityAsync(
            new Dependably.Protocol.OsvAdvisory("GHSA-pg-r1", ["GHSA-pg-r1"], "Django SQL injection", "CRITICAL", 9.9,
                [], "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", IsHydrated: true),
            "PyPI", "django");
        await using var check = await store.OpenAsync();
        Assert.Equal("CRITICAL", await check.ExecuteScalarAsync<string>(
            "SELECT alias_severity FROM package_version_vulns WHERE vuln_id = @pysecId", new { pysecId }));
    }

    [Fact]
    public async Task CachePeerDonorAndStaleSweep_BehaveTheSame_AgainstLivePostgres()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();
        string orgId = await OrgSeeder.InsertAsync(store, "pg-peer-org");
        var repo = new VulnerabilityRepository(store, TimeProvider.System);
        string[] artifacts = new string[2];
        await using (var conn = await store.OpenAsync())
        {
            for (int i = 0; i < 2; i++)
            {
                artifacts[i] = Guid.NewGuid().ToString("N");
                await conn.ExecuteAsync(
                    """
                    INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes, purl)
                    VALUES (@id, 'pypi', 'flask', '3.0.0', @file, @blobKey, @id, 0, 'pkg:pypi/flask@3.0.0')
                    """,
                    new { id = artifacts[i], file = $"flask-{i}.bin", blobKey = $"proxy/{artifacts[i]}" });
            }

            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @id)",
                new { orgId, id = artifacts[1] });
        }

        string pysec = await repo.UpsertVulnerabilityAsync(
            new Dependably.Protocol.OsvAdvisory("PYSEC-peer", ["GHSA-peer"], null, null, null, [], null, null, IsHydrated: true), "PyPI", "flask");
        string ghsa = await repo.UpsertVulnerabilityAsync(
            new Dependably.Protocol.OsvAdvisory("GHSA-peer", [], "peer summary", "HIGH", 8.1, [], null, null, IsHydrated: true), "PyPI", "flask");
        await repo.LinkCacheArtifactVulnAsync(artifacts[1], pysec);
        await repo.LinkCacheArtifactVulnAsync(artifacts[0], ghsa);

        var (items, _) = await repo.GetVulnReportAsync(new VulnReportQuery(orgId));
        Assert.Equal("HIGH", Assert.Single(items).Severity);

        // A donor edit the previous release made: only fetched_at moves. The sweep picks it up.
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE vulnerabilities SET severity = 'CRITICAL', cvss_score = 9.9, fetched_at = @now WHERE osv_id = 'GHSA-peer'",
                new { now = TimeProvider.System.GetUtcNow().ToUtcIso() });
        }

        Assert.True(await repo.ReconcileAliasDonorsAsync() >= 1);
        (items, _) = await repo.GetVulnReportAsync(new VulnReportQuery(orgId));
        Assert.Equal(9.9, Assert.Single(items).CvssScore);
    }
}
