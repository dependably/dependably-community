using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Pins <c>BackfillFindingsFirstSeenAtAsync</c>'s every-boot converge (called unledgered from
/// <c>SchemaInitializer.ApplySchemaAsync</c>, mirroring
/// <c>SchemaInitializer.TimestampNormalization.cs</c>'s reasoning): a row whose
/// <c>first_seen_at</c> is NULL gets it copied from <c>checked_at</c> on ANY boot, not just the
/// first one to see it — the blue-green case a one-shot <c>RunOnceAsync</c> migration cannot
/// cover, because the previous release's <c>LinkVersionVulnAsync</c> /
/// <c>LinkCacheArtifactVulnAsync</c> / <c>LinkComponentVulnAsync</c> keep writing rows with no
/// <c>first_seen_at</c> value for as long as that release is still deployed anywhere in the
/// cutover window — including after this database's converge has already run once.
///
/// Also covers the SQLite recreate-table reshape for <c>package_version_vulns</c>
/// (<c>add_pvv_owner_invariant_check</c>) preserving <c>first_seen_at</c> across the rebuild.
/// Follows the <c>SchemaReshapeSafetyTests</c> idiom: run the real initializer once to get the
/// current shape, then reconstruct the OLD pre-migration DDL and reset that one ledger row so
/// the reshape's detection query actually fires the rebuild body instead of the no-op branch —
/// calling <c>InitializeAsync()</c> once first and stopping there (as opposed to also
/// reconstructing the old shape) would only exercise the no-op branch and prove nothing.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SchemaInitializerFirstSeenAtConvergeTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();
    public async Task DisposeAsync() => await _db.DisposeAsync();

    private async Task ReapplyAsync() => await new SchemaInitializer(_db).InitializeAsync();

    private async Task ResetMigrationAsync(string name)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("DELETE FROM _applied_migrations WHERE name = @name", new { name });
    }

    // A fresh TestMetadataStore gets first_seen_at NOT NULL DEFAULT straight from Schema.sql's
    // CREATE TABLE block (the fresh-install shape), so an explicit NULL insert against it fails
    // the NOT NULL constraint outright. A genuinely upgraded (non-fresh) database never has that
    // constraint — RunAdditiveMigrationsAsync's ADD COLUMN is nullable with no DEFAULT (SQLite
    // rejects a non-constant DEFAULT on a populated table) — so these two helpers reconstruct
    // that upgrade-path shape before a test plants a NULL row, otherwise it would be testing a
    // state no real upgraded database is ever in.
    private async Task MakePvvFirstSeenAtNullableAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("DROP TABLE package_version_vulns");
        await conn.ExecuteAsync("""
            CREATE TABLE package_version_vulns (
                id                  TEXT PRIMARY KEY,
                package_version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
                vuln_id             TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
                checked_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                first_seen_at       TEXT,
                cache_artifact_id   TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
                owner_kind          TEXT NOT NULL DEFAULT 'package_version'
                                    CHECK (owner_kind IN ('package_version','cache_artifact')),
                CHECK (
                    (owner_kind = 'package_version' AND package_version_id IS NOT NULL AND cache_artifact_id IS NULL)
                    OR
                    (owner_kind = 'cache_artifact' AND cache_artifact_id IS NOT NULL AND package_version_id IS NULL)
                )
            )
            """);
        await conn.ExecuteAsync("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_pvv_pv_vuln
                ON package_version_vulns (package_version_id, vuln_id)
                WHERE owner_kind = 'package_version'
            """);
        await conn.ExecuteAsync("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_pvv_ca_vuln
                ON package_version_vulns (cache_artifact_id, vuln_id)
                WHERE owner_kind = 'cache_artifact'
            """);
    }

    private async Task MakeSbomFirstSeenAtNullableAsync()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("DROP TABLE sbom_component_vulns");
        await conn.ExecuteAsync("""
            CREATE TABLE sbom_component_vulns (
                id           TEXT PRIMARY KEY,
                component_id TEXT NOT NULL REFERENCES sbom_components(id) ON DELETE CASCADE,
                vuln_id      TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
                checked_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                first_seen_at TEXT,
                UNIQUE (component_id, vuln_id)
            )
            """);
    }

    // ── (a) old-shaped backlog row: checked_at set, first_seen_at never written ──────────────

    [Fact]
    public async Task PackageVersionVulns_OldShapedRow_ConvergesFirstSeenAtFromCheckedAt()
    {
        string verId = await SeedPackageVersionAsync();
        string vulnId = await SeedVulnerabilityAsync("GHSA-converge-pv-01");
        await MakePvvFirstSeenAtNullableAsync();
        string id = await SeedLinkAsync(verId, vulnId, checkedAt: "2026-01-01T00:00:00Z", firstSeenAt: null);

        await ReapplyAsync();

        await using var conn = await _db.OpenAsync();
        string? firstSeen = await conn.ExecuteScalarAsync<string?>(
            "SELECT first_seen_at FROM package_version_vulns WHERE id = @id", new { id });
        Assert.Equal("2026-01-01T00:00:00Z", firstSeen);
    }

    [Fact]
    public async Task SbomComponentVulns_OldShapedRow_ConvergesFirstSeenAtFromCheckedAt()
    {
        string orgId = await SeedOrgAsync();
        string componentId = await SeedSbomComponentAsync(orgId);
        string vulnId = await SeedVulnerabilityAsync("GHSA-converge-sbom-01");
        await MakeSbomFirstSeenAtNullableAsync();

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO sbom_component_vulns (id, component_id, vuln_id, checked_at, first_seen_at)
                VALUES ('scv-old-01', @componentId, @vulnId, '2026-02-02T00:00:00Z', NULL)
                """,
                new { componentId, vulnId });
        }

        await ReapplyAsync();

        await using var read = await _db.OpenAsync();
        string? firstSeen = await read.ExecuteScalarAsync<string?>(
            "SELECT first_seen_at FROM sbom_component_vulns WHERE id = 'scv-old-01'");
        Assert.Equal("2026-02-02T00:00:00Z", firstSeen);
    }

    // ── (b) blue-green twin: a row written AFTER the converge has already run once ───────────

    [Fact]
    public async Task PackageVersionVulns_RowWrittenAfterFirstConverge_DoesNotStayNull()
    {
        string verId = await SeedPackageVersionAsync();
        string vulnId = await SeedVulnerabilityAsync("GHSA-converge-pv-02");

        // First boot: the converge already ran once against an empty backlog (nothing to do).
        await ReapplyAsync();
        await MakePvvFirstSeenAtNullableAsync();

        // Simulate the OLD (blue) binary writing a NEW row mid-cutover, using its own
        // pre-first_seen_at column list — exactly what an upgraded (non-fresh) database's
        // nullable, no-DEFAULT first_seen_at column leaves behind when the caller never sets it.
        string id = await SeedLinkAsync(verId, vulnId, checkedAt: "2026-03-03T03:03:03Z", firstSeenAt: null);

        // A RunOnceAsync migration would already be ledgered from the first boot above and would
        // never look at this row. The unledgered converge must catch it on this second boot.
        await ReapplyAsync();

        await using var conn = await _db.OpenAsync();
        string? firstSeen = await conn.ExecuteScalarAsync<string?>(
            "SELECT first_seen_at FROM package_version_vulns WHERE id = @id", new { id });
        Assert.NotNull(firstSeen);
        Assert.Equal("2026-03-03T03:03:03Z", firstSeen);
    }

    [Fact]
    public async Task SbomComponentVulns_RowWrittenAfterFirstConverge_DoesNotStayNull()
    {
        string orgId = await SeedOrgAsync();
        string componentId = await SeedSbomComponentAsync(orgId);
        string vulnId = await SeedVulnerabilityAsync("GHSA-converge-sbom-02");

        // First boot: converge already ran once against an empty backlog.
        await ReapplyAsync();
        await MakeSbomFirstSeenAtNullableAsync();

        // Simulate blue's SbomComponentVulnRepository.LinkComponentVulnAsync writing a fresh row
        // mid-cutover with no first_seen_at value.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO sbom_component_vulns (id, component_id, vuln_id, checked_at, first_seen_at)
                VALUES ('scv-bluegreen-01', @componentId, @vulnId, '2026-04-04T04:04:04Z', NULL)
                """,
                new { componentId, vulnId });
        }

        await ReapplyAsync();

        await using var read = await _db.OpenAsync();
        string? firstSeen = await read.ExecuteScalarAsync<string?>(
            "SELECT first_seen_at FROM sbom_component_vulns WHERE id = 'scv-bluegreen-01'");
        Assert.NotNull(firstSeen);
        Assert.Equal("2026-04-04T04:04:04Z", firstSeen);
    }

    // ── (c) reshape parity: add_pvv_owner_invariant_check must not drop first_seen_at ─────────

    [Fact]
    public async Task AddPvvOwnerInvariantCheck_Reshape_PreservesFirstSeenAt()
    {
        await using var conn = await _db.OpenAsync();

        // Reconstruct the shape add_pvv_owner_invariant_check reshapes FROM: has the surrogate id
        // PK and the first_seen_at column (both P0/additive already applied to this database) but
        // NOT YET the owner-invariant CHECK the migration adds. This is the exact _new column set
        // from SchemaInitializer.Reshapes.cs's make_pvv_package_version_id_nullable body, minus
        // the CHECK — i.e. what a database sits at between that reshape and this one.
        await conn.ExecuteAsync("DROP TABLE package_version_vulns");
        await conn.ExecuteAsync("""
            CREATE TABLE package_version_vulns (
                id                  TEXT PRIMARY KEY,
                package_version_id  TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
                vuln_id             TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
                checked_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                first_seen_at       TEXT,
                cache_artifact_id   TEXT REFERENCES cache_artifact(id) ON DELETE CASCADE,
                owner_kind          TEXT NOT NULL DEFAULT 'package_version'
                                    CHECK (owner_kind IN ('package_version','cache_artifact'))
            )
            """);

        // Confirm the reconstruction actually trips detection: the invariant CHECK text must be
        // absent from the stored DDL, matching AddPvvOwnerInvariantCheckSqliteAsync's own probe.
        string? sql = await conn.ExecuteScalarAsync<string?>(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'package_version_vulns'");
        Assert.DoesNotContain("owner_kind = 'package_version' AND", sql);

        string verId = await SeedPackageVersionAsync();
        string vulnId = await SeedVulnerabilityAsync("GHSA-converge-reshape-01");
        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_vulns
                (id, package_version_id, vuln_id, owner_kind, checked_at, first_seen_at)
            VALUES ('pvv-reshape-01', @verId, @vulnId, 'package_version',
                    '2026-05-05T05:05:05Z', '2026-05-05T05:05:05Z')
            """,
            new { verId, vulnId });

        await ResetMigrationAsync("add_pvv_owner_invariant_check");
        await ReapplyAsync();

        // The reshape actually ran (not the no-op branch) — the invariant CHECK is present now.
        string? afterSql = await conn.ExecuteScalarAsync<string?>(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'package_version_vulns'");
        Assert.Contains("owner_kind = 'package_version' AND", afterSql);

        // first_seen_at survived the DROP+recreate with its seeded value intact.
        string? firstSeen = await conn.ExecuteScalarAsync<string?>(
            "SELECT first_seen_at FROM package_version_vulns WHERE id = 'pvv-reshape-01'");
        Assert.Equal("2026-05-05T05:05:05Z", firstSeen);
    }

    // ── seed helpers ───────────────────────────────────────────────────────────────────────

    private async Task<string> SeedOrgAsync()
    {
        string orgId = $"o-{Guid.NewGuid():N}";
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@orgId, @orgId)", new { orgId });
        return orgId;
    }

    private async Task<string> SeedPackageVersionAsync()
    {
        string orgId = await SeedOrgAsync();
        string pkgId = $"pkg-{Guid.NewGuid():N}";
        string verId = $"pv-{Guid.NewGuid():N}";
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES (@pkgId, @orgId, 'npm', 'acme', 'acme', 0)",
            new { pkgId, orgId });
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key) " +
            "VALUES (@verId, @pkgId, '1.0.0', 'pkg:npm/acme@1.0.0', 'npm/registry/acme/1.0.0/acme-1.0.0.tgz')",
            new { verId, pkgId });
        return verId;
    }

    private async Task<string> SeedVulnerabilityAsync(string osvId)
    {
        string id = $"vuln-{Guid.NewGuid():N}";
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name) " +
            "VALUES (@id, @osvId, 'npm', 'acme')",
            new { id, osvId });
        return id;
    }

    private async Task<string> SeedLinkAsync(string verId, string vulnId, string checkedAt, string? firstSeenAt)
    {
        string id = $"pvv-{Guid.NewGuid():N}";
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_vulns
                (id, package_version_id, vuln_id, owner_kind, checked_at, first_seen_at)
            VALUES (@id, @verId, @vulnId, 'package_version', @checkedAt, @firstSeenAt)
            """,
            new { id, verId, vulnId, checkedAt, firstSeenAt });
        return id;
    }

    private async Task<string> SeedSbomComponentAsync(string orgId)
    {
        string projectId = $"proj-{Guid.NewGuid():N}";
        string projectVersionId = $"pver-{Guid.NewGuid():N}";
        string componentId = $"comp-{Guid.NewGuid():N}";
        string purl = "pkg:npm/left-pad@1.3.0";
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name) VALUES (@projectId, @orgId, @name)",
            new { projectId, orgId, name = $"proj-{Guid.NewGuid():N}" });
        await conn.ExecuteAsync(
            "INSERT INTO project_versions (id, org_id, project_id, version) " +
            "VALUES (@projectVersionId, @orgId, @projectId, '1.0.0')",
            new { projectVersionId, orgId, projectId });
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name)
            VALUES
                (@componentId, @orgId, @projectVersionId, @purl, 'npm', 'left-pad', '1.3.0', 'left-pad')
            """,
            new { componentId, orgId, projectVersionId, purl });
        return componentId;
    }
}
