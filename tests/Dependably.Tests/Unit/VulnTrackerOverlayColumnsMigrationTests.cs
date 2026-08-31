using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Data.Sqlite;

namespace Dependably.Tests.Unit;

/// <summary>
/// The tracker enrichment-overlay columns on <c>vulnerabilities</c>: the NVD band/score, the three
/// SSVC decision points, and two stamps per signal class. Covers what the static schema-parity and
/// temporal-CHECK gates cannot — that the vocabularies actually reject a bad value on a fresh
/// install, that <c>NONE</c> is admitted where the OSV-derived <c>severity</c> column refuses it,
/// and that an existing database gains all nine columns through the additive ALTER path.
/// </summary>
[Trait("Category", "Unit")]
public sealed class VulnTrackerOverlayColumnsMigrationTests : IAsyncLifetime
{
    private static readonly string[] OverlayColumns =
    [
        "nvd_severity", "nvd_score", "nvd_checked_at", "nvd_asserted_at",
        "ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact",
        "ssvc_checked_at", "ssvc_asserted_at",
    ];

    // Second installment: malicious-package live-status, exploit-code observation, and the
    // cvelistV5 CVSS/CWE/SSVC overlay. Covered by a separate list (rather than folded into
    // OverlayColumns) so a failure names precisely which installment regressed.
    //
    // mal_still_live_for_version is DELIBERATELY not in this list — it does not live on
    // vulnerabilities at all. See PackageVersionVulnsMalStillLiveColumnTests below.
    private static readonly string[] SecondInstallmentColumns =
    [
        "mal_compromised_versions", "mal_version_compromised", "mal_still_live",
        "mal_live_checked_at", "mal_live_versions",
        "exploit_code_exists", "exploit_code_max_weight", "exploit_code_sources",
        "cvelist_cvss_score", "cvelist_cvss_severity", "cvelist_cvss_provenance", "cvelist_cwes",
        "cvelist_ssvc_exploitation", "cvelist_ssvc_automatable", "cvelist_ssvc_technical_impact",
        "cvelist_checked_at",
    ];

    private readonly TestMetadataStore _db = new();
    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static async Task SeedAdvisoryAsync(System.Data.Common.DbConnection conn, string id) =>
        await conn.ExecuteAsync(
            "INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name) "
            + "VALUES (@id, @id, 'npm', 'left-pad')",
            new { id });

    [Fact]
    public async Task FreshSchema_DeclaresEveryOverlayColumn()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();

        var columns = (await conn.QueryAsync<string>(
            "SELECT name FROM pragma_table_info('vulnerabilities')")).ToHashSet();

        foreach (string column in OverlayColumns)
        {
            Assert.Contains(column, columns);
        }

        foreach (string column in SecondInstallmentColumns)
        {
            Assert.Contains(column, columns);
        }
    }

    [Fact]
    public async Task FreshSchema_AcceptsACompleteSecondInstallmentEnrichmentRow()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await SeedAdvisoryAsync(conn, "v-mal-ok");

        await conn.ExecuteAsync(
            """
            UPDATE vulnerabilities SET
                mal_compromised_versions = '["1.0.0","1.0.1"]',
                mal_version_compromised = 1,
                mal_still_live = 1,
                mal_live_checked_at = '2026-08-23T00:00:00Z',
                mal_live_versions = '["1.0.0"]',
                exploit_code_exists = 1,
                exploit_code_max_weight = 5,
                exploit_code_sources = '["metasploit"]',
                cvelist_cvss_score = 7.4,
                cvelist_cvss_severity = 'HIGH',
                cvelist_cvss_provenance = 'cna',
                cvelist_cwes = '["CWE-79"]',
                cvelist_ssvc_exploitation = 'active',
                cvelist_ssvc_automatable = 'yes',
                cvelist_ssvc_technical_impact = 'total',
                cvelist_checked_at = '2026-08-23T00:00:00Z'
            WHERE id = 'v-mal-ok'
            """);

        Assert.Equal("HIGH", await conn.ExecuteScalarAsync<string>(
            "SELECT cvelist_cvss_severity FROM vulnerabilities WHERE id = 'v-mal-ok'"));
    }

    [Theory]
    [InlineData("cvelist_cvss_severity", "BOGUS")]
    [InlineData("cvelist_cvss_severity", "high")]              // vocabulary is upper-case, same as nvd_severity
    [InlineData("cvelist_ssvc_exploitation", "Active")]        // vocabulary is lower-case, same as ssvc_exploitation
    [InlineData("cvelist_ssvc_automatable", "true")]
    [InlineData("cvelist_ssvc_technical_impact", "complete")]
    public async Task FreshSchema_RejectsASecondInstallmentValueOutsideTheVocabulary(string column, string value)
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await SeedAdvisoryAsync(conn, "v-mal-bad");

        var ex = await Assert.ThrowsAsync<SqliteException>(() => conn.ExecuteAsync(
            $"UPDATE vulnerabilities SET {column} = @value WHERE id = 'v-mal-bad'", new { value }));
        Assert.Contains("CHECK", ex.Message);
    }

    [Theory]
    [InlineData("mal_version_compromised")]
    [InlineData("mal_still_live")]
    [InlineData("exploit_code_exists")]
    public async Task FreshSchema_RejectsANonBooleanIntegerOnTheTriStateOrFlagColumns(string column)
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await SeedAdvisoryAsync(conn, "v-mal-bool");

        var ex = await Assert.ThrowsAsync<SqliteException>(() => conn.ExecuteAsync(
            $"UPDATE vulnerabilities SET {column} = 2 WHERE id = 'v-mal-bool'"));
        Assert.Contains("CHECK", ex.Message);
    }

    [Fact]
    public async Task FreshSchema_DefaultsTheExploitFlagColumnToFalse_NeverNull()
    {
        // exploit_code_exists is NOT NULL DEFAULT 0 — unlike the nullable tri-state pass-through
        // columns beside it, a row that has never been enriched must read as a definite "no", not
        // "unknown". (mal_still_live_for_version has the identical NOT NULL DEFAULT 0 discipline,
        // but on package_version_vulns — see PackageVersionVulnsMalStillLiveColumnTests.)
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await SeedAdvisoryAsync(conn, "v-mal-default");

        Assert.Equal(0L, await conn.ExecuteScalarAsync<long>(
            "SELECT exploit_code_exists FROM vulnerabilities WHERE id = 'v-mal-default'"));
    }

    [Theory]
    [InlineData("mal_live_checked_at")]
    [InlineData("cvelist_checked_at")]
    public async Task FreshSchema_RejectsASecondInstallmentNonCanonicalTimestamp(string column)
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await SeedAdvisoryAsync(conn, "v-mal-ts");

        var ex = await Assert.ThrowsAsync<SqliteException>(() => conn.ExecuteAsync(
            $"UPDATE vulnerabilities SET {column} = '2026-08-23 00:00:00+00' WHERE id = 'v-mal-ts'"));
        Assert.Contains("CHECK", ex.Message);

        await conn.ExecuteAsync(
            $"UPDATE vulnerabilities SET {column} = '2026-08-23T00:00:00Z' WHERE id = 'v-mal-ts'");
        Assert.Equal("2026-08-23T00:00:00Z", await conn.ExecuteScalarAsync<string>(
            $"SELECT {column} FROM vulnerabilities WHERE id = 'v-mal-ts'"));
    }

    [Fact]
    public async Task FreshSchema_AcceptsACompleteEnrichmentRow()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await SeedAdvisoryAsync(conn, "v-ok");

        await conn.ExecuteAsync(
            """
            UPDATE vulnerabilities SET
                nvd_severity = 'HIGH', nvd_score = 8.1,
                nvd_checked_at = '2026-08-23T00:00:00Z', nvd_asserted_at = '2026-08-22T00:00:00Z',
                ssvc_exploitation = 'active', ssvc_automatable = 'yes',
                ssvc_technical_impact = 'total',
                ssvc_checked_at = '2026-08-23T00:00:00Z', ssvc_asserted_at = '2026-08-22T00:00:00Z'
            WHERE id = 'v-ok'
            """);

        string? band = await conn.ExecuteScalarAsync<string>(
            "SELECT nvd_severity FROM vulnerabilities WHERE id = 'v-ok'");
        Assert.Equal("HIGH", band);
    }

    [Fact]
    public async Task FreshSchema_AdmitsTheNoneBand_WhichTheOsvSeverityColumnRefuses()
    {
        // The deliberate divergence: NVD assigns NONE to a 0.0 base score, so refusing it would
        // fail the enrichment write rather than record the band the source publishes. The second
        // half is the twin — it proves the value set genuinely differs from the neighbouring
        // column's rather than both having been widened by accident.
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await SeedAdvisoryAsync(conn, "v-none");

        await conn.ExecuteAsync(
            "UPDATE vulnerabilities SET nvd_severity = 'NONE' WHERE id = 'v-none'");
        Assert.Equal("NONE", await conn.ExecuteScalarAsync<string>(
            "SELECT nvd_severity FROM vulnerabilities WHERE id = 'v-none'"));

        var ex = await Assert.ThrowsAsync<SqliteException>(() => conn.ExecuteAsync(
            "UPDATE vulnerabilities SET severity = 'NONE' WHERE id = 'v-none'"));
        Assert.Contains("CHECK", ex.Message);
    }

    [Theory]
    [InlineData("nvd_severity", "BOGUS")]
    [InlineData("nvd_severity", "high")]                 // vocabulary is upper-case
    [InlineData("ssvc_exploitation", "Active")]          // vocabulary is lower-case
    [InlineData("ssvc_exploitation", "exploited")]
    [InlineData("ssvc_automatable", "true")]
    [InlineData("ssvc_technical_impact", "complete")]
    public async Task FreshSchema_RejectsAValueOutsideTheVocabulary(string column, string value)
    {
        // Case matters in both directions here, and the two vocabularies disagree on it: NVD
        // bands are upper-case, SSVC decision points lower-case. A CHECK that quietly accepted
        // either casing would let two spellings of one fact into the same column.
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await SeedAdvisoryAsync(conn, "v-bad");

        var ex = await Assert.ThrowsAsync<SqliteException>(() => conn.ExecuteAsync(
            $"UPDATE vulnerabilities SET {column} = @value WHERE id = 'v-bad'", new { value }));
        Assert.Contains("CHECK", ex.Message);
    }

    [Theory]
    [InlineData("nvd_checked_at")]
    [InlineData("nvd_asserted_at")]
    [InlineData("ssvc_checked_at")]
    [InlineData("ssvc_asserted_at")]
    public async Task FreshSchema_RejectsANonCanonicalTimestamp(string column)
    {
        // Both stamps per signal class carry the canonical-UTC CHECK, not just the local one.
        // The producer-asserted stamp arrives from outside this system, which is precisely why
        // it needs the constraint rather than being trusted to be well-shaped.
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await SeedAdvisoryAsync(conn, "v-ts");

        var ex = await Assert.ThrowsAsync<SqliteException>(() => conn.ExecuteAsync(
            $"UPDATE vulnerabilities SET {column} = '2026-08-23 00:00:00+00' WHERE id = 'v-ts'"));
        Assert.Contains("CHECK", ex.Message);

        // Twin: the canonical shape is accepted, so the rejection above is the format check
        // doing its job rather than the column being unwritable.
        await conn.ExecuteAsync(
            $"UPDATE vulnerabilities SET {column} = '2026-08-23T00:00:00Z' WHERE id = 'v-ts'");
        Assert.Equal("2026-08-23T00:00:00Z", await conn.ExecuteScalarAsync<string>(
            $"SELECT {column} FROM vulnerabilities WHERE id = 'v-ts'"));
    }

    [Fact]
    public async Task ExistingDatabaseWithoutTheColumns_GainsThemAllOnReInit()
    {
        // A database that predates the overlay: drop the table and recreate it without any of the
        // nine columns, then re-run the initializer. The additive ALTER path must add every one —
        // a partial application would leave the enrichment write failing on whichever column was
        // missed, which nothing else here would catch.
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync("DROP TABLE IF EXISTS vulnerabilities");
            await setup.ExecuteAsync(
                """
                CREATE TABLE vulnerabilities (
                    id           TEXT PRIMARY KEY,
                    osv_id       TEXT NOT NULL UNIQUE,
                    ecosystem    TEXT NOT NULL,
                    package_name TEXT NOT NULL
                )
                """);
            await SeedAdvisoryAsync(setup, "v-legacy");

            var columns = (await setup.QueryAsync<string>(
                "SELECT name FROM pragma_table_info('vulnerabilities')")).ToHashSet();
            Assert.DoesNotContain("nvd_severity", columns);
        }

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        var after = (await conn.QueryAsync<string>(
            "SELECT name FROM pragma_table_info('vulnerabilities')")).ToHashSet();
        foreach (string column in OverlayColumns)
        {
            Assert.Contains(column, after);
        }

        foreach (string column in SecondInstallmentColumns)
        {
            Assert.Contains(column, after);
        }

        // The pre-existing row survives with the overlay unset, which is the correct unenriched
        // state — no backfill, and nothing for a gate arm to read differently.
        string? band = await conn.ExecuteScalarAsync<string>(
            "SELECT nvd_severity FROM vulnerabilities WHERE id = 'v-legacy'");
        Assert.Null(band);

        // The NOT NULL DEFAULT column lands as a definite false on the ALTER path too, not NULL —
        // SQLite's ADD COLUMN honours a literal DEFAULT for existing rows.
        Assert.Equal(0L, await conn.ExecuteScalarAsync<long>(
            "SELECT exploit_code_exists FROM vulnerabilities WHERE id = 'v-legacy'"));
    }
}

/// <summary>
/// The version-precise <c>package_version_vulns.mal_still_live_for_version</c> column —
/// deliberately NOT on <c>vulnerabilities</c> (see that table's own schema comment): "is this
/// version still live" is a fact about the (advisory, version) PAIR, not the advisory alone, so it
/// lives on the table that is already the version-precise link between one owner and one advisory.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PackageVersionVulnsMalStillLiveColumnTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static async Task<string> SeedAdvisoryAsync(System.Data.Common.DbConnection conn, string id)
    {
        await conn.ExecuteAsync(
            "INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name) "
            + "VALUES (@id, @id, 'npm', 'left-pad')",
            new { id });
        return id;
    }

    /// <summary>Seeds a global cache_artifact row so a package_version_vulns row has an owner
    /// with no per-org plumbing needed — mirrors the 'cache_artifact' arm's own shape.</summary>
    private static async Task<string> SeedCacheArtifactAsync(System.Data.Common.DbConnection conn, string name)
    {
        string id = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes, purl)
            VALUES (@id, 'npm', @name, '1.0.0', @filename, @blobKey, @hash, 0, @purl)
            """,
            new
            {
                id,
                name,
                filename = $"{name}-1.0.0.tgz",
                blobKey = $"proxy/npm/{name}/1.0.0/{name}-1.0.0.tgz",
                hash = $"sha256:{Guid.NewGuid():N}",
                purl = $"pkg:npm/{name}@1.0.0",
            });
        return id;
    }

    private static async Task<string> SeedLinkAsync(
        System.Data.Common.DbConnection conn, string cacheArtifactId, string vulnId)
    {
        string id = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_vulns (id, cache_artifact_id, vuln_id, owner_kind)
            VALUES (@id, @cacheArtifactId, @vulnId, 'cache_artifact')
            """,
            new { id, cacheArtifactId, vulnId });
        return id;
    }

    [Fact]
    public async Task FreshSchema_DeclaresTheColumn()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();

        var columns = (await conn.QueryAsync<string>(
            "SELECT name FROM pragma_table_info('package_version_vulns')")).ToHashSet();

        Assert.Contains("mal_still_live_for_version", columns);
    }

    [Fact]
    public async Task FreshSchema_DefaultsToFalse_NeverNull()
    {
        // NOT NULL DEFAULT 0 — a link that has never been enriched must read as a definite "no",
        // not "unknown", because MalStillLiveTriggers reads it with no staleness gating.
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        string vulnId = await SeedAdvisoryAsync(conn, "v-link-default");
        string caId = await SeedCacheArtifactAsync(conn, "left-pad-default");
        await SeedLinkAsync(conn, caId, vulnId);

        Assert.Equal(0L, await conn.ExecuteScalarAsync<long>(
            "SELECT mal_still_live_for_version FROM package_version_vulns WHERE vuln_id = @vulnId",
            new { vulnId }));
    }

    [Fact]
    public async Task FreshSchema_AcceptsAndPersistsATrueValue()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        string vulnId = await SeedAdvisoryAsync(conn, "v-link-true");
        string caId = await SeedCacheArtifactAsync(conn, "left-pad-true");
        await SeedLinkAsync(conn, caId, vulnId);

        await conn.ExecuteAsync(
            "UPDATE package_version_vulns SET mal_still_live_for_version = 1 WHERE vuln_id = @vulnId",
            new { vulnId });

        Assert.Equal(1L, await conn.ExecuteScalarAsync<long>(
            "SELECT mal_still_live_for_version FROM package_version_vulns WHERE vuln_id = @vulnId",
            new { vulnId }));
    }

    [Fact]
    public async Task FreshSchema_RejectsANonBooleanInteger()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        string vulnId = await SeedAdvisoryAsync(conn, "v-link-bad");
        string caId = await SeedCacheArtifactAsync(conn, "left-pad-bad");
        await SeedLinkAsync(conn, caId, vulnId);

        var ex = await Assert.ThrowsAsync<SqliteException>(() => conn.ExecuteAsync(
            "UPDATE package_version_vulns SET mal_still_live_for_version = 2 WHERE vuln_id = @vulnId",
            new { vulnId }));
        Assert.Contains("CHECK", ex.Message);
    }

    [Fact]
    public async Task ExistingDatabaseWithoutTheColumn_GainsItOnReInit()
    {
        // A database that predates the column: drop and recreate package_version_vulns without
        // it, then re-run the initializer. The additive ALTER path must add it back, landing the
        // NOT NULL DEFAULT 0 even on a pre-existing link row.
        await new SchemaInitializer(_db).InitializeAsync();
        string vulnId;
        string caId;
        await using (var setup = await _db.OpenAsync())
        {
            vulnId = await SeedAdvisoryAsync(setup, "v-link-legacy");
            caId = await SeedCacheArtifactAsync(setup, "left-pad-legacy");

            await setup.ExecuteAsync("DROP TABLE IF EXISTS package_version_vulns");
            await setup.ExecuteAsync(
                """
                CREATE TABLE package_version_vulns (
                    id                 TEXT PRIMARY KEY,
                    package_version_id TEXT,
                    vuln_id            TEXT NOT NULL,
                    checked_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                    first_seen_at      TEXT,
                    cache_artifact_id  TEXT,
                    owner_kind         TEXT NOT NULL DEFAULT 'package_version'
                )
                """);
            await SeedLinkAsync(setup, caId, vulnId);

            var columns = (await setup.QueryAsync<string>(
                "SELECT name FROM pragma_table_info('package_version_vulns')")).ToHashSet();
            Assert.DoesNotContain("mal_still_live_for_version", columns);
        }

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        var after = (await conn.QueryAsync<string>(
            "SELECT name FROM pragma_table_info('package_version_vulns')")).ToHashSet();
        Assert.Contains("mal_still_live_for_version", after);

        Assert.Equal(0L, await conn.ExecuteScalarAsync<long>(
            "SELECT mal_still_live_for_version FROM package_version_vulns WHERE vuln_id = @vulnId",
            new { vulnId }));
    }
}
