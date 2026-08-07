using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Migration;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end proof of the standalone → HA data move: a SQLite database seeded with rows across the
/// schema's type surface (nullable columns, integer-encoded booleans, ISO-8601 timestamps that land
/// in a Postgres <c>timestamptz</c>, 4-byte <c>real</c>, 8-byte <c>bigint</c>, an autoincrement
/// primary key, and text carrying newlines, quotes and non-ASCII) is copied into a LIVE Postgres,
/// and the round-tripped values are compared value by value — not merely counted. Type fidelity is
/// the whole point: a migration that moves the right number of rows with the wrong values is worse
/// than one that fails.
///
/// <para>Tagged <c>Category=SchemaPostgres</c> like the rest of the live-Postgres suite, so it runs
/// in the <c>schema-integrity</c> CI job that attaches a postgres service and sets
/// <c>TEST_POSTGRES_CONNECTION</c>. Running it without a connection fails loudly rather than
/// skipping silently.</para>
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class SqliteToPostgresMigrationTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    private const string OrgId = "org-migration-src";
    private const string PackageId = "pkg-migration-src";
    private const string VersionId = "pv-migration-src";
    private const string SecondVersionId = "pv-migration-src-2";
    private const string UserId = "user-migration-src";
    private const string DistTagId = "tag-migration-src";

    /// <summary>Text with a newline, a tab, both quote characters, a backslash and non-ASCII.</summary>
    private const string AwkwardText = "naïve\nmulti-line\t中文 \"double\" 'single' back\\slash";

    /// <summary>Second-precision UTC, the form the schema's own timestamp defaults write.</summary>
    private const string SeededTimestamp = "2026-03-04T05:06:07Z";

    private static readonly DateTime ExpectedInstant = new(2026, 3, 4, 5, 6, 7, DateTimeKind.Utc);

    private static async Task<TestMetadataStore> SeededSqliteAsync()
    {
        var db = new TestMetadataStore();
        await new SchemaInitializer(db).InitializeAsync();
        await using var conn = await db.OpenAsync();

        await conn.ExecuteAsync(
            """
            INSERT INTO orgs (id, slug, deleted_at, storage_quota_bytes, created_at)
            VALUES (@OrgId, 'migration-src', NULL, 9007199254740993, @Created)
            """,
            new { OrgId, Created = SeededTimestamp });

        // Integer-encoded booleans, a 4-byte REAL on the Postgres side, and a NULL REAL.
        await conn.ExecuteAsync(
            """
            INSERT INTO org_settings (org_id, anonymous_pull, allowlist_mode, max_osv_score_tolerance,
                                      max_epss_tolerance, keep_versions, maven_reserved_prefixes)
            VALUES (@OrgId, 1, 0, 7.5, NULL, NULL, @Prefixes)
            """,
            new { OrgId, Prefixes = "[\"com.example\"]" });

        await conn.ExecuteAsync(
            """
            INSERT INTO users (id, tenant_id, email, password_hash, role, last_login_at, language, token_version)
            VALUES (@UserId, @OrgId, 'owner@example.test', 'bcrypt$hash', 'owner', @LastLogin, NULL, 4)
            """,
            new { UserId, OrgId, LastLogin = SeededTimestamp });

        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
            VALUES (@PackageId, @OrgId, 'npm', 'migration-pkg', 'migration-pkg', 0)
            """,
            new { PackageId, OrgId });

        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key)
            VALUES (@VersionId, @PackageId, '1.0.0', 'pkg:npm/migration-pkg@1.0.0',
                    'npm/r/migration-pkg/1.0.0/migration-pkg-1.0.0.tgz'),
                   (@SecondVersionId, @PackageId, '1.1.0', 'pkg:npm/migration-pkg@1.1.0',
                    'npm/r/migration-pkg/1.1.0/migration-pkg-1.1.0.tgz')
            """,
            new { VersionId, SecondVersionId, PackageId });

        // TEXT in SQLite, timestamptz in Postgres — the only columns whose storage class differs.
        await conn.ExecuteAsync(
            """
            INSERT INTO npm_dist_tags (id, org_id, package_id, tag, version, created_at, updated_at)
            VALUES (@DistTagId, @OrgId, @PackageId, 'latest', '1.0.0', @Stamp, @Stamp)
            """,
            new { DistTagId, OrgId, PackageId, Stamp = SeededTimestamp });

        await conn.ExecuteAsync(
            """
            INSERT INTO upstream_negative_cache (url_key, ecosystem, fetched_at)
            VALUES ('deadbeefdeadbeefdeadbeefdeadbeef', 'npm', @Stamp)
            """,
            new { Stamp = SeededTimestamp });

        // Autoincrement primary key: two rows (one per version — the table is unique per version),
        // so the target sequence must land past 2.
        await conn.ExecuteAsync(
            """
            INSERT INTO cargo_metadata (version_id, index_line, owner_kind)
            VALUES (@VersionId, @First, 'package_version'),
                   (@SecondVersionId, @Second, 'package_version')
            """,
            new { VersionId, SecondVersionId, First = "{\"name\":\"a\"}", Second = "{\"name\":\"b\"}" });

        await conn.ExecuteAsync(
            "INSERT INTO instance_settings (key, value) VALUES ('migration_probe', @Value)",
            new { Value = AwkwardText });

        await conn.ExecuteAsync(
            "INSERT INTO data_protection_keys (friendly_name, xml) VALUES ('key-1', @Xml)",
            new { Xml = "<key id=\"1\">" + AwkwardText + "</key>" });

        return db;
    }

    private static SqliteToPostgresMigrator Migrator(TestMetadataStore source, IMetadataStore target) =>
        new(source, target);

    [Fact]
    public async Task Migrate_CopiesEveryTable_AndRoundTripsValuesExactly()
    {
        await using var sqlite = await SeededSqliteAsync();
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);

        var result = await Migrator(sqlite, pg.Store).MigrateAsync(new MetadataMigrationOptions());

        Assert.NotNull(result.Verification);
        Assert.True(result.Verification!.Ok,
            "verification reported a difference: " +
            string.Join("; ", result.Verification.Failures.Select(f =>
                $"{f.Table} {f.SourceRows}/{f.TargetRows} {f.SourceDigest} vs {f.TargetDigest}")));
        Assert.Empty(result.SkippedTables);
        Assert.NotEmpty(result.Verification.Tables);

        await using var conn = await pg.Store.OpenAsync();

        // Identity and 8-byte magnitude survive: 2^53+1 is the smallest integer a double cannot hold,
        // so a silent trip through floating point would come back as 9007199254740992.
        Assert.Equal(9007199254740993L, await conn.ExecuteScalarAsync<long>(
            "SELECT storage_quota_bytes FROM orgs WHERE id = @OrgId", new { OrgId }));
        Assert.Null(await conn.ExecuteScalarAsync<string?>(
            "SELECT deleted_at FROM orgs WHERE id = @OrgId", new { OrgId }));

        // Integer-encoded booleans and a 4-byte real; the NULL real stays NULL rather than defaulting.
        var (anonymousPull, allowlistMode, osvTolerance, epssTolerance) =
            await conn.QuerySingleAsync<(int AnonymousPull, int AllowlistMode, float Osv, float? Epss)>(
                """
                SELECT anonymous_pull AS AnonymousPull, allowlist_mode AS AllowlistMode,
                       max_osv_score_tolerance AS Osv, max_epss_tolerance AS Epss
                FROM org_settings WHERE org_id = @OrgId
                """,
                new { OrgId });
        Assert.Equal(1, anonymousPull);
        Assert.Equal(0, allowlistMode);
        Assert.Equal(7.5f, osvTolerance);
        Assert.Null(epssTolerance);

        // ISO-8601 TEXT stays TEXT where the target column is TEXT…
        Assert.Equal(SeededTimestamp, await conn.ExecuteScalarAsync<string>(
            "SELECT last_login_at FROM users WHERE id = @UserId", new { UserId }));
        Assert.Null(await conn.ExecuteScalarAsync<string?>(
            "SELECT language FROM users WHERE id = @UserId", new { UserId }));
        Assert.Equal(4, await conn.ExecuteScalarAsync<int>(
            "SELECT token_version FROM users WHERE id = @UserId", new { UserId }));

        // …and becomes a real instant where the target column is timestamptz.
        var created = await conn.ExecuteScalarAsync<DateTime>(
            "SELECT created_at FROM npm_dist_tags WHERE id = @DistTagId", new { DistTagId });
        Assert.Equal(ExpectedInstant, created.ToUniversalTime());
        var fetched = await conn.ExecuteScalarAsync<DateTime>(
            "SELECT fetched_at FROM upstream_negative_cache WHERE url_key = @Key",
            new { Key = "deadbeefdeadbeefdeadbeefdeadbeef" });
        Assert.Equal(ExpectedInstant, fetched.ToUniversalTime());

        // Text is byte-for-byte, including the newline, tab, quotes, backslash and non-ASCII.
        Assert.Equal(AwkwardText, await conn.ExecuteScalarAsync<string>(
            "SELECT value FROM instance_settings WHERE key = 'migration_probe'"));

        // Foreign-key chains land intact, parents first.
        Assert.Equal(PackageId, await conn.ExecuteScalarAsync<string>(
            "SELECT package_id FROM package_versions WHERE id = @VersionId", new { VersionId }));

        // The autoincrement primary keys are preserved rather than re-minted.
        var cargoIds = (await conn.QueryAsync<long>(
            "SELECT id FROM cargo_metadata ORDER BY id")).ToList();
        Assert.Equal(new List<long> { 1, 2 }, cargoIds);

        // The seeded SPDX catalogue is copied, not left as the target's own freshly seeded copy.
        long spdxSource;
        await using (var sourceConn = await sqlite.OpenAsync())
        {
            spdxSource = await sourceConn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM spdx_license");
        }

        Assert.True(spdxSource > 0);
        Assert.Equal(spdxSource, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM spdx_license"));
    }

    [Fact]
    public async Task Migrate_ResetsIdentitySequences_SoTheNextInsertDoesNotCollide()
    {
        await using var sqlite = await SeededSqliteAsync();
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);

        var result = await Migrator(sqlite, pg.Store).MigrateAsync(new MetadataMigrationOptions());
        Assert.Contains("cargo_metadata.id", result.ResetSequences);

        await using var conn = await pg.Store.OpenAsync();

        // Rows were inserted with explicit ids 1 and 2. Without a setval the sequence still starts
        // at 1 and this insert duplicates a primary key.
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key)
            VALUES ('pv-post-migration', @PackageId, '2.0.0', 'pkg:npm/migration-pkg@2.0.0',
                    'npm/r/migration-pkg/2.0.0/migration-pkg-2.0.0.tgz')
            """,
            new { PackageId });

        long minted = await conn.ExecuteScalarAsync<long>(
            """
            INSERT INTO cargo_metadata (version_id, index_line, owner_kind)
            VALUES ('pv-post-migration', '{"name":"c"}', 'package_version')
            RETURNING id
            """);

        Assert.True(minted > 2, $"sequence handed out {minted}, which collides with a migrated row");
    }

    [Fact]
    public async Task Verification_DetectsADeletedRow()
    {
        await using var sqlite = await SeededSqliteAsync();
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var migrator = Migrator(sqlite, pg.Store);

        Assert.True((await migrator.MigrateAsync(new MetadataMigrationOptions())).Verification!.Ok);

        await using (var conn = await pg.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "DELETE FROM npm_dist_tags WHERE id = @DistTagId", new { DistTagId });
        }

        var report = await migrator.VerifyAsync();

        Assert.False(report.Ok);
        var failure = Assert.Single(report.Failures);
        Assert.Equal("npm_dist_tags", failure.Table);
        Assert.Equal(1, failure.SourceRows);
        Assert.Equal(0, failure.TargetRows);
    }

    [Fact]
    public async Task Verification_DetectsAMutatedValue_WhereRowCountsStillMatch()
    {
        await using var sqlite = await SeededSqliteAsync();
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var migrator = Migrator(sqlite, pg.Store);

        Assert.True((await migrator.MigrateAsync(new MetadataMigrationOptions())).Verification!.Ok);

        await using (var conn = await pg.Store.OpenAsync())
        {
            // One character in one column, with the row count untouched — the case a count-only
            // check cannot see.
            await conn.ExecuteAsync(
                "UPDATE users SET email = 'owner@example.tesT' WHERE id = @UserId", new { UserId });
        }

        var report = await migrator.VerifyAsync();

        Assert.False(report.Ok);
        var failure = Assert.Single(report.Failures);
        Assert.Equal("users", failure.Table);
        Assert.Equal(failure.SourceRows, failure.TargetRows);
        Assert.NotEqual(failure.SourceDigest, failure.TargetDigest);
    }

    /// <summary>
    /// Timestamps are canonical ISO-8601 TEXT on both providers, so the smallest drift the
    /// verifier can be asked to catch is a single character. Flipping one digit of the seconds
    /// field is that minimum — were the digest comparison to tolerate it, a target whose
    /// timestamps had shifted would verify clean and an operator would cut over on it.
    /// </summary>
    [Fact]
    public async Task Verification_DetectsASingleCharacterTimestampDrift()
    {
        await using var sqlite = await SeededSqliteAsync();
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var migrator = Migrator(sqlite, pg.Store);

        Assert.True((await migrator.MigrateAsync(new MetadataMigrationOptions())).Verification!.Ok);

        await using (var conn = await pg.Store.OpenAsync())
        {
            // Position 19 of `YYYY-MM-DDTHH:MM:SSZ` is the ones digit of the seconds field.
            int drifted = await conn.ExecuteAsync(
                """
                UPDATE npm_dist_tags
                SET created_at = overlay(
                        created_at placing
                        CASE WHEN substr(created_at, 19, 1) = '0' THEN '1' ELSE '0' END
                        from 19 for 1)
                WHERE id = @DistTagId
                """,
                new { DistTagId });

            Assert.Equal(1, drifted);
        }

        var report = await migrator.VerifyAsync();

        Assert.False(report.Ok);
        Assert.Equal("npm_dist_tags", Assert.Single(report.Failures).Table);
    }

    /// <summary>
    /// The vacuous-pass guard. A target with no schema skips every table, and an all-skipped report
    /// must NOT read as success — an operator would cut over on it.
    /// </summary>
    [Fact]
    public async Task Verification_FailsAgainstATargetThatWasNeverMigrated()
    {
        await using var sqlite = await SeededSqliteAsync();
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);

        var report = await Migrator(sqlite, pg.Store).VerifyAsync();

        Assert.False(report.Ok);
        Assert.Empty(report.Tables);
        Assert.NotEmpty(report.SkippedTables);
    }

    [Fact]
    public async Task Migrate_RefusesATargetThatAlreadyHoldsData_UnlessForced()
    {
        await using var sqlite = await SeededSqliteAsync();
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var migrator = Migrator(sqlite, pg.Store);

        Assert.True((await migrator.MigrateAsync(new MetadataMigrationOptions())).Verification!.Ok);

        var refusal = await Assert.ThrowsAsync<MetadataMigrationException>(
            () => migrator.MigrateAsync(new MetadataMigrationOptions()));
        Assert.Contains("--force", refusal.Message, StringComparison.Ordinal);

        var forced = await migrator.MigrateAsync(new MetadataMigrationOptions { Force = true });
        Assert.True(forced.Verification!.Ok);

        // The forced re-run replaces rather than appends: no duplicate rows.
        await using var conn = await pg.Store.OpenAsync();
        Assert.Equal(1, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM orgs WHERE id = @OrgId", new { OrgId }));
    }

    [Fact]
    public async Task Migrate_AcceptsATargetThatHasOnlyEverHadTheSchemaApplied()
    {
        await using var sqlite = await SeededSqliteAsync();
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);

        // A target the operator booted the app against once: schema present, SPDX catalogue seeded,
        // no operator data. That must not need --force.
        await new SchemaInitializer(pg.Store).InitializeAsync();

        var result = await Migrator(sqlite, pg.Store).MigrateAsync(new MetadataMigrationOptions());
        Assert.True(result.Verification!.Ok);
    }
}
