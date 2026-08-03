using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Pins the self-healing legacy-DateTimeOffset repair sweep
/// (<c>SchemaInitializer.TimestampNormalization.cs</c>): every column a raw-DateTimeOffset Dapper
/// bind could have reached before <c>RemoveTypeMap</c> was ordered ahead of <c>AddTypeHandler</c>
/// must convert its legacy, provider-native shape (space-separated, offset preserved, no UTC
/// conversion) to the canonical <c>Z</c> form the column's other writers already use. The sweep
/// is not ledger-gated — it runs on every <c>InitializeAsync()</c> call, so these tests call it
/// again directly rather than clearing an <c>_applied_migrations</c> row.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SchemaInitializerTimestampNormalizationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");

        // Every test in this file plants a legacy, non-canonical shape directly to exercise the
        // repair sweep — exactly the state a database predating the canonical-timestamp CHECK
        // constraint is in. A fresh TestMetadataStore gets that constraint immediately from
        // InitializeAsync() above, so it has to be stripped first — see TemporalCheckTestHelper.
        foreach (var (table, column) in new[]
        {
            ("cache_artifact", "first_cached_at"), ("cache_artifact", "last_accessed_at"),
            ("tenant_artifact_access", "first_accessed_at"), ("tenant_artifact_access", "last_accessed_at"),
            ("tenant_artifact_access", "last_used"),
            ("audit_event", "occurred_at"),
            ("claim", "created_at"), ("claim", "updated_at"), ("claim", "deleted_at"),
            ("claim_history", "occurred_at"),
            ("packages", "upstream_latest_published_at"), ("package_versions", "published_at"),
            ("cache_artifact", "published_at"),
        })
        {
            await TemporalCheckTestHelper.StripSqliteCheckAsync(conn, table, column);
        }
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private async Task ReapplyAsync() => await new SchemaInitializer(_db).InitializeAsync();

    [Fact]
    public async Task CacheArtifact_LegacySpaceFormWithOffset_NormalizesToCanonicalUtc()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash,
                     first_cached_at, last_accessed_at)
                VALUES
                    ('ca1', 'npm', 'lodash', '1.0.0', 'lodash-1.0.0.tgz', 'proxy/abc', 'h',
                     '2026-03-04 05:06:07+02:00', '2026-03-04 05:06:07.500+00:00')
                """);
        }

        await ReapplyAsync();

        await using var read = await _db.OpenAsync();
        var (first, last) = await read.QuerySingleAsync<(string First, string Last)>(
            "SELECT first_cached_at AS First, last_accessed_at AS Last FROM cache_artifact WHERE id = 'ca1'");

        // +02:00 shifts to 03:06:07Z; the already-zero-offset row keeps its instant but drops the
        // space/offset shape — note the column is second precision so its .500 truncates away
        // rather than being dropped as a shape error, matching every other second-precision
        // writer of this column.
        Assert.Equal("2026-03-04T03:06:07Z", first);
        Assert.Equal("2026-03-04T05:06:07Z", last);
    }

    [Fact]
    public async Task TenantArtifactAccess_CompositeKey_LegacyRow_Normalizes()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
                VALUES ('ca2', 'npm', 'lodash', '2.0.0', 'lodash-2.0.0.tgz', 'proxy/def', 'h')
                """);
            await conn.ExecuteAsync(
                """
                INSERT INTO tenant_artifact_access
                    (org_id, cache_artifact_id, first_accessed_at, last_accessed_at, last_used)
                VALUES
                    ('o1', 'ca2', '2026-03-04 05:06:07+00:00', '2026-03-04 06:00:00+02:00', '2026-03-04 07:00:00+00:00')
                """);
        }

        await ReapplyAsync();

        await using var read = await _db.OpenAsync();
        var (first, last, used) = await read.QuerySingleAsync<(string First, string Last, string Used)>(
            """
            SELECT first_accessed_at AS First, last_accessed_at AS Last, last_used AS Used
            FROM tenant_artifact_access WHERE org_id = 'o1' AND cache_artifact_id = 'ca2'
            """);

        Assert.Equal("2026-03-04T05:06:07Z", first);
        Assert.Equal("2026-03-04T04:00:00Z", last); // +02:00 shifts back 2h
        Assert.Equal("2026-03-04T07:00:00Z", used);
    }

    [Fact]
    public async Task AuditEvent_LegacyRow_NormalizesAtMillisecondPrecision()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO audit_event
                    (event_id, event_type, org_id, tenant_resolver, actor_type, outcome, payload, occurred_at)
                VALUES
                    ('ev1', 'package.publish', 'o1', 'single', 'user', 'accepted', '{}',
                     '2026-03-04 05:06:07.500+02:00')
                """);
        }

        await ReapplyAsync();

        await using var read = await _db.OpenAsync();
        string occurredAt = await read.QuerySingleAsync<string>(
            "SELECT occurred_at FROM audit_event WHERE event_id = 'ev1'");

        Assert.Equal("2026-03-04T03:06:07.500Z", occurredAt);
    }

    [Fact]
    public async Task Claim_And_ClaimHistory_LegacyRows_Normalize()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO claim (id, org_id, ecosystem, name, state, reason, created_at, updated_at, deleted_at)
                VALUES ('cl1', 'o1', 'npm', 'lodash', 'local_only', 'r',
                        '2026-03-04 05:06:07+02:00', '2026-03-05 05:06:07+02:00', '2026-03-06 05:06:07+02:00')
                """);
            await conn.ExecuteAsync(
                """
                INSERT INTO claim_history (id, org_id, claim_id, ecosystem, name, new_state, reason, occurred_at)
                VALUES ('ch1', 'o1', 'cl1', 'npm', 'lodash', 'local_only', 'r', '2026-03-04 05:06:07+02:00')
                """);
        }

        await ReapplyAsync();

        await using var read = await _db.OpenAsync();
        var (createdAt, updatedAt, deletedAt) = await read.QuerySingleAsync<(string CreatedAt, string UpdatedAt, string DeletedAt)>(
            "SELECT created_at AS CreatedAt, updated_at AS UpdatedAt, deleted_at AS DeletedAt FROM claim WHERE id = 'cl1'");
        string occurredAt = await read.QuerySingleAsync<string>(
            "SELECT occurred_at FROM claim_history WHERE id = 'ch1'");

        Assert.Equal("2026-03-04T03:06:07Z", createdAt);
        Assert.Equal("2026-03-05T03:06:07Z", updatedAt);
        Assert.Equal("2026-03-06T03:06:07Z", deletedAt);
        Assert.Equal("2026-03-04T03:06:07Z", occurredAt);
    }

    [Fact]
    public async Task PackageVersions_And_Packages_MicrosecondColumns_Normalize()
    {
        // published_at / upstream_latest_published_at were never reachable through the Dapper
        // DateTimeOffsetHandler (both are written via an explicit string conversion at the call
        // site) — their legacy shape is the OLD .ToString("o") writer's, not the space-separated
        // provider-native one: T-separated, 7-digit fraction, "+00:00" instead of "Z".
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, upstream_latest_published_at) " +
                "VALUES ('pkg1', 'o1', 'npm', 'lodash', 'lodash', '2026-03-04T05:06:07.1234567+00:00')");
            await conn.ExecuteAsync(
                "INSERT INTO package_versions (id, package_id, version, purl, blob_key, published_at) " +
                "VALUES ('pv1', 'pkg1', '1.0.0', 'pkg:npm/lodash@1.0.0', 'blob/x', '2026-03-04T05:06:07.1234567+00:00')");
        }

        await ReapplyAsync();

        await using var read = await _db.OpenAsync();
        string packagePublishedAt = await read.QuerySingleAsync<string>(
            "SELECT upstream_latest_published_at FROM packages WHERE id = 'pkg1'");
        string versionPublishedAt = await read.QuerySingleAsync<string>(
            "SELECT published_at FROM package_versions WHERE id = 'pv1'");

        Assert.Equal("2026-03-04T05:06:07.123456Z", packagePublishedAt);
        Assert.Equal("2026-03-04T05:06:07.123456Z", versionPublishedAt);
    }

    [Fact]
    public async Task CacheArtifact_PublishedAt_LegacyRawDateTimeOffsetBind_NormalizesAtMicrosecondPrecision()
    {
        // cache_artifact.published_at is the one column on this table whose writer
        // (CacheArtifactRepository.UpdateGlobalFactsAsync) bound a raw DateTimeOffset parameter, so
        // it is exposed to exactly the provider-native serialization the handler fix addresses —
        // and it was added by a bare ALTER TABLE ADD COLUMN, so no timestamptz conversion covers it
        // either. Swept row-by-row rather than set-based because the column is microsecond
        // precision: a set-based strftime pass would truncate the sub-second digits the upstream
        // registry declared and this artifact re-serves.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash, published_at)
                VALUES
                    ('ca-pub', 'pypi', 'requests', '2.31.0', 'requests-2.31.0.tar.gz', 'proxy/stu', 'h',
                     '2026-03-04 05:06:07.1234560+02:00')
                """);
        }

        await ReapplyAsync();

        await using var read = await _db.OpenAsync();
        string publishedAt = await read.QuerySingleAsync<string>(
            "SELECT published_at FROM cache_artifact WHERE id = 'ca-pub'");

        // +02:00 shifts back 2h, and all six fractional digits survive.
        Assert.Equal("2026-03-04T03:06:07.123456Z", publishedAt);

        // Idempotent: a second sweep leaves the now-canonical value byte-identical.
        await ReapplyAsync();
        await using var reread = await _db.OpenAsync();
        Assert.Equal(publishedAt, await reread.QuerySingleAsync<string>(
            "SELECT published_at FROM cache_artifact WHERE id = 'ca-pub'"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a date")]
    public async Task UnparseableInput_IsLeftUntouched_AndDoesNotWedgeBoot(string garbage)
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash, first_cached_at, last_accessed_at)
                VALUES ('ca5', 'npm', 'lodash', '5.0.0', 'lodash-5.0.0.tgz', 'proxy/mno', 'h', @garbage, @garbage)
                """,
                new { garbage });
        }

        // Must not throw — an unparseable value is skipped, not fatal to boot.
        await ReapplyAsync();

        await using var read = await _db.OpenAsync();
        string stored = await read.QuerySingleAsync<string>(
            "SELECT first_cached_at FROM cache_artifact WHERE id = 'ca5'");
        Assert.Equal(garbage, stored);
    }

    [Fact]
    public async Task UnparseableIntegerLookingValue_IsLeftUntouched_AndDoesNotWedgeBoot()
    {
        // A bare numeric literal inserted into this TEXT-affinity column is converted to its
        // text form by SQLite before storage ("20260304"), but the shape guard (GLOB requiring
        // literal '-'/':' characters at fixed positions) still excludes it from the sweep's
        // UPDATE entirely, rather than feeding it to strftime — which would otherwise
        // reinterpret an untyped numeric string as a Julian day / unixepoch and silently
        // corrupt it into a nonsense date instead of leaving it alone.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash, first_cached_at, last_accessed_at)
                VALUES ('ca6', 'npm', 'lodash', '6.0.0', 'lodash-6.0.0.tgz', 'proxy/pqr', 'h', 20260304, 20260304)
                """);
        }

        await ReapplyAsync();

        await using var read = await _db.OpenAsync();
        string stored = await read.QuerySingleAsync<string>(
            "SELECT first_cached_at FROM cache_artifact WHERE id = 'ca6'");
        Assert.Equal("20260304", stored);
    }

    [Fact]
    public async Task Migration_IsIdempotent_SecondApplicationChangesNothing()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash,
                     first_cached_at, last_accessed_at)
                VALUES
                    ('ca3', 'npm', 'lodash', '3.0.0', 'lodash-3.0.0.tgz', 'proxy/ghi', 'h',
                     '2026-03-04 05:06:07+02:00', '2026-03-04 05:06:07+02:00')
                """);
        }

        await ReapplyAsync();

        await using var afterFirst = await _db.OpenAsync();
        string firstPass = await afterFirst.QuerySingleAsync<string>(
            "SELECT first_cached_at FROM cache_artifact WHERE id = 'ca3'");
        Assert.Equal("2026-03-04T03:06:07Z", firstPass);

        // Re-run against the now-canonical row: the NOT LIKE '%Z' filter excludes it from the
        // UPDATE entirely, so a second application must leave it byte-identical.
        await ReapplyAsync();

        await using var afterSecond = await _db.OpenAsync();
        string secondPass = await afterSecond.QuerySingleAsync<string>(
            "SELECT first_cached_at FROM cache_artifact WHERE id = 'ca3'");
        Assert.Equal(firstPass, secondPass);
    }

    [Fact]
    public async Task Migration_LeavesAlreadyCanonicalRowsUntouched()
    {
        // A row written by the fixed handler (or any explicit UtcTimestamp.ToUtcIso() writer) is
        // already canonical; the sweep must not alter it.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash,
                     first_cached_at, last_accessed_at)
                VALUES
                    ('ca4', 'npm', 'lodash', '4.0.0', 'lodash-4.0.0.tgz', 'proxy/jkl', 'h',
                     '2026-03-04T05:06:07Z', '2026-03-04T05:06:07Z')
                """);
        }

        await ReapplyAsync();

        await using var read = await _db.OpenAsync();
        string firstCachedAt = await read.QuerySingleAsync<string>(
            "SELECT first_cached_at FROM cache_artifact WHERE id = 'ca4'");
        Assert.Equal("2026-03-04T05:06:07Z", firstCachedAt);
    }

    [Fact]
    public async Task SetBasedSweep_HandlesTenThousandLegacyRows_WellUnderASecond()
    {
        // Not a comparison against the deleted row-by-row implementation (see
        // TimestampNormalizationPostgresTests for that, against the live engine the reviewer's
        // benchmark used) — this just demonstrates the set-based UPDATE scales to a realistic
        // cache_artifact row count without the per-row round-trip cost a row-by-row C# loop
        // would add, even against in-memory SQLite.
        const int rowCount = 10_000;
        await using (var conn = await _db.OpenAsync())
        {
            for (int batchStart = 0; batchStart < rowCount; batchStart += 500)
            {
                var batch = Enumerable.Range(batchStart, Math.Min(500, rowCount - batchStart))
                    .Select(i => new
                    {
                        id = $"ca-perf-{i}",
                        version = $"1.0.{i}",
                        filename = $"lodash-1.0.{i}.tgz",
                        blobKey = $"proxy/perf-{i}",
                    });
                await conn.ExecuteAsync(
                    """
                    INSERT INTO cache_artifact
                        (id, ecosystem, name, version, filename, blob_key, content_hash,
                         first_cached_at, last_accessed_at)
                    VALUES
                        (@id, 'npm', 'lodash', @version, @filename, @blobKey, 'h',
                         '2026-03-04 05:06:07+02:00', '2026-03-04 05:06:07+02:00')
                    """,
                    batch);
            }
        }

        var initializer = new SchemaInitializer(_db);
        await using var sweepConn = await _db.OpenAsync();
        var stopwatch = System.Diagnostics.Stopwatch.StartNew(); // now-ok: timing evidence for the set-based sweep, logged not branched on
        await initializer.NormalizeLegacyDateTimeOffsetColumnsAsync(sweepConn);
        stopwatch.Stop();

        Assert.True(stopwatch.ElapsedMilliseconds < 2000,
            $"set-based sweep of {rowCount} rows took {stopwatch.ElapsedMilliseconds}ms, expected well under 2000ms");

        long normalizedCount = await sweepConn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE id LIKE 'ca-perf-%' AND first_cached_at = '2026-03-04T03:06:07Z'");
        Assert.Equal(rowCount, normalizedCount);
    }
}
