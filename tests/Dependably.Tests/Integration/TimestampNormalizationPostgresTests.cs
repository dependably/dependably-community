using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Live-Postgres counterpart to <c>SchemaInitializerTimestampNormalizationTests</c>: confirms the
/// self-healing legacy-DateTimeOffset repair sweep correctly parses and UTC-shifts Npgsql's own
/// legacy provider-native shape (<c>2026-03-04 05:06:07.5+00</c> — space-separated, short-form
/// offset, no colon) the same way it handles Microsoft.Data.Sqlite's, and that the high-volume
/// columns are repaired set-based on the live engine: the sweep's statement list is fixed, not a
/// round trip per legacy row. It counts statements rather than timing them, so a contended
/// runner cannot fail it and a per-row regression fails it on an idle one.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class TimestampNormalizationPostgresTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests.");

    [Fact]
    public async Task NormalizesLegacyRows_AndIsIdempotentOnReapplication()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");

            // Plant legacy shapes directly, simulating a database predating the canonical-timestamp
            // CHECK — see TemporalCheckTestHelper. A fresh live-Postgres reset gets the constraint
            // immediately from InitializeAsync() above, so it has to be dropped first.
            await TemporalCheckTestHelper.DropPostgresCheckAsync(conn, "cache_artifact", "first_cached_at");
            await TemporalCheckTestHelper.DropPostgresCheckAsync(conn, "cache_artifact", "last_accessed_at");
            await TemporalCheckTestHelper.DropPostgresCheckAsync(conn, "cache_artifact", "published_at");
            await TemporalCheckTestHelper.DropPostgresCheckAsync(conn, "audit_event", "occurred_at");
            await TemporalCheckTestHelper.DropPostgresCheckAsync(conn, "packages", "upstream_latest_published_at");
            await TemporalCheckTestHelper.DropPostgresCheckAsync(conn, "package_versions", "published_at");

            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash,
                     first_cached_at, last_accessed_at, published_at)
                VALUES
                    ('ca1', 'npm', 'lodash', '1.0.0', 'lodash-1.0.0.tgz', 'proxy/abc', 'h',
                     '2026-03-04 05:06:07.5+02', '2026-03-04 05:06:07+00',
                     '2026-03-04 05:06:07.123456+02')
                """);
            await conn.ExecuteAsync(
                """
                INSERT INTO audit_event
                    (event_id, event_type, org_id, tenant_resolver, actor_type, outcome, payload, occurred_at)
                VALUES
                    ('ev1', 'package.publish', 'o1', 'single', 'user', 'accepted', '{}',
                     '2026-03-04 05:06:07.5+02')
                """);
            await conn.ExecuteAsync(
                "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, upstream_latest_published_at) " +
                "VALUES ('pkg1', 'o1', 'npm', 'lodash', 'lodash', '2026-03-04T05:06:07.1234567+00:00')");
            await conn.ExecuteAsync(
                "INSERT INTO package_versions (id, package_id, version, purl, blob_key, published_at) " +
                "VALUES ('pv1', 'pkg1', '1.0.0', 'pkg:npm/lodash@1.0.0', 'blob/x', '2026-03-04T05:06:07.1234567+00:00')");
        }

        // Self-healing: not ledger-gated, so re-running InitializeAsync() re-sweeps directly —
        // no _applied_migrations row to clear.
        await new SchemaInitializer(store).InitializeAsync();

        await using (var conn = await store.OpenAsync())
        {
            var (first, last) = await conn.QuerySingleAsync<(string First, string Last)>(
                "SELECT first_cached_at AS First, last_accessed_at AS Last FROM cache_artifact WHERE id = 'ca1'");
            // +02 (Postgres short-form, no colon) shifts 05:06:07.5 back 2h to 03:06:07Z.
            Assert.Equal("2026-03-04T03:06:07Z", first);
            Assert.Equal("2026-03-04T05:06:07Z", last);

            // published_at is the microsecond-precision column on this table, swept row-by-row so
            // the sub-second digits the upstream registry declared survive the UTC shift.
            Assert.Equal(
                "2026-03-04T03:06:07.123456Z",
                await conn.QuerySingleAsync<string>(
                    "SELECT published_at FROM cache_artifact WHERE id = 'ca1'"));

            string occurredAt = await conn.QuerySingleAsync<string>(
                "SELECT occurred_at FROM audit_event WHERE event_id = 'ev1'");
            Assert.Equal("2026-03-04T03:06:07.500Z", occurredAt);

            string packagePublishedAt = await conn.QuerySingleAsync<string>(
                "SELECT upstream_latest_published_at FROM packages WHERE id = 'pkg1'");
            string versionPublishedAt = await conn.QuerySingleAsync<string>(
                "SELECT published_at FROM package_versions WHERE id = 'pv1'");
            Assert.Equal("2026-03-04T05:06:07.123456Z", packagePublishedAt);
            Assert.Equal("2026-03-04T05:06:07.123456Z", versionPublishedAt);
        }

        // Idempotency: re-run against the now-canonical rows. A second application must leave
        // them byte-identical rather than reformatting an already-correct value.
        await new SchemaInitializer(store).InitializeAsync();

        await using (var conn = await store.OpenAsync())
        {
            var (first, last) = await conn.QuerySingleAsync<(string First, string Last)>(
                "SELECT first_cached_at AS First, last_accessed_at AS Last FROM cache_artifact WHERE id = 'ca1'");
            Assert.Equal("2026-03-04T03:06:07Z", first);
            Assert.Equal("2026-03-04T05:06:07Z", last);
        }
    }

    [Fact]
    public async Task UnparseableInput_IsLeftUntouched_AndDoesNotWedgeBoot()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
            await TemporalCheckTestHelper.DropPostgresCheckAsync(conn, "cache_artifact", "first_cached_at");
            await TemporalCheckTestHelper.DropPostgresCheckAsync(conn, "cache_artifact", "last_accessed_at");
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash, first_cached_at, last_accessed_at)
                VALUES ('ca1', 'npm', 'lodash', '1.0.0', 'lodash-1.0.0.tgz', 'proxy/abc', 'h', @garbage, @garbage)
                """,
                new { garbage = "not a date" });
        }

        // Must not throw: Postgres's ::timestamptz cast is strict, so the shape guard has to
        // keep a non-date-shaped value out of the cast entirely, not rely on a cast failure
        // being caught.
        await new SchemaInitializer(store).InitializeAsync();

        await using var read = await store.OpenAsync();
        string stored = await read.QuerySingleAsync<string>(
            "SELECT first_cached_at FROM cache_artifact WHERE id = 'ca1'");
        Assert.Equal("not a date", stored);
    }

    [Fact]
    public async Task SetBasedSweep_IssuesTheSameStatementsRegardlessOfLegacyRowCount()
    {
        // Two backlogs two orders of magnitude apart. A set-based sweep issues an identical,
        // fixed statement list for both; any per-row round trip makes the larger list longer.
        const int smallBacklog = 10;
        const int largeBacklog = 1_000;

        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();

        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
            await TemporalCheckTestHelper.DropPostgresCheckAsync(conn, "cache_artifact", "first_cached_at");
            await TemporalCheckTestHelper.DropPostgresCheckAsync(conn, "cache_artifact", "last_accessed_at");
        }

        var initializer = new SchemaInitializer(store);

        // Each backlog is seeded and swept on its own, so the second sweep sees only its own
        // legacy rows: the first sweep has already made the small backlog canonical.
        await SeedLegacyRowsAsync(store, "small", smallBacklog);
        var smallStatements = await CaptureSweepStatementsAsync(store, initializer);
        Assert.Equal(smallBacklog, await CountNormalizedAsync(store, "small"));

        await SeedLegacyRowsAsync(store, "large", largeBacklog);
        var largeStatements = await CaptureSweepStatementsAsync(store, initializer);
        Assert.Equal(largeBacklog, await CountNormalizedAsync(store, "large"));

        // The statement list does not grow with the backlog, statement for statement.
        Assert.True(
            smallStatements.SequenceEqual(largeStatements),
            $"expected the same statements for a {smallBacklog}-row and a {largeBacklog}-row " +
            $"backlog, got {smallStatements.Count} and {largeStatements.Count}");

        // Exactly one statement writes each high-volume column: a per-row UPDATE matches too.
        foreach (string column in new[] { "first_cached_at", "last_accessed_at" })
        {
            Assert.Single(
                largeStatements,
                sql => sql.Contains($"UPDATE cache_artifact SET {column} =", StringComparison.Ordinal));
        }

        // Twin: the same counter on a row-by-row loop (one SELECT, then one UPDATE per row, the
        // shape the set-based sweep replaces) counts every round trip. Without this, a counter
        // that silently saw nothing would pass the equality above.
        const int rowBacklog = 25;
        await SeedLegacyRowsAsync(store, "row", rowBacklog);
        await using (var inner = await store.OpenAsync())
        {
            var counting = new CountingConnection(inner);
            var legacyRows = (await counting.QueryAsync<(string Id, string Value)>(
                "SELECT id AS Id, first_cached_at AS Value FROM cache_artifact " +
                "WHERE ecosystem = 'row' AND first_cached_at IS NOT NULL"))
                .ToList();
            foreach (var (id, value) in legacyRows)
            {
                var parsed = DateTimeOffset.Parse(value, System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal);
                await counting.ExecuteAsync(
                    "UPDATE cache_artifact SET first_cached_at = @normalized WHERE id = @id",
                    new { normalized = parsed.ToUtcIso(), id });
            }

            Assert.Equal(1 + rowBacklog, counting.Statements.Count);
        }

        await using var read = await store.OpenAsync();
        Assert.Equal(rowBacklog, await read.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact " +
            "WHERE ecosystem = 'row' AND first_cached_at = '2026-03-04T03:06:07Z'"));
    }

    private static async Task<IReadOnlyList<string>> CaptureSweepStatementsAsync(
        NpgsqlMetadataStore store, SchemaInitializer initializer)
    {
        await using var inner = await store.OpenAsync();
        var counting = new CountingConnection(inner);
        await initializer.NormalizeLegacyDateTimeOffsetColumnsAsync(counting);
        return counting.Statements;
    }

    private static async Task<long> CountNormalizedAsync(NpgsqlMetadataStore store, string ecosystemTag)
    {
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = @ecosystemTag " +
            "AND first_cached_at = '2026-03-04T03:06:07Z' AND last_accessed_at = '2026-03-04T03:06:07Z'",
            new { ecosystemTag });
    }

    private static async Task SeedLegacyRowsAsync(NpgsqlMetadataStore store, string ecosystemTag, int rowCount)
    {
        const int batchSize = 1000;
        await using var conn = await store.OpenAsync();
        for (int batchStart = 0; batchStart < rowCount; batchStart += batchSize)
        {
            var batch = Enumerable.Range(batchStart, Math.Min(batchSize, rowCount - batchStart))
                .Select(i => new
                {
                    id = $"ca-{ecosystemTag}-{i}",
                    version = $"1.0.{i}",
                    filename = $"lodash-1.0.{i}.tgz",
                    blobKey = $"proxy/{ecosystemTag}-{i}",
                });
            await conn.ExecuteAsync(
                $"""
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash,
                     first_cached_at, last_accessed_at)
                VALUES
                    (@id, '{ecosystemTag}', 'lodash', @version, @filename, @blobKey, 'h',
                     '2026-03-04 05:06:07.5+02', '2026-03-04 05:06:07.5+02')
                """,
                batch);
        }
    }
}
