using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Integration;

/// <summary>
/// Exercises the DbBatch flush path in <see cref="ActivityWriterHostedService"/> against a
/// live Postgres server through the production <see cref="NpgsqlMetadataStore"/>. The SQLite
/// path is already covered by <c>ActivityWriterTests</c>; this test proves the Npgsql-pipelined
/// batch executes correctly and that the two-batch split (250 rows &gt; MaxBatch=200) lands all rows.
///
/// Tagged <c>Category=SchemaPostgres</c> so it runs only in the <c>schema-integrity</c> CI job
/// (which attaches a Postgres service and sets <c>TEST_POSTGRES_CONNECTION</c>). Fails loudly
/// when the environment variable is absent rather than skipping silently.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class ActivityWriterPostgresTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    private static async Task<NpgsqlMetadataStore> FreshPostgresAsync()
    {
        var store = new NpgsqlMetadataStore(ConnectionString);
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
        return store;
    }

    /// <summary>
    /// Enqueues 250 activity rows (exceeding MaxBatch=200, which forces two DbBatch flushes)
    /// and confirms all 250 land in the <c>activity</c> table after DrainPendingAsync.
    /// Timestamps are driven through the injected TimeProvider — no DateTime.UtcNow is used.
    /// </summary>
    [Fact]
    public async Task DbBatch_FlushesToLivePostgres_AllRowsPersisted()
    {
        var store = await FreshPostgresAsync();
        await new SchemaInitializer(store).InitializeAsync();

        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");

        var writer = new ActivityWriter();
        var repo = new AuditRepository(store, writer, TestTime.Frozen());
        var service = new ActivityWriterHostedService(
            writer, store, NullLogger<ActivityWriterHostedService>.Instance);

        for (int i = 0; i < 250; i++)
        {
            await repo.LogActivityAsync("o1", "pypi", $"pkg:pypi/foo@{i}", "download");
        }

        await service.DrainPendingAsync();

        long count = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM activity");
        Assert.Equal(250, count);
    }

    /// <summary>
    /// Mixed partial-failure scenario (house rule): enqueues a burst where the channel
    /// capacity is smaller than the burst size, then drains. Only the successfully enqueued
    /// rows must appear in Postgres; overflowed rows are silently dropped.
    /// </summary>
    [Fact]
    public async Task DbBatch_OnLivePostgres_PartialBurst_OnlySuccessfulRowsPersisted()
    {
        var store = await FreshPostgresAsync();
        await new SchemaInitializer(store).InitializeAsync();

        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");

        // Channel too small to hold all burst records — the overflow is dropped.
        const int capacity = 50;
        const int burst = 70;

        var writer = new ActivityWriter(capacity: capacity);
        var service = new ActivityWriterHostedService(
            writer, store, NullLogger<ActivityWriterHostedService>.Instance);

        int enqueued = 0;
        for (int i = 0; i < burst; i++)
        {
            var record = new ActivityRecord(
                Id: Guid.NewGuid().ToString("N"),
                OrgId: "o1",
                Ecosystem: "pypi",
                Purl: $"pkg:pypi/foo@{i}",
                EventType: "download",
                ActorId: null,
                ActorKind: null,
                Detail: null,
                SourceIp: null,
                CreatedAt: TestTime.KnownNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ",
                    System.Globalization.CultureInfo.InvariantCulture));
            if (writer.TryEnqueue(record))
            {
                enqueued++;
            }
        }

        // Exactly capacity rows accepted; the rest dropped.
        Assert.Equal(capacity, enqueued);

        await service.DrainPendingAsync();

        long count = await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM activity");
        Assert.Equal(capacity, count);
    }
}
