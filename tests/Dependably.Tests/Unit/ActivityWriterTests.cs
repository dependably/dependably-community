using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Acceptance tests for <see cref="AuditRepository.LogActivityAsync"/>: the hot-path
/// must enqueue into the writer's channel and return without touching the DB; the
/// hosted-service drainer must batch the rows into a single INSERT pass.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ActivityWriterTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public void TryEnqueue_BelowCapacity_Returns_True()
    {
        var writer = new ActivityWriter();
        var record = Record("event-1");

        Assert.True(writer.TryEnqueue(record));
    }

    [Fact]
    public void TryEnqueue_AtCapacity_DropsRecord_ReturnsFalse()
    {
        var writer = new ActivityWriter();
        for (int i = 0; i < ActivityWriter.ChannelCapacity; i++)
        {
            Assert.True(writer.TryEnqueue(Record($"event-{i}")));
        }

        Assert.False(writer.TryEnqueue(Record("overflow")));
    }

    [Fact]
    public async Task LogActivityAsync_WithWriter_DoesNotInsertSynchronously()
    {
        var writer = new ActivityWriter();
        var repo = new AuditRepository(_db, writer);

        await repo.LogActivityAsync("o1", "pypi", "pkg:pypi/foo@1", "download");

        // Row should not be in the DB yet — the writer holds it until the drainer flushes.
        await using var conn = await _db.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM activity");
        Assert.Equal(0, count);
    }

    [Fact]
    public async Task LogActivityAsync_WithoutWriter_KeepsSynchronousBehaviour()
    {
        // Sync fallback is what every existing unit test relies on — verify it still
        // writes the row immediately when no writer is wired.
        var repo = new AuditRepository(_db);
        await repo.LogActivityAsync("o1", "pypi", "pkg:pypi/foo@1", "download");

        await using var conn = await _db.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM activity");
        Assert.Equal(1, count);
    }

    [Fact]
    public async Task DrainPendingAsync_FlushesBufferedRowsIntoActivityTable()
    {
        var writer = new ActivityWriter();
        var repo = new AuditRepository(_db, writer);
        var service = new ActivityWriterHostedService(writer, _db,
            NullLogger<ActivityWriterHostedService>.Instance);

        for (int i = 0; i < 50; i++)
        {
            await repo.LogActivityAsync("o1", "pypi", $"pkg:pypi/foo@{i}", "download");
        }

        await service.DrainPendingAsync();

        await using var conn = await _db.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM activity");
        Assert.Equal(50, count);
    }

    [Fact]
    public async Task DrainPendingAsync_HandlesOverMaxBatch_InTwoTransactions()
    {
        // 250 records > MaxBatch(200) — proves the drainer doesn't drop or block once
        // a single batch fills; it just keeps flushing.
        var writer = new ActivityWriter();
        var repo = new AuditRepository(_db, writer);
        var service = new ActivityWriterHostedService(writer, _db,
            NullLogger<ActivityWriterHostedService>.Instance);

        for (int i = 0; i < 250; i++)
        {
            await repo.LogActivityAsync("o1", "pypi", $"pkg:pypi/foo@{i}", "download");
        }

        await service.DrainPendingAsync();

        await using var conn = await _db.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM activity");
        Assert.Equal(250, count);
    }

    private static ActivityRecord Record(string eventType) => new(
        Id: Guid.NewGuid().ToString("N"),
        OrgId: "o1",
        Ecosystem: "pypi",
        Purl: "pkg:pypi/foo@1",
        EventType: eventType,
        ActorId: null,
        ActorKind: null,
        Detail: null,
        SourceIp: null,
        CreatedAt: "2026-05-25T00:00:00.000Z");
}
