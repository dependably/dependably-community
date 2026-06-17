using System.Diagnostics.Metrics;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
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

    // ── Capacity defaults ────────────────────────────────────────────────────

    [Fact]
    public void DefaultCapacity_Is_50k()
    {
        Assert.Equal(50_000, ActivityWriter.DefaultChannelCapacity);
    }

    [Fact]
    public void ChannelCapacity_UsesDefault_WhenNullPassed()
    {
        var writer = new ActivityWriter();
        Assert.Equal(ActivityWriter.DefaultChannelCapacity, writer.ChannelCapacity);
    }

    [Fact]
    public void ChannelCapacity_Configurable_WithCustomValue()
    {
        var writer = new ActivityWriter(capacity: 7);
        Assert.Equal(7, writer.ChannelCapacity);
    }

    [Fact]
    public void ChannelCapacity_IgnoresNonPositive_FallsBackToDefault()
    {
        var writer = new ActivityWriter(capacity: 0);
        Assert.Equal(ActivityWriter.DefaultChannelCapacity, writer.ChannelCapacity);
    }

    // ── TryEnqueue — below/at capacity ──────────────────────────────────────

    [Fact]
    public void TryEnqueue_BelowCapacity_Returns_True()
    {
        var writer = new ActivityWriter();
        var record = Record("event-1");

        Assert.True(writer.TryEnqueue(record));
    }

    [Fact]
    public void TryEnqueue_AtCustomCapacity_DropsRecord_ReturnsFalse()
    {
        // Use a tiny capacity so the test is fast.
        const int cap = 5;
        var writer = new ActivityWriter(capacity: cap);
        for (int i = 0; i < cap; i++)
        {
            Assert.True(writer.TryEnqueue(Record($"event-{i}")));
        }

        Assert.False(writer.TryEnqueue(Record("overflow")));
    }

    // ── Drop-meter fires on full channel ────────────────────────────────────

    [Fact]
    public void TryEnqueue_OverCapacity_IncrementsDropMeter()
    {
        const int cap = 3;
        var writer = new ActivityWriter(capacity: cap);

        long drops = 0;
        using var listener = DropMeterListener(delta => drops += delta);

        // Saturate the channel.
        for (int i = 0; i < cap; i++)
        {
            writer.TryEnqueue(Record($"e{i}"));
        }

        bool enqueued = writer.TryEnqueue(Record("overflow"));

        Assert.False(enqueued);
        Assert.Equal(1, drops);
    }

    // ── Mixed partial-failure scenario (house rule) ──────────────────────────
    // A burst that partially exceeds capacity: under-capacity writes succeed and
    // persist after drain; only overflow records are dropped and counted.

    [Fact]
    public async Task MixedBurst_PartiallyExceedsCapacity_OnlyOverflowDropped()
    {
        const int cap = 10;
        const int burst = 15;  // 5 will overflow
        const int expectedDrops = burst - cap;

        var writer = new ActivityWriter(capacity: cap);
        var repo = new AuditRepository(_db, writer);
        var service = new ActivityWriterHostedService(writer, _db,
            NullLogger<ActivityWriterHostedService>.Instance);

        long drops = 0;
        using var listener = DropMeterListener(delta => drops += delta);

        int successCount = 0;
        for (int i = 0; i < burst; i++)
        {
            if (writer.TryEnqueue(Record($"event-{i}")))
            {
                successCount++;
            }
        }

        Assert.Equal(cap, successCount);
        Assert.Equal(expectedDrops, drops);

        // Drain and verify only successfully queued rows land in the DB.
        await service.DrainPendingAsync();

        await using var conn = await _db.OpenAsync();
        int dbCount = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM activity");
        Assert.Equal(cap, dbCount);
    }

    // ── AuditRepository integration ──────────────────────────────────────────

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

    // ── Helpers ──────────────────────────────────────────────────────────────

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

    /// <summary>
    /// Returns an active <see cref="MeterListener"/> that invokes <paramref name="onDrop"/>
    /// with each measurement delta emitted by
    /// <c>dependably.activity_writer.dropped</c>. Must be disposed after the assertion.
    /// </summary>
    private static MeterListener DropMeterListener(Action<long> onDrop)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == DependablyMeter.MeterName &&
                    instrument.Name == "dependably.activity_writer.dropped")
                {
                    l.EnableMeasurementEvents(instrument);
                }
            }
        };
        listener.SetMeasurementEventCallback<long>((_, measurement, _, _) => onDrop(measurement));
        listener.Start();
        return listener;
    }
}
