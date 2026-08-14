using System.Diagnostics.Metrics;
using Dependably.Infrastructure.Observability;
using Dependably.Infrastructure.Siem;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

// Attaches a MeterListener filtered only by DependablyMeter.MeterName + instrument name and
// asserts exact counts — must run alone against the process-wide static meter.
// See MeterSensitiveCollection.
[Trait("Category", "Unit")]
[Collection("MeterSensitive")]
public class SiemForwarderQueueTests
{
    private static IConfiguration Cfg(int? capacity = null) =>
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["SIEM_QUEUE_CAPACITY"] = capacity?.ToString()
        }).Build();

    private sealed class CountingForwarder : ISiemForwarder
    {
        public int Calls { get; private set; }
        public Func<SiemEvent, Task>? Behavior { get; set; }
        public string Name => "counting";
        public Task SendAsync(SiemEvent ev, CancellationToken ct = default)
        {
            Calls++;
            return Behavior?.Invoke(ev) ?? Task.CompletedTask;
        }
    }

    private static SiemEvent Sample(string id = "e1") => new(
        Id: id, Action: "login.success", Scope: "tenant", OrgId: "o1",
        ActorId: "u1", Ecosystem: null, Purl: null, Detail: null,
        CreatedAt: TestTime.KnownNow);

    [Fact]
    public async Task EnqueueAndDeliver_HappyPath()
    {
        var fwd = new CountingForwarder();
        var q = new SiemForwarderQueue(
            fwd, new FakeTimeProvider(TestTime.KnownNow), Cfg(), NullLogger<SiemForwarderQueue>.Instance);
        using var cts = new CancellationTokenSource();
        var run = q.StartAsync(cts.Token);

        Assert.True(q.TryEnqueue(Sample()));
        await WaitAsync(() => fwd.Calls == 1);

        await cts.CancelAsync();
        try { await q.StopAsync(CancellationToken.None); } catch { }
        Assert.Equal(1, q.DeliveredCount);
    }

    [Fact]
    public void Overflow_DropsAndIncrementsMetric()
    {
        // Don't start the consumer — exercise the bounded-channel drop path directly.
        // Use capacity=2 and write 5 events; expect at least 3 drops (5 minus the 2 buffered).
        var fwd = new CountingForwarder();
        var q = new SiemForwarderQueue(
            fwd, new FakeTimeProvider(TestTime.KnownNow), Cfg(capacity: 2), NullLogger<SiemForwarderQueue>.Instance);

        long meterDrops = 0;
        using var listener = MeterListenerFor("dependably.siem_forwarder.dropped", delta => meterDrops += delta);

        int accepted = 0;
        for (int i = 0; i < 5; i++)
        {
            if (q.TryEnqueue(Sample($"e{i}")))
            {
                accepted++;
            }
        }

        Assert.Equal(2, accepted);
        Assert.Equal(3, q.DroppedCount);
        // The DroppedCount field alone is invisible to an operator — the OTel counter is what a
        // dashboard/alert actually reads, so a drop must be observable on the meter too.
        Assert.Equal(3, meterDrops);
    }

    // A dedicated FakeTimeProvider drives the queue's retry backoff so the test advances virtual
    // time instead of waiting out the real 1s delay between the first and second attempt.
    [Fact]
    public async Task TransientFailure_RetriesAndCounts()
    {
        int attempts = 0;
        var fwd = new CountingForwarder
        {
            Behavior = _ =>
            {
                attempts++;
                return attempts < 2
                    ? Task.FromException(new HttpRequestException("transient"))
                    : Task.CompletedTask;
            }
        };
        var clock = new FakeTimeProvider(TestTime.KnownNow);
        var q = new SiemForwarderQueue(fwd, clock, Cfg(), NullLogger<SiemForwarderQueue>.Instance);
        using var cts = new CancellationTokenSource();
        await q.StartAsync(cts.Token);

        q.TryEnqueue(Sample());
        await ClockPump.UntilAsync(clock, () => q.DeliveredCount == 1, TimeSpan.FromSeconds(1));

        await cts.CancelAsync();
        try { await q.StopAsync(CancellationToken.None); } catch { }
        Assert.Equal(2, attempts);
        Assert.Equal(0, q.FailedCount);
    }

    // ── Shutdown drain (channel still buffered when the stopping token is cancelled) ──

    /// <summary>
    /// Reproduces the shutdown-drop defect deterministically by invoking <c>ExecuteAsync</c>
    /// directly (via the <see cref="SiemForwarderQueue.ExecuteAsyncForTests"/> test hook) with an
    /// already-cancelled token — <see cref="BackgroundService.StartAsync"/> itself short-circuits
    /// and never calls <c>ExecuteAsync</c> at all in that case, so it cannot exercise the real
    /// race being tested (a stopping token cancelled while the read loop is genuinely running,
    /// mid-shutdown, with an audit event still buffered). The main <c>ReadAllAsync</c> loop
    /// observes cancellation on its very first <c>WaitToReadAsync</c> call — before it ever gets a
    /// chance to dequeue — exactly like <c>ApplicationStopping</c> firing in that window. SIEM is
    /// a compliance sink, so on the old code this silently drops the event; the shutdown drain
    /// must still forward it.
    /// </summary>
    [Fact]
    public async Task ExecuteAsync_CancelledMidRun_StillDrainsBufferedEvent()
    {
        var fwd = new CountingForwarder();
        var q = new SiemForwarderQueue(
            fwd, new FakeTimeProvider(TestTime.KnownNow), Cfg(), NullLogger<SiemForwarderQueue>.Instance);

        // Buffer the event before the worker ever starts reading.
        Assert.True(q.TryEnqueue(Sample()));

        // Drives ExecuteAsync directly with an already-cancelled token — the exact state the
        // stopping token is in by the time BackgroundService.StopAsync signals cancellation.
        await q.ExecuteAsyncForTests(new CancellationToken(canceled: true));

        Assert.Equal(1, fwd.Calls);
        Assert.Equal(1, q.DeliveredCount);
    }

    /// <summary>
    /// Mixed partial-failure variant: two events are buffered before <c>ExecuteAsync</c> runs with
    /// an already-cancelled token, one that forwards successfully and one whose forwarder always
    /// throws. The drain must deliver the first and count the second as failed independently,
    /// after exhausting its own retry budget inside the drain — proving one failing event doesn't
    /// block or lose the other.
    /// </summary>
    [Fact]
    public async Task ExecuteAsync_CancelledMidRun_DrainsMixedSuccessAndFailure()
    {
        var fwd = new CountingForwarder
        {
            Behavior = ev => ev.Id == "bad"
                ? Task.FromException(new HttpRequestException("always fails"))
                : Task.CompletedTask
        };
        var clock = new FakeTimeProvider(TestTime.KnownNow);
        var q = new SiemForwarderQueue(fwd, clock, Cfg(), NullLogger<SiemForwarderQueue>.Instance);

        long meterFailed = 0;
        using var listener = MeterListenerFor("dependably.siem_forwarder.failed", delta => meterFailed += delta);

        Assert.True(q.TryEnqueue(Sample("good")));
        Assert.True(q.TryEnqueue(Sample("bad")));

        var executeTask = q.ExecuteAsyncForTests(new CancellationToken(canceled: true));

        // The failing event burns through the 1s/5s/30s backoff inside the drain itself; pump
        // the fake clock so that finishes in virtual time instead of real time.
        await ClockPump.UntilAsync(clock, () => q.DeliveredCount == 1 && q.FailedCount == 1, TimeSpan.FromSeconds(1));

        await executeTask;

        Assert.Equal(1, q.DeliveredCount);
        Assert.Equal(1, q.FailedCount);
        // Mixed partial-failure batch: the successful delivery must not itself register as a
        // failure on the meter, and the one genuine failure must be visible on it.
        Assert.Equal(1, meterFailed);
    }

    private static async Task WaitAsync(Func<bool> condition, TimeSpan? timeout = null)
    {
        // now-ok: polling deadline awaiting real async completion of the queue's consumer loop.
        // A generous default — the consumer loop involves genuine async work (send + backoff)
        // that a short deadline can miss under load.
        var deadline = DateTimeOffset.UtcNow + (timeout ?? TimeSpan.FromSeconds(10));
        while (!condition() && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(20);
        }

        if (!condition())
        {
            throw new TimeoutException("Condition never satisfied.");
        }
    }

    /// <summary>
    /// Returns an active <see cref="MeterListener"/> that invokes <paramref name="onMeasurement"/>
    /// with each measurement delta emitted by the named instrument on <see cref="DependablyMeter"/>.
    /// Must be disposed after the assertion.
    /// </summary>
    private static MeterListener MeterListenerFor(string instrumentName, Action<long> onMeasurement)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == DependablyMeter.MeterName && instrument.Name == instrumentName)
                {
                    l.EnableMeasurementEvents(instrument);
                }
            }
        };
        listener.SetMeasurementEventCallback<long>((_, measurement, _, _) => onMeasurement(measurement));
        listener.Start();
        return listener;
    }
}
