using Dependably.Infrastructure.Siem;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class SiemForwarderQueueTests
{
    private static IConfiguration Cfg(int? capacity = null) =>
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["SIEM_QUEUE_CAPACITY"] = capacity?.ToString()
        }).Build();

    /// <summary>
    /// Drives a queue's retry backoff deterministically: advances <paramref name="clock"/> by
    /// <paramref name="step"/> and yields briefly so the background delivery loop observes each
    /// fired timer, repeating until <paramref name="condition"/> is met. The tiny real-time yield
    /// only gives the scheduler a turn — it does not wait out the backoff itself, which is driven
    /// entirely by the advancing fake clock.
    /// </summary>
    private static async Task PumpUntilAsync(
        FakeTimeProvider clock, Func<bool> condition, TimeSpan step, int maxIterations = 200)
    {
        for (int i = 0; i < maxIterations && !condition(); i++)
        {
            clock.Advance(step);
            await Task.Delay(5);
        }

        if (!condition())
        {
            throw new TimeoutException("Condition never satisfied while pumping the fake clock.");
        }
    }

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
        await PumpUntilAsync(clock, () => q.DeliveredCount == 1, TimeSpan.FromSeconds(1));

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

        Assert.True(q.TryEnqueue(Sample("good")));
        Assert.True(q.TryEnqueue(Sample("bad")));

        var executeTask = q.ExecuteAsyncForTests(new CancellationToken(canceled: true));

        // The failing event burns through the 1s/5s/30s backoff inside the drain itself; pump
        // the fake clock so that finishes in virtual time instead of real time.
        await PumpUntilAsync(clock, () => q.DeliveredCount == 1 && q.FailedCount == 1, TimeSpan.FromSeconds(1));

        await executeTask;

        Assert.Equal(1, q.DeliveredCount);
        Assert.Equal(1, q.FailedCount);
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
}
