using Dependably.Infrastructure.Siem;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
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
        var q = new SiemForwarderQueue(fwd, Cfg(), NullLogger<SiemForwarderQueue>.Instance);
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
        var q = new SiemForwarderQueue(fwd, Cfg(capacity: 2), NullLogger<SiemForwarderQueue>.Instance);

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
        var q = new SiemForwarderQueue(fwd, Cfg(), NullLogger<SiemForwarderQueue>.Instance);
        using var cts = new CancellationTokenSource();
        await q.StartAsync(cts.Token);

        q.TryEnqueue(Sample());
        await WaitAsync(() => q.DeliveredCount == 1, TimeSpan.FromSeconds(5));

        await cts.CancelAsync();
        try { await q.StopAsync(CancellationToken.None); } catch { }
        Assert.Equal(2, attempts);
        Assert.Equal(0, q.FailedCount);
    }

    private static async Task WaitAsync(Func<bool> condition, TimeSpan? timeout = null)
    {
        // now-ok: polling deadline awaiting real async completion of the queue's consumer loop
        var deadline = DateTimeOffset.UtcNow + (timeout ?? TimeSpan.FromSeconds(2));
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
