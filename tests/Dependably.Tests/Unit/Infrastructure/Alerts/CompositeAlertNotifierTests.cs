using Dependably.Infrastructure.Alerts;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Infrastructure.Alerts;

/// <summary>
/// <see cref="CompositeAlertNotifier"/> fans a raised alert out to every registered channel. The
/// partial-failure case — one channel throwing — must never suppress delivery to the others,
/// since <see cref="IAlertNotifier.NotifyAsync"/> is meant to queue rather than deliver, and a bug
/// (or a database failure in the durable email outbox) must not silently swallow Slack alongside it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CompositeAlertNotifierTests
{
    private static AlertRecord SampleAlert() => new(
        Id: "alert1", OrgId: "org1", Type: AlertTypes.QuarantineNew, Severity: null, SourceRef: "ref",
        Ecosystem: "npm", Purl: "pkg:npm/x@1.0.0", Title: "New quarantine item", Detail: null,
        State: "active", DismissedBy: null, DismissedAt: null, SlackStatus: null, SlackError: null,
        EmailStatus: null, EmailError: null,
        CreatedAt: TestTime.KnownNow, UpdatedAt: TestTime.KnownNow);

    private sealed class RecordingNotifier : IAlertNotifier
    {
        public int Calls { get; private set; }

        public Task NotifyAsync(AlertRecord alert, CancellationToken ct = default)
        {
            Calls++;
            return Task.CompletedTask;
        }
    }

    /// <summary>Throws from the awaited body, the shape a failed durable outbox write takes.</summary>
    private sealed class ThrowingNotifier : IAlertNotifier
    {
        public int Calls { get; private set; }

        public async Task NotifyAsync(AlertRecord alert, CancellationToken ct = default)
        {
            Calls++;
            await Task.Yield();
            throw new InvalidOperationException("channel exploded");
        }
    }

    [Fact]
    public async Task NotifyAsync_FansToEachChildExactlyOnce()
    {
        var slack = new RecordingNotifier();
        var email = new RecordingNotifier();
        var composite = new CompositeAlertNotifier([slack, email], NullLogger<CompositeAlertNotifier>.Instance);

        await composite.NotifyAsync(SampleAlert());

        Assert.Equal(1, slack.Calls);
        Assert.Equal(1, email.Calls);
    }

    [Fact]
    public async Task NotifyAsync_OneChildThrows_OtherChannelStillNotified()
    {
        var throwing = new ThrowingNotifier();
        var recording = new RecordingNotifier();
        var composite = new CompositeAlertNotifier([throwing, recording], NullLogger<CompositeAlertNotifier>.Instance);

        // Must not throw back to the caller — AlertService treats notification as best-effort.
        await composite.NotifyAsync(SampleAlert());

        Assert.Equal(1, throwing.Calls);
        Assert.Equal(1, recording.Calls);
    }

    [Fact]
    public async Task NotifyAsync_OrderReversed_ThrowingChannelSecond_FirstChannelStillNotified()
    {
        var recording = new RecordingNotifier();
        var throwing = new ThrowingNotifier();
        var composite = new CompositeAlertNotifier([recording, throwing], NullLogger<CompositeAlertNotifier>.Instance);

        await composite.NotifyAsync(SampleAlert());

        Assert.Equal(1, recording.Calls);
        Assert.Equal(1, throwing.Calls);
    }
}
