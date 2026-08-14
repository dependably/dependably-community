namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// Fans a freshly-raised alert out to every registered delivery channel — currently
/// <see cref="AlertSlackQueue"/> and <see cref="AlertEmailQueue"/>, both of which keep
/// implementing <see cref="IAlertNotifier"/> themselves and are enqueued independently. This is
/// the single <see cref="IAlertNotifier"/> <see cref="AlertService"/> resolves — the composite,
/// not either child queue, is what the management DI container
/// registers under the seam. One channel throwing (each <see cref="IAlertNotifier.NotifyAsync"/>
/// call is expected to queue without throwing, but a defensive catch here keeps a bug — or a
/// database failure in the durable email outbox — from ever suppressing the other) never prevents
/// the remaining channels from being notified. Channels are notified sequentially: the two queue
/// writes are cheap, and running them in order keeps a failure attributable to one channel.
/// </summary>
public sealed class CompositeAlertNotifier : IAlertNotifier
{
    private readonly IReadOnlyList<IAlertNotifier> _notifiers;
    private readonly ILogger<CompositeAlertNotifier> _logger;

    public CompositeAlertNotifier(IReadOnlyList<IAlertNotifier> notifiers, ILogger<CompositeAlertNotifier> logger)
    {
        _notifiers = notifiers;
        _logger = logger;
    }

    public async Task NotifyAsync(AlertRecord alert, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(alert);

        foreach (var notifier in _notifiers)
        {
            try
            {
                await notifier.NotifyAsync(alert, ct);
            }
            // Cancellation is host shutdown, not a channel bug: let it stop the fan-out rather than
            // logging one "channel failed" warning per remaining channel.
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex,
                    "{ExceptionType} notifying {NotifierType} of alert {AlertId} (org {OrgId}); other delivery channels are still notified.",
                    ex.GetType().Name, notifier.GetType().Name, alert.Id, alert.OrgId);
            }
        }
    }
}
