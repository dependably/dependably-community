namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// Fans a freshly-raised alert out to every registered delivery channel — currently
/// <see cref="AlertSlackQueue"/> and <see cref="AlertEmailQueue"/>, both of which keep
/// implementing <see cref="IAlertNotifier"/> themselves and are enqueued independently. This is
/// the single <see cref="IAlertNotifier"/> <see cref="AlertService"/> resolves — the composite,
/// not either child queue, is what the management DI container
/// registers under the seam. One channel throwing (each <see cref="IAlertNotifier.Notify"/> call
/// is expected to be non-blocking and non-throwing, but a defensive catch here keeps a bug in one
/// channel from ever suppressing the other) never prevents the remaining channels from being
/// notified.
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

    public void Notify(AlertRecord alert)
    {
        foreach (var notifier in _notifiers)
        {
            try
            {
                notifier.Notify(alert);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "{ExceptionType} notifying {NotifierType} of alert {AlertId} (org {OrgId}); other delivery channels are still notified.",
                    ex.GetType().Name, notifier.GetType().Name, alert.Id, alert.OrgId);
            }
        }
    }
}
