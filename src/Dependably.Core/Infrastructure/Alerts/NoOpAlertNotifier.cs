namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// <see cref="IAlertNotifier"/> that discards every notification. Registered by the headless edge
/// composition root and any host that never wires the management plane: Slack delivery (the
/// bounded-channel queue, the SSRF-guarded typed client, and the settings repository holding the
/// envelope-encrypted webhook URL) lives entirely in <c>Dependably.Management</c>. The no-op
/// keeps <see cref="AlertService"/> — a hard dependency of the Core quarantine and vulnerability
/// pipelines — resolvable without pulling the management plane into the edge closure. Alerts are
/// still raised and persisted; only the outbound Slack push is skipped.
/// </summary>
public sealed class NoOpAlertNotifier : IAlertNotifier
{
    public void Notify(AlertRecord alert)
    {
        // Intentionally empty: no Slack delivery plane is wired in this composition root.
    }
}
