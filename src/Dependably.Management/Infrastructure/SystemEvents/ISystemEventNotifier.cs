namespace Dependably.Infrastructure.SystemEvents;

/// <summary>
/// Dispatch seam for the operator-realm (system-scope) Slack channel. This is a deliberately
/// separate seam from <see cref="Dependably.Infrastructure.Alerts.IAlertNotifier"/>: an
/// <see cref="ISystemEventNotifier"/> implementation receives only control-plane events raised
/// by system-realm (apex, <c>scope=system</c>) actions — tenant lifecycle changes and operator
/// account changes — and must never be wired into <c>IAlertNotifier</c>/<c>AlertService</c> or
/// used to mirror a per-org quarantine or vulnerability alert. <see cref="SystemEventRecord"/>'s
/// shape enforces this structurally: it carries an action name plus tenant slug/name/actor only,
/// so there is no field through which a package name, vulnerability detail, or member email could
/// reach the operator Slack channel.
/// </summary>
public interface ISystemEventNotifier
{
    /// <summary>
    /// Notifies the configured delivery channel that <paramref name="record"/> just occurred.
    /// Non-blocking; a delivery failure is recorded internally by the implementation and never
    /// propagated back to the system-realm action that raised the event.
    /// </summary>
    void Notify(SystemEventRecord record);
}

/// <summary>
/// A control-plane event raised by a system-realm action, and the entire payload surface the
/// operator Slack channel is allowed to see for it. <paramref name="Action"/> is the audit-log
/// action string (e.g. <c>"tenant.created"</c>); <paramref name="TenantSlug"/> and
/// <paramref name="TenantName"/> identify the tenant the event concerns (both null for events
/// with no tenant, such as an operator-account change); <paramref name="Actor"/> is the acting
/// operator's identity (null for background-job-raised events such as the retention sweep's
/// hard-delete). Nothing beyond these four fields — a package name, vulnerability detail, or
/// tenant member email has no field to travel through.
/// </summary>
public sealed record SystemEventRecord(string Action, string? TenantSlug, string? TenantName, string? Actor);
