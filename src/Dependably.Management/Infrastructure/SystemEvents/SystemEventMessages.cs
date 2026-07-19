using Microsoft.Extensions.Localization;

namespace Dependably.Infrastructure.SystemEvents;

/// <summary>
/// Renders a <see cref="SystemEventRecord"/> as the operator-Slack message text. One resx
/// template per action keeps the wording action-specific ("Dependably [system]: tenant 'acme'
/// created by ops@example.com") rather than a single catch-all sentence trying to cover every
/// action shape. An action this queue doesn't recognize falls back to a generic template so a
/// future <c>LogSystemAsync</c> call site that starts notifying never silently produces an empty
/// message.
/// </summary>
public static class SystemEventMessages
{
    public static string Build(SystemEventRecord record, IStringLocalizer<SharedResource> localizer)
    {
        string actor = string.IsNullOrEmpty(record.Actor)
            ? localizer["system.slack.actorUnknown"]
            : record.Actor;
        string slug = record.TenantSlug ?? "";

        return record.Action switch
        {
            "tenant.created" => localizer["system.slack.tenantCreated", slug, actor],
            "tenant.deleted" => localizer["system.slack.tenantDeleted", slug, actor],
            "tenant.restored" => localizer["system.slack.tenantRestored", slug, actor],
            "tenant.status_changed" => localizer["system.slack.tenantStatusChanged", slug, actor],
            // Raised by the retention sweep (TenantHardDeleteService), never by an operator
            // action — there is no actor to name.
            "tenant.hard_deleted" => localizer["system.slack.tenantHardDeleted", slug],
            "system_admin.admin_created" => localizer["system.slack.adminCreated", actor],
            "system_admin.admin_deleted" => localizer["system.slack.adminDeleted", actor],
            _ => localizer["system.slack.genericEvent", record.Action],
        };
    }
}
