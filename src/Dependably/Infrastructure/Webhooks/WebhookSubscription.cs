namespace Dependably.Infrastructure.Webhooks;

/// <summary>
/// Represents a user-configured webhook subscription row from the
/// <c>webhook_subscription</c> table. Secret is never returned in this view
/// model — the API always masks it to a <c>hasSecret</c> boolean.
/// </summary>
public sealed record WebhookSubscription(
    string Id,
    string OrgId,
    string Url,
    IReadOnlyList<string> EventTypes,
    bool Enabled,
    bool HasSecret,
    string? Description,
    string? LastDeliveryAt,
    string? LastStatus,
    int ConsecutiveFailures,
    string? FailingSince,
    string? LastError,
    string CreatedAt,
    string UpdatedAt);

/// <summary>
/// Row shape used only by the delivery fan-out path — includes the decrypted secret
/// so the dispatcher can sign payloads. Never exposed to API callers.
/// </summary>
internal sealed record WebhookSubscriptionDelivery(
    string Id,
    string OrgId,
    string Url,
    string? Secret,
    IReadOnlyList<string> EventTypes,
    int ConsecutiveFailures,
    string? FailingSince);
