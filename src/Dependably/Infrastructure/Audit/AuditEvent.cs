namespace Dependably.Infrastructure.Audit;

/// <summary>
/// Typed audit event base record per #52. The envelope is mandatory and populated by
/// <see cref="IAuditEmitter"/> from the request context — <c>EventType</c>, <c>OrgId</c>,
/// <c>ActorType</c>, <c>Outcome</c>, and <c>Payload</c> are the only fields callers set
/// explicitly.
///
/// <c>Payload</c> is the JSON-serialised per-event-type shape. Concrete event records (e.g.
/// <c>PackagePublishEvent</c>, <c>ClaimTransitionEvent</c>) live alongside this file under
/// <c>Audit/Events/</c> — each defines its own properties, then serialises itself to
/// <c>Payload</c> when emitted. Adding a new event type does not require a schema migration;
/// the <c>audit_event</c> table is already shaped for it.
///
/// Property-style record (rather than positional) so Dapper can materialise via property
/// setters + the registered <c>DateTimeOffsetHandler</c>.
/// </summary>
public sealed class AuditEvent
{
    public string EventId { get; init; } = "";
    public int SchemaVersion { get; init; } = 1;
    public string EventType { get; init; } = "";
    public string? OrgId { get; init; }
    public string TenantResolver { get; init; } = "";
    public string ActorType { get; init; } = "";   // 'user' | 'api_token' | 'system'
    public string? ActorId { get; init; }
    public string? RequestId { get; init; }
    public string? SourceIp { get; init; }
    public string? UserAgent { get; init; }
    public string Outcome { get; init; } = "";     // 'accepted' | 'rejected' | 'error'
    public string Payload { get; init; } = "";     // JSON
    public DateTimeOffset OccurredAt { get; init; }
}
