namespace Dependably.Infrastructure.Audit;

/// <summary>
/// <see cref="IAuditEmitter"/> that discards every event. Registered only by the headless edge
/// composition root, which builds no management plane and therefore no <c>AuditEmitter</c> (that
/// implementation depends on the audit-event repository, SIEM queue, and webhook sink the edge
/// never wires up).
///
/// <para>An edge node is a cache-only pull-through: publish/push/import all fail closed with a 405
/// via <see cref="Edge.EdgePublishGuard"/>, so <see cref="Publish.PublishAuditor"/> never reaches
/// an emit call on this host. The no-op exists purely so the publish pipeline's DI graph resolves —
/// audit events from a cache edge have no store to land in and no consumer to forward to, so
/// discarding them is the honest behaviour rather than a silent partial-audit surface.</para>
/// </summary>
public sealed class NoOpAuditEmitter : IAuditEmitter
{
    public Task EmitAsync(
        string eventType,
        string? orgId,
        string actorType,
        string? actorId,
        string outcome,
        string payloadJson,
        CancellationToken ct = default) => Task.CompletedTask;
}
