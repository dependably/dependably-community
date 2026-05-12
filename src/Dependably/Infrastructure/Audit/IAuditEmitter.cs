namespace Dependably.Infrastructure.Audit;

/// <summary>
/// Persists typed audit events. Callers construct an event description (event type, org,
/// actor, outcome, JSON payload) and the emitter fills in the envelope (event id, request id,
/// source ip, user agent, occurred-at) from the current request context.
///
/// Failure to persist a successful operation's audit event is logged at error level — audit
/// gaps are a security concern. Callers do not handle the exception; the emitter is
/// fire-and-forget from their perspective.
/// </summary>
public interface IAuditEmitter
{
    /// <summary>
    /// Emit an event. <paramref name="payloadJson"/> is the per-event-type JSON shape.
    /// </summary>
    Task EmitAsync(
        string eventType,
        string? orgId,
        string actorType,
        string? actorId,
        string outcome,
        string payloadJson,
        CancellationToken ct = default);
}
