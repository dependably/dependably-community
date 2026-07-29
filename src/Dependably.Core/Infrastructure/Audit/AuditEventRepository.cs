using Dapper;

namespace Dependably.Infrastructure.Audit;

/// <summary>
/// Persistence for <see cref="AuditEvent"/> on the <c>audit_event</c> table. Append-only;
/// no UPDATE/DELETE methods exist by design.
/// </summary>
public sealed class AuditEventRepository
{
    private readonly IMetadataStore _db;

    public AuditEventRepository(IMetadataStore db) { _db = db; }

    public async Task InsertAsync(AuditEvent ev, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync("""
            INSERT INTO audit_event (
                event_id, schema_version, event_type, org_id, tenant_resolver,
                actor_type, actor_id, request_id, source_ip, user_agent,
                outcome, payload, occurred_at)
            VALUES (
                @EventId, @SchemaVersion, @EventType, @OrgId, @TenantResolver,
                @ActorType, @ActorId, @RequestId, @SourceIp, @UserAgent,
                @Outcome, @Payload, @OccurredAt)
            """,
            new
            {
                ev.EventId,
                ev.SchemaVersion,
                ev.EventType,
                ev.OrgId,
                ev.TenantResolver,
                ev.ActorType,
                ev.ActorId,
                ev.RequestId,
                ev.SourceIp,
                ev.UserAgent,
                ev.Outcome,
                ev.Payload,
                // Millisecond precision, matching audit_log/activity: this append-only forensic
                // table needs a deterministic order for events sharing a wall-clock second. Bound
                // explicitly rather than through the global DateTimeOffsetHandler default (second
                // precision) — passing `ev` directly here would silently drop the sub-second
                // component this table's ordering relies on.
                OccurredAt = ev.OccurredAt.ToUtcIsoMillis(),
            });
    }

    public async Task<IReadOnlyList<AuditEvent>> ListByTenantAsync(
        string orgId, int limit, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<AuditEvent>("""
            SELECT event_id AS EventId, schema_version AS SchemaVersion, event_type AS EventType,
                   org_id AS OrgId, tenant_resolver AS TenantResolver, actor_type AS ActorType,
                   actor_id AS ActorId, request_id AS RequestId, source_ip AS SourceIp,
                   user_agent AS UserAgent, outcome AS Outcome, payload AS Payload,
                   occurred_at AS OccurredAt
            FROM audit_event
            WHERE org_id = @orgId
            ORDER BY occurred_at DESC, event_id DESC
            LIMIT @limit
            """, new { orgId, limit });
        return rows.AsList();
    }
}
