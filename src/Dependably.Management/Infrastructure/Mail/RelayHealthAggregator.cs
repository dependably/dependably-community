using Dapper;
using Dependably.Storage;

namespace Dependably.Infrastructure.Mail;

/// <summary>
/// The operator's aggregate view of the one shared SMTP relay: how many tenants are currently
/// failing to deliver, how bad the worst streak is, when it started, and the durable outbox's
/// backlog. A per-org row on <c>alert_settings</c> answers "did my mail land" — a question a bad
/// recipient can answer negatively while the relay is perfectly healthy. This aggregate answers a
/// different question — "is the shared relay itself in trouble, and how many tenants does that
/// affect" — which no single tenant's row can answer on its own.
///
/// <para>
/// <b>Derived, not instance-level, and why.</b> The natural alternative is a single instance-level
/// fact ("the relay is down") written once rather than read back by aggregating N per-tenant rows.
/// That is deliberately not what this does yet: no such fact exists in the schema today, and the
/// concurrently-developed transport circuit breaker is exactly the mechanism that will compute one
/// (a trip decision needs the same "is the relay currently failing" signal this aggregate derives).
/// Introducing a second, differently-computed instance-level fact ahead of the breaker would be the
/// duplicate-source-of-truth failure this surface exists to avoid, not the fix for it. Once the
/// breaker's transport-scope state lands, this aggregate's <see cref="RelayHealthView.Unhealthy"/>,
/// <see cref="RelayHealthView.ConsecutiveFailures"/>, and <see cref="RelayHealthView.FirstFailureAt"/>
/// fields should be read from that state directly rather than re-derived here — the aggregation
/// below is the interim answer, not a second computation to keep in sync with it.
/// </para>
///
/// <para>
/// <b>Affected-tenant count, never a tenant list.</b> This never returns tenant identifiers. In
/// multi-tenant mode the aggregate renders in the system_admin SPA, which must never show tenant
/// business data; a count is control-plane metadata, a list of slugs is tenant business data by a
/// different name. Fixing a relay outage is an action taken on the relay (credentials, host,
/// firewall) — it needs "how many tenants does this affect", not "which ones", so there is no
/// operator need that a list would serve here.
/// </para>
/// </summary>
public sealed class RelayHealthAggregator
{
    private readonly IMetadataStore _db;
    private readonly EmailOutboxRepository _outbox;

    public RelayHealthAggregator(IMetadataStore db, EmailOutboxRepository outbox)
    {
        _db = db;
        _outbox = outbox;
    }

    public async Task<RelayHealthView> GetAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        var affected = new { enabled = 1, failed = "failed" };

        // Three plain scalar aggregates rather than one combined SELECT — the same shape
        // EmailOutboxRepository.GetBacklogAsync uses, for the same reason: under SQLite, MIN()/MAX()
        // over a TEXT column across an empty (all-filtered-out) group loses its declared type and
        // comes back as a byte[], which then fails Dapper's string mapping.
        //
        // xtenant: the operator's relay-health aggregate is deliberately cross-tenant — one shared
        // SMTP transport, so its health is read as one fact about every currently-enabled email
        // channel, not one tenant's row. Only counts and aggregates cross the boundary; no org_id
        // or tenant identifier is projected.
        int affectedTenants = await conn.ExecuteScalarAsync<int>(new CommandDefinition(
            "SELECT COUNT(*) FROM alert_settings WHERE email_enabled = @enabled AND email_last_status = @failed",
            affected, cancellationToken: ct));

        // xtenant: same instance-wide gauge as the count above.
        int? consecutiveFailures = await conn.ExecuteScalarAsync<int?>(new CommandDefinition(
            "SELECT MAX(email_consecutive_failures) FROM alert_settings WHERE email_enabled = @enabled AND email_last_status = @failed",
            affected, cancellationToken: ct));

        // xtenant: same instance-wide gauge as the count above.
        string? firstFailureAt = await conn.ExecuteScalarAsync<string?>(new CommandDefinition(
            "SELECT MIN(email_failing_since) FROM alert_settings WHERE email_enabled = @enabled AND email_last_status = @failed",
            affected, cancellationToken: ct));

        var backlog = await _outbox.GetBacklogAsync(ct);

        return new RelayHealthView(
            Unhealthy: affectedTenants > 0,
            AffectedTenants: affectedTenants,
            ConsecutiveFailures: consecutiveFailures ?? 0,
            FirstFailureAt: firstFailureAt,
            BacklogDepth: backlog.Depth,
            OldestQueuedAt: backlog.OldestCreatedAt,
            DeadLettered: backlog.DeadLettered,
            Expired: backlog.Expired);
    }
}

/// <summary>
/// Operator-facing shape of <see cref="RelayHealthAggregator.GetAsync"/>. Every field is a count or
/// an aggregate timestamp — never a tenant identifier — so the same view is safe to render
/// unmodified in the multi-mode system_admin SPA and the single-mode tenant admin's Settings page.
/// </summary>
public sealed record RelayHealthView(
    bool Unhealthy,
    int AffectedTenants,
    int ConsecutiveFailures,
    string? FirstFailureAt,
    int BacklogDepth,
    string? OldestQueuedAt,
    int DeadLettered,
    int Expired);
