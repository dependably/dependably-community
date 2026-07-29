using Dapper;

namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// Dapper-backed store for <c>alert</c> rows. <see cref="TryInsertAsync"/> is the entire dedup
/// mechanism: the UNIQUE(org_id, type, source_ref) constraint plus ON CONFLICT DO NOTHING means a
/// repeat trigger for the same natural key is a no-op — the caller tells a fresh alert from a
/// deduped repeat by the affected-row count, with no read-before-write race. Every query filters
/// on org_id (tenant isolation; <see cref="GetByIdAsync"/> doubles as the BOLA guard).
/// </summary>
public sealed class AlertRepository
{
    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public AlertRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    private string NowIso() => _time.GetUtcNow().ToUtcIso();

    /// <summary>
    /// Inserts a new alert row, deduplicated on (org_id, type, source_ref). Returns the inserted
    /// <see cref="AlertRecord"/> on a fresh insert, or null when an alert with the same natural
    /// key already exists (the conflict makes the insert a no-op) — callers use the null/non-null
    /// result to decide whether to notify.
    /// </summary>
    public async Task<AlertRecord?> TryInsertAsync(NewAlert alert, CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        var nowOffset = _time.GetUtcNow();
        string now = nowOffset.ToUtcIso();

        await using var conn = await _db.OpenAsync(ct);
        int rows = await conn.ExecuteAsync(
            """
            INSERT INTO alert (id, org_id, type, severity, source_ref, ecosystem, purl, title, detail, state, created_at, updated_at)
            VALUES (@id, @orgId, @type, @severity, @sourceRef, @ecosystem, @purl, @title, @detail, 'active', @now, @now)
            ON CONFLICT (org_id, type, source_ref) DO NOTHING
            """,
            new
            {
                id,
                orgId = alert.OrgId,
                type = alert.Type,
                severity = alert.Severity,
                sourceRef = alert.SourceRef,
                ecosystem = alert.Ecosystem,
                purl = alert.Purl,
                title = alert.Title,
                detail = alert.Detail,
                now
            });

        return rows == 0
            ? null
            : new AlertRecord(
                id, alert.OrgId, alert.Type, alert.Severity, alert.SourceRef, alert.Ecosystem,
                alert.Purl, alert.Title, alert.Detail, "active",
                DismissedBy: null, DismissedAt: null, SlackStatus: null, SlackError: null,
                EmailStatus: null, EmailError: null,
                CreatedAt: nowOffset, UpdatedAt: nowOffset);
    }

    /// <summary>Paged, newest-first list of alerts for an org, optionally filtered by state.</summary>
    public async Task<(IReadOnlyList<AlertRecord> Items, int Total)> ListAsync(
        string orgId, string? state, int limit, int offset, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<AlertRecord>(
            """
            SELECT id AS Id, org_id AS OrgId, type AS Type, severity AS Severity, source_ref AS SourceRef,
                   ecosystem AS Ecosystem, purl AS Purl, title AS Title, detail AS Detail, state AS State,
                   dismissed_by AS DismissedBy, dismissed_at AS DismissedAt,
                   slack_status AS SlackStatus, slack_error AS SlackError,
                   email_status AS EmailStatus, email_error AS EmailError,
                   created_at AS CreatedAt, updated_at AS UpdatedAt
            FROM alert
            WHERE org_id = @orgId
              AND (@state IS NULL OR state = @state)
            ORDER BY created_at DESC
            LIMIT @limit OFFSET @offset
            """,
            new { orgId, state, limit, offset });
        int total = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM alert WHERE org_id = @orgId AND (@state IS NULL OR state = @state)",
            new { orgId, state });
        return (rows.ToList(), total);
    }

    /// <summary>Active-alert count for an org — backs the bell badge.</summary>
    public async Task<int> CountActiveAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM alert WHERE org_id = @orgId AND state = 'active'",
            new { orgId });
    }

    /// <summary>Org-scoped lookup — a cross-tenant id comes back null (BOLA guard).</summary>
    public async Task<AlertRecord?> GetByIdAsync(string orgId, string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<AlertRecord>(
            """
            SELECT id AS Id, org_id AS OrgId, type AS Type, severity AS Severity, source_ref AS SourceRef,
                   ecosystem AS Ecosystem, purl AS Purl, title AS Title, detail AS Detail, state AS State,
                   dismissed_by AS DismissedBy, dismissed_at AS DismissedAt,
                   slack_status AS SlackStatus, slack_error AS SlackError,
                   email_status AS EmailStatus, email_error AS EmailError,
                   created_at AS CreatedAt, updated_at AS UpdatedAt
            FROM alert WHERE id = @id AND org_id = @orgId
            """,
            new { id, orgId });
    }

    /// <summary>
    /// Dismisses an active alert. Returns false when the alert was already dismissed (idempotent
    /// no-op — the state predicate makes the update zero rows) or the id/org didn't match.
    /// </summary>
    public async Task<bool> DismissAsync(
        string orgId, string id, string? dismissedBy, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string now = NowIso();
        int rows = await conn.ExecuteAsync(
            """
            UPDATE alert
            SET state = 'dismissed', dismissed_by = @dismissedBy, dismissed_at = @now, updated_at = @now
            WHERE id = @id AND org_id = @orgId AND state = 'active'
            """,
            new { orgId, id, dismissedBy, now });
        return rows > 0;
    }

    /// <summary>
    /// Records the terminal outcome of an async Slack delivery attempt on the alert row. Called by
    /// the management-plane Slack delivery queue after a success or exhausted-retry failure.
    /// </summary>
    public async Task RecordSlackOutcomeAsync(
        string orgId, string id, string status, string? error, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            UPDATE alert SET slack_status = @status, slack_error = @error, updated_at = @now
            WHERE id = @id AND org_id = @orgId
            """,
            new { orgId, id, status, error, now = NowIso() });
    }

    /// <summary>
    /// Records the terminal outcome of an async email delivery attempt on the alert row. Called by
    /// the management-plane email delivery queue after a success or exhausted-retry failure.
    /// </summary>
    public async Task RecordEmailOutcomeAsync(
        string orgId, string id, string status, string? error, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            UPDATE alert SET email_status = @status, email_error = @error, updated_at = @now
            WHERE id = @id AND org_id = @orgId
            """,
            new { orgId, id, status, error, now = NowIso() });
    }

    /// <summary>
    /// Reads the three raise-gating columns off <c>alert_settings</c> without touching the
    /// envelope-encrypted Slack webhook URL, so <see cref="AlertService"/> (Core) can gate raising
    /// without depending on <c>EnvelopeProtector</c> or the management plane. An absent settings
    /// row returns the documented defaults (both alert types on, HIGH severity floor) — there is
    /// no backfill migration, every org reads through this same default path.
    /// </summary>
    public async Task<AlertRaiseSettings> GetRaiseSettingsAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<RawRaiseSettings>(
            """
            SELECT quarantine_alerts_enabled AS QuarantineAlertsEnabled,
                   vuln_alerts_enabled AS VulnAlertsEnabled,
                   vuln_min_severity AS VulnMinSeverity
            FROM alert_settings WHERE org_id = @orgId
            """,
            new { orgId });

        return row is null
            ? new AlertRaiseSettings(QuarantineAlertsEnabled: true, VulnAlertsEnabled: true, VulnMinSeverity: "HIGH")
            : new AlertRaiseSettings(
                row.QuarantineAlertsEnabled != 0, row.VulnAlertsEnabled != 0, row.VulnMinSeverity);
    }

    // SQLite returns INTEGER columns as Int64; use long here to avoid Dapper constructor-matching
    // errors, then convert to bool in GetRaiseSettingsAsync.
    private sealed record RawRaiseSettings(
        long QuarantineAlertsEnabled, long VulnAlertsEnabled, string VulnMinSeverity);
}

/// <summary>Fields required to raise a new alert (before the id/state/timestamps are assigned).</summary>
public sealed record NewAlert(
    string OrgId,
    string Type,
    string? Severity,
    string SourceRef,
    string? Ecosystem,
    string? Purl,
    string Title,
    string? Detail);

/// <summary>A persisted <c>alert</c> row.</summary>
public sealed record AlertRecord(
    string Id,
    string OrgId,
    string Type,
    string? Severity,
    string SourceRef,
    string? Ecosystem,
    string? Purl,
    string Title,
    string? Detail,
    string State,
    string? DismissedBy,
    DateTimeOffset? DismissedAt,
    string? SlackStatus,
    string? SlackError,
    string? EmailStatus,
    string? EmailError,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);

/// <summary>The subset of <c>alert_settings</c> that gates whether raising happens at all.</summary>
public sealed record AlertRaiseSettings(
    bool QuarantineAlertsEnabled, bool VulnAlertsEnabled, string VulnMinSeverity);
