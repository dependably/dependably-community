using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Review queue for policy-gate blocks. <see cref="UpsertPendingAsync"/> is called by the
/// block gate beside every automatic block: the UNIQUE(org_id, purl) constraint plus the
/// state-guarded ON CONFLICT update mean repeat blocks refresh the pending row (latest gate +
/// detail win) and never resurrect a decided one. Decisions flow through
/// <see cref="DecideAsync"/>; the manual block/unblock endpoints call
/// <see cref="ResolveForVersionAsync"/> so the two surfaces can't disagree.
/// </summary>
public sealed class QuarantineRepository
{
    private readonly IMetadataStore _db;

    public QuarantineRepository(IMetadataStore db)
    {
        _db = db;
    }

    private static string NowIso() => DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

    /// <summary>
    /// Records (or refreshes) the pending review row for a blocked purl. A decided row is
    /// left untouched — the conflict update's state predicate makes the upsert a no-op then.
    /// </summary>
    public async Task UpsertPendingAsync(
        string orgId, string ecosystem, string purl, string gate,
        string? detail, string? packageVersionId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO quarantine (id, org_id, package_version_id, ecosystem, purl, gate, detail, state, updated_at)
            VALUES (@id, @orgId, @packageVersionId, @ecosystem, @purl, @gate, @detail, 'pending', @now)
            ON CONFLICT (org_id, purl) DO UPDATE SET
                gate = excluded.gate,
                detail = excluded.detail,
                package_version_id = COALESCE(excluded.package_version_id, quarantine.package_version_id),
                updated_at = excluded.updated_at
            WHERE quarantine.state = 'pending'
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, packageVersionId, ecosystem, purl, gate, detail, now = NowIso() });
    }

    public async Task<(IReadOnlyList<QuarantineEntry> Items, int Total)> ListAsync(
        string orgId, string? state, string? ecosystem, int limit, int offset,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<QuarantineEntry>(
            """
            SELECT id, org_id AS OrgId, package_version_id AS PackageVersionId,
                   ecosystem, purl, gate, detail, state,
                   decided_by AS DecidedBy, decided_at AS DecidedAt, note,
                   created_at AS CreatedAt, updated_at AS UpdatedAt
            FROM quarantine
            WHERE org_id = @orgId
              AND (@state IS NULL OR state = @state)
              AND (@ecosystem IS NULL OR ecosystem = @ecosystem)
            ORDER BY updated_at DESC
            LIMIT @limit OFFSET @offset
            """,
            new { orgId, state, ecosystem, limit, offset });
        int total = await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*) FROM quarantine
            WHERE org_id = @orgId
              AND (@state IS NULL OR state = @state)
              AND (@ecosystem IS NULL OR ecosystem = @ecosystem)
            """,
            new { orgId, state, ecosystem });
        return (rows.ToList(), total);
    }

    /// <summary>Org-scoped lookup — a cross-tenant id comes back null (BOLA guard).</summary>
    public async Task<QuarantineEntry?> GetByIdAsync(string orgId, string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<QuarantineEntry>(
            """
            SELECT id, org_id AS OrgId, package_version_id AS PackageVersionId,
                   ecosystem, purl, gate, detail, state,
                   decided_by AS DecidedBy, decided_at AS DecidedAt, note,
                   created_at AS CreatedAt, updated_at AS UpdatedAt
            FROM quarantine WHERE id = @id AND org_id = @orgId
            """,
            new { id, orgId });
    }

    /// <summary>
    /// Applies a decision to a pending row. Returns false when the row was already decided
    /// (the state predicate makes a double-decide update zero rows) — the controller maps
    /// that to 409.
    /// </summary>
    public async Task<bool> DecideAsync(
        string orgId, string id, string decision, string? decidedBy, string? note,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        int rows = await conn.ExecuteAsync(
            """
            UPDATE quarantine
            SET state = @decision, decided_by = @decidedBy, decided_at = @now, note = @note, updated_at = @now
            WHERE id = @id AND org_id = @orgId AND state = 'pending'
            """,
            new { orgId, id, decision, decidedBy, note, now = NowIso() });
        return rows > 0;
    }

    /// <summary>
    /// Resolves any pending row for a version when an operator uses the manual block/unblock
    /// endpoints directly, so the review queue can't disagree with the version's
    /// manual_block_state. Manual allow ⇒ approved; manual block ⇒ denied.
    /// </summary>
    public async Task ResolveForVersionAsync(
        string orgId, string packageVersionId, string manualState, string? decidedBy,
        CancellationToken ct = default)
    {
        string state = manualState == "allowed" ? "approved" : "denied";
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            UPDATE quarantine
            SET state = @state, decided_by = @decidedBy, decided_at = @now,
                note = 'resolved via manual ' || @manualState, updated_at = @now
            WHERE org_id = @orgId AND package_version_id = @packageVersionId AND state = 'pending'
            """,
            new { orgId, packageVersionId, state, manualState, decidedBy, now = NowIso() });
    }

    /// <summary>
    /// True when the purl has an approved review — the first-fetch analog of the manual allow
    /// override, for blocks recorded before any version row existed.
    /// </summary>
    public async Task<bool> HasApprovedForPurlAsync(string orgId, string purl, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM quarantine WHERE org_id = @orgId AND purl = @purl AND state = 'approved'",
            new { orgId, purl });
        return count > 0;
    }
}

public sealed class QuarantineEntry
{
    public string Id { get; init; } = "";
    public string OrgId { get; init; } = "";
    public string? PackageVersionId { get; init; }
    public string Ecosystem { get; init; } = "";
    public string Purl { get; init; } = "";
    public string Gate { get; init; } = "";
    public string? Detail { get; init; }
    public string State { get; init; } = "pending";
    public string? DecidedBy { get; init; }
    public DateTimeOffset? DecidedAt { get; init; }
    public string? Note { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset UpdatedAt { get; init; }
}
