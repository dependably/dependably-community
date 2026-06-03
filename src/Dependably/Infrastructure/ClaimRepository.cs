using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Persistence for the per-tenant package-name claim model. Two tables:
/// <c>claim</c> (current state per <c>(org, ecosystem, name)</c>) and <c>claim_history</c>
/// (append-only transitions). State transitions go through <see cref="ClaimStateMachine"/>;
/// this repository is a thin DB layer that does not enforce the rules itself.
/// </summary>
public sealed class ClaimRepository
{
    private readonly IMetadataStore _db;

    public ClaimRepository(IMetadataStore db) { _db = db; }

    public async Task<NameClaim?> GetAsync(
        string orgId, string ecosystem, string name, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<NameClaim>("""
            SELECT id AS Id, org_id AS OrgId, ecosystem AS Ecosystem, name AS Name,
                   state AS State, reason AS Reason, created_by AS CreatedBy,
                   created_at AS CreatedAt, updated_at AS UpdatedAt, deleted_at AS DeletedAt
            FROM claim
            WHERE org_id = @orgId AND ecosystem = @ecosystem AND name = @name
              AND deleted_at IS NULL
            """, new { orgId, ecosystem, name });
    }

    public async Task<IReadOnlyList<NameClaim>> ListAsync(
        string orgId, string? ecosystem = null, string? state = null,
        string? search = null, int limit = 100, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<NameClaim>("""
            SELECT id AS Id, org_id AS OrgId, ecosystem AS Ecosystem, name AS Name,
                   state AS State, reason AS Reason, created_by AS CreatedBy,
                   created_at AS CreatedAt, updated_at AS UpdatedAt, deleted_at AS DeletedAt
            FROM claim
            WHERE org_id = @orgId
              AND deleted_at IS NULL
              AND (@ecosystem IS NULL OR ecosystem = @ecosystem)
              AND (@state IS NULL OR state = @state)
              AND (@search IS NULL OR name LIKE @searchPattern)
            ORDER BY ecosystem, name
            LIMIT @limit
            """, new
        {
            orgId, ecosystem, state, search,
            searchPattern = search is null ? null : $"%{search}%",
            limit
        });
        return rows.AsList();
    }

    /// <summary>
    /// Persists a claim transition: writes/updates the <c>claim</c> row and appends a
    /// <c>claim_history</c> entry. Idempotent at the SQL layer — concurrent transitions on
    /// the same name resolve through the unique constraint on <c>(org_id, ecosystem, name)</c>.
    /// On release, <c>NewState</c> is recorded as <c>unclaimed</c> in history; the claim row
    /// itself is soft-deleted via <c>deleted_at</c>.
    /// </summary>
    public async Task ApplyTransitionAsync(
        ClaimTransition tx, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await using var dbTx = await conn.BeginTransactionAsync(ct);
        try
        {
            if (tx.PriorState is null)
            {
                // Creation — insert claim row.
                await conn.ExecuteAsync("""
                    INSERT INTO claim (id, org_id, ecosystem, name, state, reason, created_by, created_at, updated_at)
                    VALUES (@ClaimId, @OrgId, @Ecosystem, @Name, @NewState, @Reason, @ActorId, @OccurredAt, @OccurredAt)
                    """, tx, dbTx);
            }
            else if (tx.NewState is null)
            {
                // Release — soft-delete claim row.
                await conn.ExecuteAsync(
                    "UPDATE claim SET deleted_at = @OccurredAt, updated_at = @OccurredAt WHERE id = @ClaimId",
                    tx, dbTx);
            }
            else
            {
                // State change.
                await conn.ExecuteAsync(
                    "UPDATE claim SET state = @NewState, reason = @Reason, updated_at = @OccurredAt WHERE id = @ClaimId",
                    tx, dbTx);
            }

            await conn.ExecuteAsync("""
                INSERT INTO claim_history (
                    id, org_id, claim_id, ecosystem, name,
                    prior_state, new_state, reason, purged_count, actor_id, occurred_at)
                VALUES (
                    @HistoryId, @OrgId, @ClaimId, @Ecosystem, @Name,
                    @PriorState, @HistoryNewState, @Reason, @PurgedCount, @ActorId, @OccurredAt)
                """, new
                {
                    tx.HistoryId, tx.OrgId, tx.ClaimId, tx.Ecosystem, tx.Name,
                    tx.PriorState,
                    HistoryNewState = tx.NewState ?? ClaimStateMachine.Unclaimed,
                    tx.Reason, tx.PurgedCount, tx.ActorId, tx.OccurredAt
                }, dbTx);

            await dbTx.CommitAsync(ct);
        }
        catch
        {
            await dbTx.RollbackAsync(ct);
            throw;
        }
    }

    public async Task<int> CountLocalVersionsAsync(
        string orgId, string ecosystem, string name, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<int>("""
            SELECT COUNT(*)
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = @orgId
              AND p.ecosystem = @ecosystem
              AND p.purl_name = @name
              AND pv.origin = 'uploaded'
            """, new { orgId, ecosystem, name });
    }
}

public sealed class NameClaim
{
    public string Id { get; init; } = "";
    public string OrgId { get; init; } = "";
    public string Ecosystem { get; init; } = "";
    public string Name { get; init; } = "";
    public string State { get; init; } = "";
    public string Reason { get; init; } = "";
    public string? CreatedBy { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset UpdatedAt { get; init; }
    public DateTimeOffset? DeletedAt { get; init; }
}

/// <summary>
/// Describes one transition applied via <see cref="ClaimRepository.ApplyTransitionAsync"/>.
/// <c>PriorState == null</c> indicates creation; <c>NewState == null</c> indicates release.
/// </summary>
public sealed class ClaimTransition
{
    public string ClaimId { get; init; } = "";
    public string HistoryId { get; init; } = "";
    public string OrgId { get; init; } = "";
    public string Ecosystem { get; init; } = "";
    public string Name { get; init; } = "";
    public string? PriorState { get; init; }
    public string? NewState { get; init; }
    public string Reason { get; init; } = "";
    public int PurgedCount { get; init; }
    public string? ActorId { get; init; }
    public DateTimeOffset OccurredAt { get; init; }
}
