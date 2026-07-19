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
            orgId,
            ecosystem,
            state,
            search,
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
    /// itself is soft-deleted via <c>deleted_at</c>. A creation transition against a name whose
    /// only row is a soft-deleted tombstone revives that row in place (see the creation arm
    /// below) rather than colliding with it on the unique index; a creation transition that
    /// races a still-live claim throws <see cref="ClaimConflictException"/> instead of letting
    /// the underlying UNIQUE-constraint violation escape as an unhandled exception.
    /// </summary>
    public async Task ApplyTransitionAsync(
        ClaimTransition tx, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await using var dbTx = await conn.BeginTransactionAsync(ct);
        try
        {
            string claimId = tx.ClaimId;
            if (tx.PriorState is null)
            {
                // Creation — insert claim row. Release soft-deletes rather than removes the row
                // (deleted_at set, see the release arm below) so claim_history keeps its FK
                // target and the row's audit trail intact; re-creating the same
                // (org, ecosystem, name) must therefore not collide with that tombstone on the
                // unique index. This INSERT is an UPSERT that revives a tombstoned row in place —
                // clearing deleted_at and refreshing every claim column, keeping the row's
                // original id — instead of failing. A conflict against a still-LIVE row is only
                // reachable via a race between two concurrent creates (a caller checks for a live
                // claim before building the transition); the WHERE guard makes that case a no-op
                // rather than a constraint violation, and the resulting empty RETURNING set is
                // surfaced as ClaimConflictException so callers can map it to a clean 409.
                string? persistedId = await conn.ExecuteScalarAsync<string>("""
                    INSERT INTO claim (id, org_id, ecosystem, name, state, reason, created_by, created_at, updated_at, deleted_at)
                    VALUES (@ClaimId, @OrgId, @Ecosystem, @Name, @NewState, @Reason, @ActorId, @OccurredAt, @OccurredAt, NULL)
                    ON CONFLICT (org_id, ecosystem, name) DO UPDATE SET
                        state = excluded.state,
                        reason = excluded.reason,
                        created_by = excluded.created_by,
                        created_at = excluded.created_at,
                        updated_at = excluded.updated_at,
                        deleted_at = NULL
                    WHERE claim.deleted_at IS NOT NULL
                    RETURNING id
                    """, tx, dbTx);
                claimId = persistedId ?? throw new ClaimConflictException(tx.OrgId, tx.Ecosystem, tx.Name);
            }
            else if (tx.NewState is null)
            {
                // Release — soft-delete claim row.
                // xtenant: keyed by claim PK; ClaimsController sets ClaimId from the row returned by
                // GetAsync(OrgId, ecosystem, name), so a claim outside the caller's org 404s first.
                await conn.ExecuteAsync(
                    "UPDATE claim SET deleted_at = @OccurredAt, updated_at = @OccurredAt WHERE id = @ClaimId",
                    tx, dbTx);
            }
            else
            {
                // State change.
                // xtenant: same org-scoped GetAsync-resolved claim PK as the release arm above.
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
                tx.HistoryId,
                tx.OrgId,
                ClaimId = claimId,
                tx.Ecosystem,
                tx.Name,
                tx.PriorState,
                HistoryNewState = tx.NewState ?? ClaimStateMachine.Unclaimed,
                tx.Reason,
                tx.PurgedCount,
                tx.ActorId,
                tx.OccurredAt
            }, dbTx);

            await dbTx.CommitAsync(ct);
        }
        catch
        {
            await dbTx.RollbackAsync(ct);
            throw;
        }
    }

    /// <summary>
    /// Patches the <c>purged_count</c> of an already-inserted <c>claim_history</c> row. Used
    /// when the transition is persisted before the proxy-artefact purge runs (see
    /// <c>ClaimsController</c>): the history row is written with <c>purged_count = 0</c> at
    /// persist time, then updated here once the purge completes and the real count is known.
    /// </summary>
    public async Task UpdateHistoryPurgedCountAsync(
        string historyId, int purgedCount, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: historyId is the server-generated PK from the ApplyTransitionAsync insert
        // earlier in the same request — no caller-supplied id crosses tenants.
        await conn.ExecuteAsync(
            "UPDATE claim_history SET purged_count = @purgedCount WHERE id = @historyId",
            new { historyId, purgedCount });
    }

    /// <summary>
    /// <see langword="true"/> when the org holds at least one hosted (origin='uploaded')
    /// version under <c>(org, ecosystem, name)</c>. Drives the implicit <c>local_only</c>
    /// resolution in <see cref="ClaimResolver"/> — a hosted name with no explicit claim must
    /// not be shadowable by upstream. EXISTS probe via the packages unique index so the
    /// per-request cost on the claim-row-miss path stays a point lookup.
    /// </summary>
    public async Task<bool> HasUploadedVersionsAsync(
        string orgId, string ecosystem, string name, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // SQLite surfaces EXISTS as 0/1, Postgres as boolean — Dapper's scalar conversion
        // handles both as bool.
        // plane-ok: intentional origin='uploaded' probe: the hosted-name-shadowing defense asks specifically whether a HOSTED version exists.
        return await conn.ExecuteScalarAsync<bool>("""
            SELECT EXISTS (
                SELECT 1
                FROM packages p
                JOIN package_versions pv ON pv.package_id = p.id
                WHERE p.org_id = @orgId
                  AND p.ecosystem = @ecosystem
                  AND p.purl_name = @name
                  AND pv.origin = 'uploaded')
            """, new { orgId, ecosystem, name });
    }

    public async Task<int> CountLocalVersionsAsync(
        string orgId, string ecosystem, string name, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // plane-ok: claim-release gate counts hosted-owned (origin='uploaded') versions; proxy artifacts are not org-owned for claim purposes.
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

/// <summary>
/// Thrown by <see cref="ClaimRepository.ApplyTransitionAsync"/> when a creation transition
/// collides with a claim of the same <c>(org_id, ecosystem, name)</c> that is still live —
/// only reachable via a race between two concurrent creates, since callers check for a live
/// claim before building the transition. Callers translate this into a 409 Conflict rather
/// than letting the underlying UNIQUE-constraint violation surface as an unhandled exception.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Binary serialization ctor on Exception is obsolete in .NET 10 (SYSLIB0051); this exception is never serialized across an AppDomain or binary boundary.")]
public sealed class ClaimConflictException : Exception
{
    public string OrgId { get; }
    public string Ecosystem { get; }
    public string Name { get; }

    public ClaimConflictException(string orgId, string ecosystem, string name)
        : base($"Claim already exists for {ecosystem}/{name}.")
    {
        OrgId = orgId;
        Ecosystem = ecosystem;
        Name = name;
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
