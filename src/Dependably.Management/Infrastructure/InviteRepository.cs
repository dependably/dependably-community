using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Security;

namespace Dependably.Infrastructure;

public sealed class InviteRepository
{
    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public InviteRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    /// <summary>
    /// Creates a new 24-hour invite. Returns the raw token and the stored record, or
    /// <c>null</c> when <paramref name="orgId"/> already holds a pending (unaccepted) invite
    /// for <paramref name="email"/> — the state the <c>idx_invites_unique_pending</c> partial
    /// unique index rejects. The INSERT names that index as its conflict target so the
    /// duplicate resolves to a zero-row no-op instead of a store exception, which makes the
    /// check race-free: a caller that pre-checks and loses to a concurrent create for the same
    /// address still gets <c>null</c> rather than an unhandled failure. Any other constraint
    /// (an id or token_hash collision) is a genuine anomaly and still throws.
    ///
    /// If instance SMTP delivery is not available, the caller is responsible for logging the link.
    /// </summary>
    public async Task<InviteCreation?> CreateAsync(
        string orgId, string email, string createdByUserId, string role = "member", CancellationToken ct = default)
    {
        // Canonical form before storage and before the pending-invite conflict check: the invite
        // is what mints the users row, so an invite stored in a different case than an existing
        // account's address would create a second account for the same mailbox.
        email = EmailNormalizer.Normalize(email);
        string raw = TokenGenerator.Generate();
        byte[] hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        string hash = Convert.ToHexString(hashBytes).ToLowerInvariant();
        string id = Guid.NewGuid().ToString("N");
        var expiresAt = _time.GetUtcNow().AddHours(24);
        string expiresStr = expiresAt.ToUtcIso();

        await using var conn = await _db.OpenAsync(ct);
        int inserted = await conn.ExecuteAsync(
            """
            INSERT INTO invites (id, org_id, email, role, token_hash, created_by, expires_at)
            VALUES (@id, @orgId, @email, @role, @hash, @createdBy, @expires)
            ON CONFLICT (org_id, email) WHERE accepted_at IS NULL DO NOTHING
            """,
            new { id, orgId, email, role, hash, createdBy = createdByUserId, expires = expiresStr });

        return inserted == 0
            ? null
            : new InviteCreation(raw, new InviteRecord
            {
                Id = id,
                OrgId = orgId,
                Email = email,
                Role = role,
                CreatedBy = createdByUserId,
                CreatedAt = _time.GetUtcNow(),
                ExpiresAt = expiresAt,
                AcceptedAt = null
            });
    }

    /// <summary>
    /// True when <paramref name="orgId"/> already holds a pending (unaccepted) invite for
    /// <paramref name="email"/>. Mirrors the <c>idx_invites_unique_pending</c> predicate, so a
    /// caller can answer a duplicate with a conflict response before minting a token. Expiry is
    /// deliberately not part of the predicate: the index does not consider it either, so an
    /// expired-but-unaccepted row still blocks the insert until the retention prune removes it.
    /// </summary>
    public async Task<bool> HasPendingAsync(string orgId, string email, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM invites WHERE org_id = @orgId AND email = @email AND accepted_at IS NULL",
            new { orgId, email = EmailNormalizer.Normalize(email) }) > 0;
    }

    public async Task<IReadOnlyList<InviteRecord>> ListAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<(string Id, string OrgId, string Email, string Role, string CreatedBy, string CreatedAt, string ExpiresAt, string? AcceptedAt)>(
            """
            SELECT id, org_id, email, role, created_by, created_at, expires_at, accepted_at
            FROM invites WHERE org_id = @orgId ORDER BY created_at DESC
            """,
            new { orgId });

        return rows.Select(r => new InviteRecord
        {
            Id = r.Id,
            OrgId = r.OrgId,
            Email = r.Email,
            Role = r.Role,
            CreatedBy = r.CreatedBy,
            CreatedAt = DateTimeOffset.Parse(r.CreatedAt),
            ExpiresAt = DateTimeOffset.Parse(r.ExpiresAt),
            AcceptedAt = r.AcceptedAt is not null ? DateTimeOffset.Parse(r.AcceptedAt) : null
        })
            .ToList();
    }

    /// <summary>
    /// Deletes a pending invite, scoped to <paramref name="orgId"/>. Returns the number of rows
    /// removed (0 when the id belongs to another tenant or does not exist) so the caller can 404
    /// without revealing cross-tenant existence. The id is a global PK, so the org_id predicate is
    /// what enforces tenant isolation here.
    /// </summary>
    public async Task<int> DeleteAsync(string orgId, string inviteId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteAsync(
            "DELETE FROM invites WHERE id = @id AND org_id = @orgId", new { id = inviteId, orgId });
    }

    /// <summary>
    /// Reads the invite identified by <paramref name="rawToken"/> only if it is still pending
    /// (unaccepted, unexpired) — without consuming it. Lets a caller resolve email/tenant
    /// context for a policy check (e.g. password strength) ahead of the one-shot
    /// <see cref="AcceptAsync"/>, so a failed check never burns the invite's single use.
    /// </summary>
    public async Task<InviteRecord?> PeekPendingAsync(string rawToken, CancellationToken ct = default)
    {
        byte[] hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        string hash = Convert.ToHexString(hashBytes).ToLowerInvariant();
        string now = _time.GetUtcNow().ToUtcIso();

        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by the SHA-256 of the bearer's invite token, same rationale as AcceptAsync.
        var (Id, OrgId, Email, Role, CreatedBy, CreatedAt, ExpiresAt, AcceptedAt) =
            await conn.QuerySingleOrDefaultAsync<(string? Id, string OrgId, string Email, string Role, string CreatedBy, string CreatedAt, string ExpiresAt, string? AcceptedAt)>(
            "SELECT id, org_id, email, role, created_by, created_at, expires_at, accepted_at FROM invites WHERE token_hash = @hash AND accepted_at IS NULL AND expires_at > @now",
            new { hash, now });

        return Id is null
            ? null
            : new InviteRecord
            {
                Id = Id,
                OrgId = OrgId,
                Email = Email,
                Role = Role,
                CreatedBy = CreatedBy,
                CreatedAt = DateTimeOffset.Parse(CreatedAt),
                ExpiresAt = DateTimeOffset.Parse(ExpiresAt),
                AcceptedAt = AcceptedAt is not null ? DateTimeOffset.Parse(AcceptedAt) : null,
            };
    }

    /// <summary>
    /// Atomically consumes an invite token. The UPDATE predicate guards both the
    /// not-yet-accepted and not-yet-expired conditions in one statement, so concurrent
    /// requests carrying the same token race on the DB write — exactly one wins
    /// (rowsAffected == 1); all others see rowsAffected == 0 and receive null.
    /// Returns the invite record on success, null if expired/not found/already accepted.
    /// </summary>
    public async Task<InviteRecord?> AcceptAsync(string rawToken, CancellationToken ct = default)
    {
        byte[] hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        string hash = Convert.ToHexString(hashBytes).ToLowerInvariant();
        string now = _time.GetUtcNow().ToUtcIso();

        await using var conn = await _db.OpenAsync(ct);

        // Single conditional UPDATE: wins the race only when the row is still pending
        // and unexpired. Concurrent requests with the same token both reach this statement
        // but at most one will match (SQLite serializes writes); the loser gets 0 rows.
        // xtenant: keyed by the SHA-256 of the bearer's invite token. The row itself carries
        // the org the invite grants; an org filter would need an org the acceptor does not yet have.
        int rowsAffected = await conn.ExecuteAsync(
            "UPDATE invites SET accepted_at = @now WHERE token_hash = @hash AND accepted_at IS NULL AND expires_at > @now",
            new { now, hash });

        if (rowsAffected == 0)
        {
            return null;
        }

        // Read the now-immutably-accepted row. The row is race-free at this point because
        // the winning UPDATE has set accepted_at; no further state change is possible.
        // token_hash is globally unique so no org_id predicate is required; the returned
        // org_id is what the caller uses for tenant context.
        // xtenant: token_hash is a globally-unique PK surrogate; the returned org_id enforces
        // tenant scope downstream (same rationale as DeleteAsync).
        var (Id, OrgId, Email, Role, CreatedBy, CreatedAt, ExpiresAt, AcceptedAt) =
            await conn.QuerySingleAsync<(string Id, string OrgId, string Email, string Role, string CreatedBy, string CreatedAt, string ExpiresAt, string AcceptedAt)>(
            "SELECT id, org_id, email, role, created_by, created_at, expires_at, accepted_at FROM invites WHERE token_hash = @hash",
            new { hash });

        return new InviteRecord
        {
            Id = Id,
            OrgId = OrgId,
            Email = Email,
            Role = Role,
            CreatedBy = CreatedBy,
            CreatedAt = DateTimeOffset.Parse(CreatedAt),
            ExpiresAt = DateTimeOffset.Parse(ExpiresAt),
            AcceptedAt = DateTimeOffset.Parse(AcceptedAt)
        };
    }

    /// <summary>
    /// Counts pending (unexpired, unconsumed) invites for the given org.
    /// Used to enforce the per-tenant pending-invite cap before creating a new invite.
    /// </summary>
    public async Task<int> CountPendingAsync(string orgId, CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM invites WHERE org_id = @orgId AND accepted_at IS NULL AND expires_at > @now",
            new { orgId, now });
    }

    /// <summary>
    /// Deletes expired, unconsumed invite rows. Runs as part of the background GC pass
    /// to prevent unbounded table growth when invites are never accepted or manually cancelled.
    /// </summary>
    public async Task<int> PruneExpiredAsync(CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: instance-wide expired-invite prune; no org_id predicate is correct here
        return await conn.ExecuteAsync(
            "DELETE FROM invites WHERE accepted_at IS NULL AND expires_at <= @now",
            new { now });
    }
}
