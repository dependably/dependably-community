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
    /// Creates a new 24-hour invite. Returns (rawToken, record).
    /// If SMTP_HOST is not configured, the caller is responsible for logging the link.
    /// </summary>
    public async Task<(string RawToken, InviteRecord Record)> CreateAsync(
        string orgId, string email, string createdByUserId, string role = "member", CancellationToken ct = default)
    {
        string raw = TokenGenerator.Generate();
        byte[] hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        string hash = Convert.ToHexString(hashBytes).ToLowerInvariant();
        string id = Guid.NewGuid().ToString("N");
        var expiresAt = _time.GetUtcNow().AddHours(24);
        string expiresStr = expiresAt.ToString("yyyy-MM-ddTHH:mm:ssZ");

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO invites (id, org_id, email, role, token_hash, created_by, expires_at)
            VALUES (@id, @orgId, @email, @role, @hash, @createdBy, @expires)
            """,
            new { id, orgId, email, role, hash, createdBy = createdByUserId, expires = expiresStr });

        return (raw, new InviteRecord
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
        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");

        await using var conn = await _db.OpenAsync(ct);

        // Single conditional UPDATE: wins the race only when the row is still pending
        // and unexpired. Concurrent requests with the same token both reach this statement
        // but at most one will match (SQLite serializes writes); the loser gets 0 rows.
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
        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
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
        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: instance-wide expired-invite prune; no org_id predicate is correct here
        return await conn.ExecuteAsync(
            "DELETE FROM invites WHERE accepted_at IS NULL AND expires_at <= @now",
            new { now });
    }
}
