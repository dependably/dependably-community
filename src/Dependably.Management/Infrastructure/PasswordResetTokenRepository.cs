using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Security;

namespace Dependably.Infrastructure;

/// <summary>
/// Self-serve "forgot password" reset links. Structural mirror of <see cref="InviteRepository"/>:
/// a raw token is handed to the caller once and only its SHA-256 hash is stored, a non-consuming
/// <see cref="PeekAsync"/> lets a policy check run ahead of the one-shot
/// <see cref="ConsumeAsync"/>, and the atomic single-winner UPDATE guards against a token being
/// redeemed twice under concurrent requests.
/// </summary>
public sealed class PasswordResetTokenRepository
{
    private const int ExpiryMinutes = 30;

    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public PasswordResetTokenRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    /// <summary>
    /// Issues a new 30-minute reset token for the given user, first voiding any outstanding
    /// (unconsumed) token for that user so at most one reset link is ever live — a stale link
    /// mailed earlier cannot be replayed once a fresher one is requested. Returns the raw token
    /// (never stored; only its SHA-256 hash is persisted).
    /// </summary>
    public async Task<string> IssueAsync(string userId, string orgId, CancellationToken ct = default)
    {
        string raw = TokenGenerator.Generate();
        byte[] hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        string hash = Convert.ToHexString(hashBytes).ToLowerInvariant();
        string id = Guid.NewGuid().ToString("N");
        var expiresAt = _time.GetUtcNow().AddMinutes(ExpiryMinutes);
        string expiresStr = expiresAt.ToUtcIso();

        await using var conn = await _db.OpenAsync(ct);

        // Void any outstanding reset link for this user before minting a new one — only the
        // most recently requested link is ever redeemable.
        await conn.ExecuteAsync(
            "DELETE FROM password_reset_tokens WHERE user_id = @userId AND org_id = @orgId AND consumed_at IS NULL",
            new { userId, orgId });

        await conn.ExecuteAsync(
            """
            INSERT INTO password_reset_tokens (id, user_id, org_id, token_hash, expires_at)
            VALUES (@id, @userId, @orgId, @hash, @expires)
            """,
            new { id, userId, orgId, hash, expires = expiresStr });

        return raw;
    }

    /// <summary>
    /// Reads the reset token identified by <paramref name="rawToken"/> only if it is still
    /// pending (unconsumed, unexpired) — without consuming it. Lets the caller run the password
    /// policy check ahead of the one-shot <see cref="ConsumeAsync"/>, so a failed check never
    /// burns the link's single use.
    /// </summary>
    public async Task<PasswordResetTokenRecord?> PeekAsync(string rawToken, CancellationToken ct = default)
    {
        byte[] hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        string hash = Convert.ToHexString(hashBytes).ToLowerInvariant();
        string now = _time.GetUtcNow().ToUtcIso();

        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by the SHA-256 of the reset token, same rationale as InviteRepository.AcceptAsync.
        var (Id, UserId, OrgId, Email, ExpiresAt) =
            await conn.QuerySingleOrDefaultAsync<(string? Id, string UserId, string OrgId, string Email, string ExpiresAt)>(
            """
            SELECT prt.id, prt.user_id AS UserId, prt.org_id AS OrgId, u.email, prt.expires_at AS ExpiresAt
            FROM password_reset_tokens prt
            JOIN users u ON u.id = prt.user_id
            WHERE prt.token_hash = @hash AND prt.consumed_at IS NULL AND prt.expires_at > @now
            """,
            new { hash, now });

        return Id is null
            ? null
            : new PasswordResetTokenRecord(Id, UserId, OrgId, Email, DateTimeOffset.Parse(ExpiresAt));
    }

    /// <summary>
    /// Atomically consumes a reset token. The UPDATE predicate guards both the not-yet-consumed
    /// and not-yet-expired conditions in one statement, so concurrent requests carrying the same
    /// token race on the DB write — exactly one wins (rowsAffected == 1); all others see
    /// rowsAffected == 0 and receive null. Returns the token record on success.
    /// </summary>
    public async Task<PasswordResetTokenRecord?> ConsumeAsync(string rawToken, CancellationToken ct = default)
    {
        byte[] hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        string hash = Convert.ToHexString(hashBytes).ToLowerInvariant();
        string now = _time.GetUtcNow().ToUtcIso();

        await using var conn = await _db.OpenAsync(ct);

        // Single conditional UPDATE: wins the race only when the row is still pending and
        // unexpired. Concurrent requests with the same token both reach this statement but at
        // most one will match (SQLite serializes writes); the loser gets 0 rows.
        // xtenant: keyed by the SHA-256 of the reset token, same rationale as InviteRepository.AcceptAsync.
        int rowsAffected = await conn.ExecuteAsync(
            "UPDATE password_reset_tokens SET consumed_at = @now WHERE token_hash = @hash AND consumed_at IS NULL AND expires_at > @now",
            new { now, hash });

        if (rowsAffected == 0)
        {
            return null;
        }

        // Read the now-immutably-consumed row. token_hash is globally unique, so no org_id
        // predicate is required; the returned org_id/user_id are what the caller uses downstream.
        // xtenant: keyed by the SHA-256 of the reset token, same rationale as InviteRepository.AcceptAsync.
        var (Id, UserId, OrgId, Email) = await conn.QuerySingleAsync<(string Id, string UserId, string OrgId, string Email)>(
            """
            SELECT prt.id, prt.user_id AS UserId, prt.org_id AS OrgId, u.email
            FROM password_reset_tokens prt
            JOIN users u ON u.id = prt.user_id
            WHERE prt.token_hash = @hash
            """,
            new { hash });

        return new PasswordResetTokenRecord(Id, UserId, OrgId, Email, _time.GetUtcNow());
    }
}

/// <summary>A password-reset token row projected with its owning user's email for policy checks
/// and post-reset lockout clearing.</summary>
public sealed record PasswordResetTokenRecord(
    string Id, string UserId, string OrgId, string Email, DateTimeOffset ExpiresAt);
