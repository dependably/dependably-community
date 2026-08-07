using System.Security.Cryptography;
using System.Text;
using Dapper;
using Dependably.Security;

namespace Dependably.Infrastructure;

/// <summary>
/// One-shot links that complete a self-service email change (GDPR Art. 16 rectification).
/// Structural mirror of <see cref="PasswordResetTokenRepository"/>: the raw token is handed to the
/// caller once and only its SHA-256 hash is stored, and an atomic single-winner UPDATE stops a
/// token being redeemed twice under concurrent requests.
///
/// The one difference that matters: the pending NEW address rides on the token row rather than on
/// <c>users</c>. The account keeps its current, already-verified address until the link mailed to
/// the new one comes back, so an unredeemed or expired request changes nothing — a mistyped
/// address cannot strand a user, and a stolen session cannot silently repoint the mailbox that
/// receives password resets.
/// </summary>
public sealed class EmailChangeTokenRepository
{
    // Longer than the 30-minute reset window: a rectification is not an emergency, and the link
    // goes to an address the user may not have open. Still short enough that a request forgotten
    // in an inbox stops being redeemable.
    private const int ExpiryMinutes = 60 * 24;

    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public EmailChangeTokenRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    /// <summary>How long an issued link stays redeemable. Callers surface this to the recipient.</summary>
    public static DateTimeOffset ExpiryFor(DateTimeOffset issuedAt) => issuedAt.AddMinutes(ExpiryMinutes);

    /// <summary>
    /// Issues a link that, when redeemed, moves <paramref name="userId"/> to
    /// <paramref name="newEmail"/>. Any outstanding unconsumed request for that user is voided
    /// first, so at most one pending change is ever live: two rectifications requested in
    /// sequence cannot race, and the older link cannot resurrect an address the user has since
    /// thought better of. Returns the raw token — never stored, only its SHA-256 hash is.
    /// </summary>
    public async Task<string> IssueAsync(
        string userId, string orgId, string newEmail, CancellationToken ct = default)
    {
        string raw = TokenGenerator.Generate();
        string hash = HashToken(raw);
        string id = Guid.NewGuid().ToString("N");
        string expires = ExpiryFor(_time.GetUtcNow()).ToUtcIso();

        await using var conn = await _db.OpenAsync(ct);

        await conn.ExecuteAsync(
            "DELETE FROM email_change_tokens WHERE user_id = @userId AND org_id = @orgId AND consumed_at IS NULL",
            new { userId, orgId });

        await conn.ExecuteAsync(
            """
            INSERT INTO email_change_tokens (id, user_id, org_id, new_email, token_hash, expires_at)
            VALUES (@id, @userId, @orgId, @newEmail, @hash, @expires)
            """,
            new { id, userId, orgId, newEmail = newEmail.Trim().ToLowerInvariant(), hash, expires });

        return raw;
    }

    /// <summary>
    /// Atomically consumes a change token, returning the pending record or null when the token is
    /// unknown, already redeemed, or expired. The conditional UPDATE is the whole guard: concurrent
    /// requests carrying the same token both reach it and exactly one matches.
    /// </summary>
    public async Task<EmailChangeTokenRecord?> ConsumeAsync(string rawToken, CancellationToken ct = default)
    {
        string hash = HashToken(rawToken);
        string now = _time.GetUtcNow().ToUtcIso();

        await using var conn = await _db.OpenAsync(ct);

        // xtenant: keyed by the SHA-256 of the change token, same rationale as
        // PasswordResetTokenRepository.ConsumeAsync — the token itself is the tenant binding.
        int rowsAffected = await conn.ExecuteAsync(
            """
            UPDATE email_change_tokens SET consumed_at = @now
            WHERE token_hash = @hash AND consumed_at IS NULL AND expires_at > @now
            """,
            new { now, hash });

        if (rowsAffected == 0)
        {
            return null;
        }

        // xtenant: keyed by the globally unique token_hash; the returned org_id/user_id are what
        // the caller scopes every downstream write to.
        var (Id, UserId, OrgId, NewEmail, CurrentEmail) =
            await conn.QuerySingleAsync<(string Id, string UserId, string OrgId, string NewEmail, string CurrentEmail)>(
            """
            SELECT ect.id, ect.user_id AS UserId, ect.org_id AS OrgId,
                   ect.new_email AS NewEmail, u.email AS CurrentEmail
            FROM email_change_tokens ect
            JOIN users u ON u.id = ect.user_id
            WHERE ect.token_hash = @hash
            """,
            new { hash });

        return new EmailChangeTokenRecord(Id, UserId, OrgId, NewEmail, CurrentEmail);
    }

    /// <summary>
    /// Drops any pending request for a user without redeeming it. Called when the account's email
    /// changes by another route, so a link minted against the old state cannot land afterwards.
    /// </summary>
    public async Task VoidPendingAsync(string userId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by users PK, resolved by the caller from an org-scoped lookup.
        await conn.ExecuteAsync(
            "DELETE FROM email_change_tokens WHERE user_id = @userId AND consumed_at IS NULL",
            new { userId });
    }

    private static string HashToken(string raw) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant();
}

/// <summary>
/// A consumed email-change request: which user, which org, the address being moved to, and the
/// address it is moving from (needed to notify the old mailbox that its account was repointed).
/// </summary>
public sealed record EmailChangeTokenRecord(
    string Id, string UserId, string OrgId, string NewEmail, string CurrentEmail);
