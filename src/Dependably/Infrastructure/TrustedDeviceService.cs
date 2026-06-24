using Dapper;
using Dependably.Security;

namespace Dependably.Infrastructure;

/// <summary>
/// Manages MFA trusted-device tokens. A remembered device skips the TOTP step during
/// login for the configured TTL (default 30 days, controlled by TRUSTED_DEVICE_TTL_DAYS).
/// Tokens are SHA-256-hashed at rest; the raw value is returned once at creation and
/// stored only in the browser cookie.
/// </summary>
public sealed class TrustedDeviceService
{
    private const int DefaultTtlDays = 30;

    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    /// <summary>TTL for trusted-device cookies, derived from TRUSTED_DEVICE_TTL_DAYS (default 30).</summary>
    public int TtlDays { get; }

    public TrustedDeviceService(IMetadataStore db, TimeProvider time, IConfiguration config)
    {
        _db = db;
        _time = time;
        TtlDays = int.TryParse(config["TRUSTED_DEVICE_TTL_DAYS"], out int ttl) && ttl > 0 ? ttl : DefaultTtlDays;
    }

    /// <summary>
    /// Creates a trusted-device record and returns the raw token (shown once; stored as SHA-256 hash).
    /// </summary>
    public async Task<string> CreateAsync(
        string userId, string realm, string? tenantId, string? userAgent, CancellationToken ct = default)
    {
        string raw = TokenGenerator.Generate();
        string hash = TokenRepository.HashToken(raw);
        string id = Guid.NewGuid().ToString("N");
        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        string expiresAt = _time.GetUtcNow().AddDays(TtlDays).ToString("yyyy-MM-ddTHH:mm:ssZ");

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO mfa_trusted_devices (id, user_id, realm, tenant_id, token_hash, user_agent, created_at, expires_at)
            VALUES (@id, @userId, @realm, @tenantId, @hash, @userAgent, @now, @expiresAt)
            """,
            new { id, userId, realm, tenantId, hash, userAgent, now, expiresAt });

        return raw;
    }

    /// <summary>
    /// Checks whether <paramref name="rawCookie"/> is a valid, unexpired trusted-device token
    /// for the given user/realm/tenant. On a hit, bumps last_seen_at and returns true.
    /// </summary>
    public async Task<bool> TryConsumeAsync(
        string userId, string realm, string? tenantId, string rawCookie, CancellationToken ct = default)
    {
        string hash = TokenRepository.HashToken(rawCookie);
        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");

        await using var conn = await _db.OpenAsync(ct);
        string? id = await conn.ExecuteScalarAsync<string?>(
            """
            SELECT id FROM mfa_trusted_devices
            WHERE token_hash = @hash
              AND user_id = @userId
              AND realm = @realm
              AND tenant_id IS @tenantId
              AND expires_at > @now
            """,
            new { hash, userId, realm, tenantId, now });

        if (id is null)
        {
            return false;
        }

        await conn.ExecuteAsync(
            "UPDATE mfa_trusted_devices SET last_seen_at = @now WHERE id = @id",
            new { id, now });

        return true;
    }

    /// <summary>
    /// Deletes all trusted-device records for the user within the given realm. Used when
    /// MFA is disabled or the password is changed so remembered devices no longer bypass TOTP.
    /// </summary>
    public async Task DeleteAllForUserAsync(string userId, string realm, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: user_id is FK-bound to the user, already tenant-scoped via the users table
        await conn.ExecuteAsync(
            "DELETE FROM mfa_trusted_devices WHERE user_id = @userId AND realm = @realm",
            new { userId, realm });
    }

    /// <summary>Removes expired trusted-device rows (called by RetentionService GC pass).</summary>
    public async Task PruneExpiredAsync(CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: retention sweep deletes globally expired rows across all tenants
        await conn.ExecuteAsync(
            "DELETE FROM mfa_trusted_devices WHERE expires_at <= @now", new { now });
    }
}
