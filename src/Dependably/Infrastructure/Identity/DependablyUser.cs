namespace Dependably.Infrastructure.Identity;

/// <summary>
/// In-memory representation of a tenant user for the ASP.NET Core Identity pipeline.
/// Properties are populated by <see cref="DependablyUserStore"/> from the <c>users</c>
/// table; normalized values (UserName, NormalizedEmail) are derived in the store and
/// are never persisted as separate columns.
/// </summary>
internal sealed class DependablyUser
{
    public string Id { get; set; } = "";
    public string TenantId { get; set; } = "";
    public string Email { get; set; } = "";
    /// <summary>Identity UserName — equal to Email for this provider.</summary>
    public string UserName => Email;
    public string? PasswordHash { get; set; }
    /// <summary>Maps to <c>users.mfa_enabled</c> (0/1).</summary>
    public bool TwoFactorEnabled { get; set; }
    /// <summary>Plaintext TOTP key held in memory only; encrypted before storage via <see cref="IMfaSecretProtector"/>.</summary>
    public string? AuthenticatorKey { get; set; }
    /// <summary>JSON array of SHA-256 hashes of one-time recovery codes, as stored in the DB.</summary>
    public string? RecoveryCodes { get; set; }
    /// <summary>Random stamp rotated on every credential change; detects concurrent mutations.</summary>
    public string? SecurityStamp { get; set; }
    /// <summary>Monotonic session-invalidation counter embedded as the <c>tver</c> JWT claim.</summary>
    public long TokenVersion { get; set; } = 1;
}
