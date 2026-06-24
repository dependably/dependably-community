namespace Dependably.Infrastructure.Identity;

/// <summary>
/// In-memory representation of a system_admin account for the ASP.NET Core Identity pipeline.
/// Mirrors <see cref="DependablyUser"/> but has no TenantId: system_admins live outside the
/// tenant model. Populated by <see cref="SystemAdminUserStore"/>.
/// </summary>
internal sealed class SystemAdminUser
{
    public string Id { get; set; } = "";
    public string Email { get; set; } = "";
    /// <summary>Identity UserName — equal to Email for this provider.</summary>
    public string UserName => Email;
    public string? PasswordHash { get; set; }
    /// <summary>Maps to <c>system_admins.mfa_enabled</c> (0/1).</summary>
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
