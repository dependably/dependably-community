namespace Dependably.Infrastructure.Mail;

/// <summary>
/// Sends org invite emails through the instance-level SMTP transport. Implementations are
/// injected into <c>OrgInvitesController</c>; the link-in-response fallback path is handled by
/// the caller (gated on <see cref="IsAvailableAsync"/>), not by a separate NullInviteMailer.
/// </summary>
public interface IInviteMailer
{
    /// <summary>
    /// Resolves whether the instance SMTP transport is currently enabled and configured
    /// (host/from/credentials present). Called per request rather than cached at startup so a
    /// config change in Settings → Instance (or the operator apex System Settings in multi mode)
    /// takes effect immediately.
    /// </summary>
    Task<bool> IsAvailableAsync(CancellationToken ct = default);

    /// <summary>
    /// Sends an invitation email to <paramref name="toAddress"/>. Throws on delivery
    /// failure so the caller can fall back to returning the link in the response body.
    /// The invite link and raw token are never included in any exception message or
    /// structured log property — see the caller for the fail-open fallback.
    /// <paramref name="language"/> selects the SharedResource culture for the subject
    /// and body — the recipient has no account yet, so callers pass the tenant's
    /// default language; unsupported codes fall back to English.
    /// </summary>
    Task SendInviteAsync(string toAddress, string orgName, string inviteLink, DateTimeOffset expiresAt, string language, CancellationToken ct = default);
}
