namespace Dependably.Infrastructure.Mail;

/// <summary>
/// Sends org invite emails when SMTP is configured. Implementations are injected into
/// <c>OrgInvitesController</c>; the null-object path (SMTP_HOST absent) is handled by
/// the caller, not by a separate NullInviteMailer.
/// </summary>
public interface IInviteMailer
{
    /// <summary>
    /// Sends an invitation email to <paramref name="toAddress"/>. Throws on delivery
    /// failure so the caller can fall back to returning the link in the response body.
    /// The invite link and raw token are never included in any exception message or
    /// structured log property — see the caller for the fail-open fallback.
    /// </summary>
    Task SendInviteAsync(string toAddress, string orgName, string inviteLink, DateTimeOffset expiresAt, CancellationToken ct = default);
}
