using System.Globalization;
using Microsoft.Extensions.Localization;

namespace Dependably.Infrastructure.Mail;

/// <summary>
/// Wraps the verification link for a pending email change as an <see cref="IEmailDeliveryJob"/>.
///
/// This mail is the whole security property of the rectification flow: the link goes to the
/// address being moved TO, so possession of that mailbox is what authorizes the move. Without it,
/// anyone holding a session could repoint the account's recovery address to a mailbox they own —
/// and a password reset later would then reach them, not the user.
///
/// Delivery failure is logged only, like <see cref="PasswordResetEmailJob"/>: nothing has changed
/// on the account yet, so a failed send simply means the pending request expires unredeemed and
/// the user can ask again. That is the safe direction to fail in.
///
/// The verification link is a live credential, so <see cref="ResolveAsync"/> also refuses an
/// unencrypted transport per <see cref="CredentialMailPolicy"/> — the same "unavailable" outcome
/// as an unconfigured instance.
/// </summary>
internal sealed class EmailChangeVerificationJob : IEmailDeliveryJob
{
    private readonly string _toAddress;
    private readonly string _verifyLink;
    private readonly DateTimeOffset _expiresAt;
    private readonly InstanceSmtpConfig _instanceConfig;
    private readonly bool _allowInsecureCredentialMail;
    private readonly IStringLocalizer<SharedResource> _localizer;
    private readonly ILogger _logger;

    public EmailChangeVerificationJob(
        string toAddress,
        string verifyLink,
        DateTimeOffset expiresAt,
        InstanceSmtpConfig instanceConfig,
        bool allowInsecureCredentialMail,
        IStringLocalizer<SharedResource> localizer,
        ILogger logger)
    {
        _toAddress = toAddress;
        _verifyLink = verifyLink;
        _expiresAt = expiresAt;
        _instanceConfig = instanceConfig;
        _allowInsecureCredentialMail = allowInsecureCredentialMail;
        _localizer = localizer;
        _logger = logger;
    }

    public async Task<(SmtpTransportSettings Transport, IReadOnlyList<string> Recipients)?> ResolveAsync(CancellationToken ct)
    {
        var resolved = await _instanceConfig.ResolveAsync(ct);
        if (!resolved.Enabled || !resolved.Configured)
        {
            return null;
        }

        if (CredentialMailPolicy.RefusesCredentialMail(resolved.Transport, _allowInsecureCredentialMail))
        {
            _logger.LogWarning(
                "Refusing to send email-change verification to {RecipientDomain}: instance SMTP security={Security} " +
                "would put the verification link on the wire in cleartext. Set {EnvVar}=true to override.",
                ExtractDomain(_toAddress), resolved.Transport.Security, CredentialMailPolicy.AllowInsecureEnvVar);
            return null;
        }

        return (resolved.Transport, new[] { _toAddress });
    }

    /// <summary>
    /// English-only, for the same reason <see cref="PasswordResetEmailJob"/> is: the recipient is
    /// an address that does not yet belong to any account, so there is no per-recipient language
    /// to resolve. The ambient culture is pinned for the lookups and restored afterwards.
    /// </summary>
    public (string Subject, string Body) Render()
    {
        var original = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentUICulture = new CultureInfo(LanguageCodes.Default);
            string expiry = _expiresAt.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
            string subject = _localizer["email.emailChange.subject"];
            string body = _localizer["email.emailChange.body", expiry, _verifyLink];
            return (subject, body);
        }
        finally
        {
            CultureInfo.CurrentUICulture = original;
        }
    }

    public Task RecordSuccessAsync()
    {
        _logger.LogInformation(
            "Email-change verification delivered via SMTP to {RecipientDomain}.", ExtractDomain(_toAddress));
        return Task.CompletedTask;
    }

    public Task RecordFailureAsync(string error)
    {
        _logger.LogWarning(
            "Email-change verification delivery failed to {RecipientDomain}: {Error}",
            ExtractDomain(_toAddress), error);
        return Task.CompletedTask;
    }

    // Log only the domain portion so the local-part never reaches structured logs.
    private static string ExtractDomain(string address)
    {
        int at = address.IndexOf('@', StringComparison.Ordinal);
        return at >= 0 ? address[(at + 1)..] : "[unknown]";
    }
}
