using System.Globalization;
using Microsoft.Extensions.Localization;

namespace Dependably.Infrastructure.Mail;

/// <summary>
/// Wraps a self-serve "forgot password" reset link as an <see cref="IEmailDeliveryJob"/> for the
/// shared <see cref="EmailDeliveryQueue"/>. Resolves only the instance-level SMTP transport (the
/// non-SMTP fallback is the caller returning 202 with no email ever sent — there is no
/// link-in-response fallback the way invites has, since the reset token must never reach the
/// response body). Delivery failure is logged only — unlike alert email, there is no per-org
/// health state to auto-disable, and the user can simply request a fresh link.
///
/// The reset link is a live credential, so <see cref="ResolveAsync"/> also refuses an unencrypted
/// transport per <see cref="CredentialMailPolicy"/> — the same "unavailable" outcome, and 202
/// fallback, as an unconfigured instance.
/// </summary>
internal sealed class PasswordResetEmailJob : IEmailDeliveryJob
{
    private readonly string _toAddress;
    private readonly string _resetLink;
    private readonly DateTimeOffset _expiresAt;
    private readonly InstanceSmtpConfig _instanceConfig;
    private readonly bool _allowInsecureCredentialMail;
    private readonly IStringLocalizer<SharedResource> _localizer;
    private readonly ILogger _logger;

    public PasswordResetEmailJob(
        string toAddress,
        string resetLink,
        DateTimeOffset expiresAt,
        InstanceSmtpConfig instanceConfig,
        bool allowInsecureCredentialMail,
        IStringLocalizer<SharedResource> localizer,
        ILogger logger)
    {
        _toAddress = toAddress;
        _resetLink = resetLink;
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
                "Refusing to send password reset email to {RecipientDomain}: instance SMTP security={Security} " +
                "would put the reset link on the wire in cleartext. Set {EnvVar}=true to override.",
                ExtractDomain(_toAddress), resolved.Transport.Security, CredentialMailPolicy.AllowInsecureEnvVar);
            return null;
        }

        return (resolved.Transport, new[] { _toAddress });
    }

    /// <summary>
    /// Reset email is English-only (there is no per-recipient language available at this call
    /// site), so the ambient <see cref="CultureInfo.CurrentUICulture"/> is pinned to English for
    /// the duration of the lookups, then restored — same pattern as
    /// <see cref="Alerts.AlertEmailQueue.BuildMessage"/>. The expiry stays in the locale-neutral
    /// ISO <c>yyyy-MM-dd HH:mm</c> form regardless.
    /// </summary>
    public (string Subject, string Body) Render()
    {
        var original = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentUICulture = new CultureInfo(LanguageCodes.Default);
            string expiry = _expiresAt.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
            string subject = _localizer["email.reset.subject"];
            string body = _localizer["email.reset.body", expiry, _resetLink];
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
            "Password reset email delivered via SMTP to {RecipientDomain}.", ExtractDomain(_toAddress));
        return Task.CompletedTask;
    }

    public Task RecordFailureAsync(string error)
    {
        _logger.LogWarning(
            "Password reset email delivery failed to {RecipientDomain}: {Error}",
            ExtractDomain(_toAddress), error);
        return Task.CompletedTask;
    }

    // Log only the domain portion of the recipient address so PII (the local-part) never
    // appears in structured logs.
    private static string ExtractDomain(string address)
    {
        int at = address.IndexOf('@', StringComparison.Ordinal);
        return at >= 0 ? address[(at + 1)..] : "[unknown]";
    }
}
