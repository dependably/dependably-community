using System.Globalization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Localization;

namespace Dependably.Infrastructure.Mail;

/// <summary>
/// Delivers invite emails through the instance-level SMTP transport, resolved fresh on every
/// send via <see cref="InstanceSmtpConfig"/> and dispatched through the shared
/// <see cref="SmtpMailSender"/> choke point. DB-backed only — there is no env-var fallback or
/// seed; an unconfigured or disabled instance resolves <see cref="IsAvailableAsync"/> to
/// <c>false</c> and the caller falls back to the link-in-response path.
///
/// The invite link doubles as a bearer credential — possession lets its holder create an account
/// and join the org at the invited role — so <see cref="IsAvailableAsync"/> also resolves to
/// <c>false</c> for an unencrypted transport per <see cref="CredentialMailPolicy"/>, which routes
/// the caller to the same link-in-response fallback (delivered over the inviting admin's own
/// authenticated HTTPS session, not over the relay) rather than sending the token in cleartext.
/// <see cref="SendInviteAsync"/> re-checks the same gate before dispatch, in case a future caller
/// invokes it without consulting <see cref="IsAvailableAsync"/> first.
/// </summary>
public sealed class SmtpInviteMailer : IInviteMailer
{
    private readonly InstanceSmtpConfig _config;
    private readonly SmtpMailSender _sender;
    private readonly bool _allowInsecureCredentialMail;
    private readonly ILogger<SmtpInviteMailer> _logger;
    private readonly IStringLocalizer<SharedResource> _localizer;

    public SmtpInviteMailer(
        InstanceSmtpConfig config,
        SmtpMailSender sender,
        IConfiguration appConfig,
        ILogger<SmtpInviteMailer> logger,
        IStringLocalizer<SharedResource> localizer)
    {
        _config = config;
        _sender = sender;
        // Resolved once, like WebhookSiemForwarder resolves its own insecure-override env var
        // once at construction — env vars do not change for the lifetime of the process.
        _allowInsecureCredentialMail = CredentialMailPolicy.AllowsInsecure(appConfig);
        _logger = logger;
        _localizer = localizer;
    }

    public async Task<bool> IsAvailableAsync(CancellationToken ct = default)
    {
        var resolved = await _config.ResolveAsync(ct);
        if (!resolved.Enabled || !resolved.Configured)
        {
            return false;
        }

        if (CredentialMailPolicy.RefusesCredentialMail(resolved.Transport, _allowInsecureCredentialMail))
        {
            _logger.LogWarning(
                "Instance SMTP unavailable for invite delivery: security={Security} would put the invite " +
                "token on the wire in cleartext. Set {EnvVar}=true to override; falling back to link-in-response.",
                resolved.Transport.Security, CredentialMailPolicy.AllowInsecureEnvVar);
            return false;
        }

        return true;
    }

    public async Task SendInviteAsync(string toAddress, string orgName, string inviteLink, DateTimeOffset expiresAt, string language, CancellationToken ct = default)
    {
        var resolved = await _config.ResolveAsync(ct);
        if (CredentialMailPolicy.RefusesCredentialMail(resolved.Transport, _allowInsecureCredentialMail))
        {
            // IsAvailableAsync should have kept the caller from reaching here; refuse rather than
            // put the invite token on the wire in cleartext. The caller's existing catch-and-fall
            // back-to-link-in-response handling (see OrgInvitesController) applies unchanged.
            throw new InvalidOperationException(
                $"Refusing to send an invite over an unencrypted SMTP transport (security={resolved.Transport.Security}). " +
                $"Set {CredentialMailPolicy.AllowInsecureEnvVar}=true to override.");
        }

        (string subject, string body) = ComposeInvite(_localizer, language, orgName, inviteLink, expiresAt);

        await _sender.SendAsync(resolved.Transport, [toAddress], subject, body, ct);

        _logger.LogInformation(
            "Invite email delivered via SMTP to {RecipientDomain} for org {OrgName}.",
            ExtractDomain(toAddress),
            orgName);
    }

    /// <summary>
    /// Renders the invite subject and body in <paramref name="language"/> (unsupported
    /// codes fall back to English). IStringLocalizer resolves via CurrentUICulture, so the
    /// culture is scoped around the lookups — the expiry stays in the locale-neutral
    /// ISO yyyy-MM-dd HH:mm form regardless of the recipient's language.
    /// </summary>
    internal static (string Subject, string Body) ComposeInvite(
        IStringLocalizer<SharedResource> localizer,
        string language,
        string orgName,
        string inviteLink,
        DateTimeOffset expiresAt)
    {
        var culture = new CultureInfo(
            LanguageCodes.IsSupported(language) ? language : LanguageCodes.Default);
        string expiry = expiresAt.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);

        var original = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentUICulture = culture;
            return (localizer["email.invite.subject", orgName],
                    localizer["email.invite.body", orgName, expiry, inviteLink]);
        }
        finally
        {
            CultureInfo.CurrentUICulture = original;
        }
    }

    // Log only the domain portion of the recipient address so PII (the local-part) never
    // appears in structured logs. The invite audit_log entry (see OrgInvitesController)
    // is the sanctioned record of the recipient email.
    private static string ExtractDomain(string address)
    {
        int at = address.IndexOf('@', StringComparison.Ordinal);
        return at >= 0 ? address[(at + 1)..] : "[unknown]";
    }
}
