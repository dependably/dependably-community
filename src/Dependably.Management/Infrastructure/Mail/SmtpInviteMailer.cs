using System.Globalization;
using Microsoft.Extensions.Localization;

namespace Dependably.Infrastructure.Mail;

/// <summary>
/// Delivers invite emails through the instance-level SMTP transport, resolved fresh on every
/// send via <see cref="InstanceSmtpConfig"/> and dispatched through the shared
/// <see cref="SmtpMailSender"/> choke point. DB-backed only — there is no env-var fallback or
/// seed; an unconfigured or disabled instance resolves <see cref="IsAvailableAsync"/> to
/// <c>false</c> and the caller falls back to the link-in-response path.
/// </summary>
public sealed class SmtpInviteMailer : IInviteMailer
{
    private readonly InstanceSmtpConfig _config;
    private readonly SmtpMailSender _sender;
    private readonly ILogger<SmtpInviteMailer> _logger;
    private readonly IStringLocalizer<SharedResource> _localizer;

    public SmtpInviteMailer(
        InstanceSmtpConfig config,
        SmtpMailSender sender,
        ILogger<SmtpInviteMailer> logger,
        IStringLocalizer<SharedResource> localizer)
    {
        _config = config;
        _sender = sender;
        _logger = logger;
        _localizer = localizer;
    }

    public async Task<bool> IsAvailableAsync(CancellationToken ct = default)
    {
        var resolved = await _config.ResolveAsync(ct);
        return resolved.Enabled && resolved.Configured;
    }

    public async Task SendInviteAsync(string toAddress, string orgName, string inviteLink, DateTimeOffset expiresAt, string language, CancellationToken ct = default)
    {
        var resolved = await _config.ResolveAsync(ct);
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
