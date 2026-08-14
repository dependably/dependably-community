using Microsoft.Extensions.Configuration;

namespace Dependably.Infrastructure.Mail;

/// <summary>
/// Gate for outbound mail whose body carries a bearer credential — a password-reset link, an
/// email-change verification link, or an invite token. Possessing that link grants what a stolen
/// password or session cookie would (account control, and for an invite, account creation), so
/// sending one over an unencrypted <see cref="SmtpTransportSettings"/> is refused by default,
/// exactly the way <c>WebhookSiemForwarder</c> refuses a cleartext collector URL: silently unless
/// the operator opts in explicitly via <see cref="AllowsInsecure"/>. This is a distinct finding
/// from <see cref="SmtpTransportSettings.SendsCredentialsInCleartext"/>, which is about the SMTP
/// AUTH exchange; this one is about the message content a caller is asking to send.
///
/// <para>
/// Unlike the SIEM webhook, SMTP is DB-backed (<see cref="InstanceSmtpConfig"/>) with no
/// boot-time moment to fail at, so refusal happens per-send: a credential-bearing job's
/// <see cref="IEmailDeliveryJob.ResolveAsync"/> (or, for invites, <c>IInviteMailer</c>'s
/// availability check) treats a refused transport exactly like an unconfigured one — nothing
/// sent, the existing "relay unconfigured" fallback for that message applies unchanged (202 with
/// no email for reset/email-change; the link returned in the API response for an invite, which
/// already reaches its recipient — the inviting admin — over an authenticated HTTPS session).
/// There is no per-org override; this is an instance-level opt-in like the transport itself.
/// </para>
///
/// <para>
/// Loopback and other private-range relay hosts are not exempted: an operator relaying to
/// 127.0.0.1 in cleartext still needs the override, the same posture
/// <c>SIEM_WEBHOOK_ALLOW_INSECURE</c> takes for the webhook collector. (The webhook's separate
/// <c>SIEM_WEBHOOK_ALLOW_PRIVATE</c> flag governs the address *range*, not the transport, and even
/// that one still blocks loopback — there is no analogous range gate here because
/// <c>SmtpMailSender</c>'s SSRF guard already vets the destination independently of this policy.)
/// </para>
/// </summary>
public static class CredentialMailPolicy
{
    /// <summary>
    /// Env var an operator sets to send credential-bearing mail over an unencrypted transport
    /// anyway. Named to match <c>SIEM_WEBHOOK_ALLOW_INSECURE</c>'s <c>&lt;subsystem&gt;_ALLOW_INSECURE</c>
    /// shape, scoped narrower (<c>_CREDENTIAL_MAIL</c>) because the refusal itself is scoped
    /// narrower — alert email and security-event notices, which carry no bearer secret, are
    /// unaffected either way.
    /// </summary>
    public const string AllowInsecureEnvVar = "SMTP_ALLOW_INSECURE_CREDENTIAL_MAIL";

    /// <summary>
    /// True when <paramref name="transport"/> would carry a credential-bearing message over an
    /// unencrypted connection and the operator has not opted in via <see cref="AllowsInsecure"/>.
    /// </summary>
    public static bool RefusesCredentialMail(SmtpTransportSettings transport, IConfiguration config) =>
        !transport.IsEncrypted && !AllowsInsecure(config);

    /// <summary>Same as <see cref="RefusesCredentialMail(SmtpTransportSettings, IConfiguration)"/>
    /// for a caller that already resolved the override once (every credential-bearing mail
    /// channel in this codebase does, at construction, exactly like <c>WebhookSiemForwarder</c>
    /// resolves its own override once).</summary>
    public static bool RefusesCredentialMail(SmtpTransportSettings transport, bool allowsInsecure) =>
        !transport.IsEncrypted && !allowsInsecure;

    /// <summary>Accepts the spellings an operator plausibly writes in a compose file — the same
    /// set <c>WebhookSiemForwarder.AllowsInsecure</c> accepts.</summary>
    public static bool AllowsInsecure(IConfiguration config)
    {
        string? raw = config[AllowInsecureEnvVar]?.Trim();
        return raw is not null
            && (raw.Equals("true", StringComparison.OrdinalIgnoreCase)
                || raw == "1"
                || raw.Equals("yes", StringComparison.OrdinalIgnoreCase));
    }
}
