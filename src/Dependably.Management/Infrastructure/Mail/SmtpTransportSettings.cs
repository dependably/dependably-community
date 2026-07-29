using System.Net.Mail;

namespace Dependably.Infrastructure.Mail;

/// <summary>
/// A resolved SMTP relay configuration — the shape shared by the instance-level config
/// (<see cref="InstanceSmtpConfig"/>) and any future per-org transport. Never serialized to a
/// client directly; callers project the fields they need and omit <see cref="Password"/>.
/// </summary>
public sealed record SmtpTransportSettings(
    string? Host,
    int Port,
    string Security,
    string? Username,
    string? Password,
    string? FromAddress)
{
    /// <summary>Default SMTP submission port (RFC 6409 / RFC 8314 — STARTTLS on 587).</summary>
    public const int DefaultPort = 587;

    /// <summary>Default transport security mode.</summary>
    public const string DefaultSecurity = "starttls";

    /// <summary>The three security modes <see cref="SmtpMailSender"/> understands.</summary>
    public static readonly IReadOnlyList<string> ValidSecurityModes = ["starttls", "ssl", "none"];

    /// <summary>
    /// True when enough of the transport is present to attempt a send: a host, a from address,
    /// and either a username+password pair or an explicit opt-out of authentication
    /// (<c>security == "none"</c>, e.g. an unauthenticated internal relay).
    /// </summary>
    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(Host)
        && !string.IsNullOrWhiteSpace(FromAddress)
        && ((!string.IsNullOrWhiteSpace(Username) && !string.IsNullOrWhiteSpace(Password))
            || string.Equals(Security, "none", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// True when this transport would put SMTP AUTH credentials on the wire in the clear: a
    /// username and password are configured, but <see cref="Security"/> is <c>none</c>, so the
    /// session is never wrapped in TLS and the AUTH exchange is readable by anything on the path.
    ///
    /// <para>
    /// <c>none</c> is a legitimate setting on its own — an unauthenticated relay on a trusted
    /// segment has nothing to protect. It becomes a finding only once credentials are attached to
    /// it, which is the combination reported here. The configuration is DB-backed (per-org for the
    /// alert transport, <c>instance_settings</c> for the instance one), so there is no boot-time
    /// moment at which a static startup warning could see it; the settings read and write surfaces
    /// are where the answer lives, and both report it.
    /// </para>
    /// </summary>
    public bool SendsCredentialsInCleartext =>
        SendsCredentialsInCleartextWhen(Security, Username, !string.IsNullOrEmpty(Password));

    /// <summary>
    /// <see cref="SendsCredentialsInCleartext"/> for callers holding the stored password only as a
    /// "one is set" boolean — the per-org alert transport never decrypts it on a response path.
    /// </summary>
    public static bool SendsCredentialsInCleartextWhen(string? security, string? username, bool hasPassword)
        => string.Equals(security, "none", StringComparison.OrdinalIgnoreCase)
           && !string.IsNullOrWhiteSpace(username)
           && hasPassword;

    /// <summary>
    /// Validates the fields an endpoint accepts on write (host/port/security/from — password and
    /// username are opaque strings with no format to check). Returns the first failing field name
    /// via <paramref name="invalidField"/> and a resource key describing the failure, or
    /// <c>(null, null)</c> when every supplied field is valid. Fields that are null are treated as
    /// "unchanged" and are not validated — callers pass only the fields present in the request.
    /// </summary>
    public static (string? Field, string? ResourceKey) Validate(
        int? port, string? security, string? fromAddress)
    {
        if (port is { } p && (p < 1 || p > 65535))
        {
            return ("port", "error.email.invalidPort");
        }

        if (security is not null && !ValidSecurityModes.Contains(security, StringComparer.OrdinalIgnoreCase))
        {
            return ("security", "error.email.invalidSecurity");
        }

        if (!string.IsNullOrEmpty(fromAddress) && !MailAddress.TryCreate(fromAddress, out _))
        {
            return ("fromAddress", "error.email.invalidFrom");
        }

        return (null, null);
    }
}
