using System.Globalization;

namespace Dependably.Infrastructure.Mail;

/// <summary>
/// Request body shared by <c>PUT /api/v1/system/email-config</c> and
/// <c>PUT /api/v1/instance/email-config</c>. Mirrors <c>AlertSettingsRequest</c>'s
/// write-only-secret convention: every field except <see cref="Password"/> is a full-form
/// replacement value the caller always supplies; <see cref="Password"/> is write-only —
/// null/empty on update means "leave the stored password unchanged", non-empty rotates it.
/// </summary>
public sealed class EmailConfigRequest
{
    public bool Enabled { get; set; }
    public string? Host { get; set; }
    public int Port { get; set; } = SmtpTransportSettings.DefaultPort;
    public string Security { get; set; } = SmtpTransportSettings.DefaultSecurity;
    public string? Username { get; set; }
    public string? Password { get; set; }
    public string? FromAddress { get; set; }
}

/// <summary>
/// Shared editing helpers for the instance SMTP config, used by both the multi-mode system
/// surface (<c>SystemController.EmailConfig.cs</c>) and the single-mode instance surface
/// (<c>InstanceController</c>). Centralising validation and the response projection keeps the
/// two PUT/GET handlers behaviourally identical and unable to drift.
/// </summary>
public static class EmailConfigEditing
{
    /// <summary>
    /// Validates the request's port/security/from-address fields. Returns the first invalid
    /// field name and its SharedResource key, or <c>(null, null)</c> when everything parses.
    /// Host, username, and password are opaque strings with no format to check here.
    /// </summary>
    public static (string? Field, string? ResourceKey) Validate(EmailConfigRequest req)
        => SmtpTransportSettings.Validate(req.Port, req.Security, req.FromAddress);

    /// <summary>
    /// Builds the GET/PUT response object. <c>hasPassword</c> reflects whether a password is
    /// currently stored — the raw value is never included. <c>secretsAvailable</c> mirrors the
    /// per-org <c>alert-settings</c> convention (= <c>EnvelopeProtector.IsConfigured</c>) so the
    /// UI can grey out the password field with an explanatory hint when no master key is set.
    /// </summary>
    public static object BuildView(InstanceSmtpConfig.ResolvedSmtpConfig resolved, bool secretsAvailable)
    {
        var t = resolved.Transport;
        return new
        {
            enabled = resolved.Enabled,
            host = t.Host,
            port = t.Port,
            security = t.Security,
            username = t.Username,
            hasPassword = !string.IsNullOrEmpty(t.Password),
            fromAddress = t.FromAddress,
            configured = resolved.Configured,
            secretsAvailable,
        };
    }

    /// <summary>
    /// Writes the request's fields to <c>instance_settings</c> via
    /// <see cref="OrgRepository.SetInstanceSettingAsync"/> (which envelope-encrypts
    /// <c>smtp_password</c> automatically once a master key is configured). The password is
    /// written only when the caller supplied a non-empty value — the caller is responsible for
    /// having already checked <c>EnvelopeProtector.IsConfigured</c> before calling this when
    /// <see cref="EmailConfigRequest.Password"/> is non-empty.
    /// </summary>
    public static async Task ApplyAsync(OrgRepository orgs, EmailConfigRequest req, CancellationToken ct)
    {
        await orgs.SetInstanceSettingAsync("smtp_enabled", req.Enabled ? "1" : "0", ct);
        await orgs.SetInstanceSettingAsync("smtp_host", req.Host ?? "", ct);
        await orgs.SetInstanceSettingAsync("smtp_port", req.Port.ToString(CultureInfo.InvariantCulture), ct);
        await orgs.SetInstanceSettingAsync("smtp_security", req.Security.ToLowerInvariant(), ct);
        await orgs.SetInstanceSettingAsync("smtp_username", req.Username ?? "", ct);
        await orgs.SetInstanceSettingAsync("smtp_from_address", req.FromAddress ?? "", ct);

        if (!string.IsNullOrEmpty(req.Password))
        {
            await orgs.SetInstanceSettingAsync("smtp_password", req.Password, ct);
        }
    }
}
