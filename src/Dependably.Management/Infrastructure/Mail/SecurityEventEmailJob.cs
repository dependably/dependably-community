using System.Globalization;
using Microsoft.Extensions.Localization;

namespace Dependably.Infrastructure.Mail;

/// <summary>Account-security events that notify the acting user of their own account change.</summary>
public enum SecurityEventKind
{
    MfaEnabled,
    MfaDisabled,
    PasswordChanged,
    EmailChanged,
}

/// <summary>
/// Wraps an account-security notification (MFA enabled/disabled, password changed) as an
/// <see cref="IEmailDeliveryJob"/> for the shared <see cref="EmailDeliveryQueue"/>. Resolves only
/// the instance-level SMTP transport, exactly like <see cref="PasswordResetEmailJob"/> — there is
/// no per-org resolver, no new table, and delivery failure is logged only (no auto-disable
/// health state). Unlike <see cref="PasswordResetEmailJob"/>, rendering is not English-pinned:
/// the caller has already resolved the recipient's effective language (per-user override → org
/// default → <see cref="LanguageCodes.Default"/>, via <see cref="LanguageCodes.ResolveEffective"/>)
/// before constructing this job, so <see cref="Render"/> pins the ambient culture to that
/// resolved language instead.
/// </summary>
internal sealed class SecurityEventEmailJob : IEmailDeliveryJob
{
    private readonly SecurityEventKind _kind;
    private readonly string _toAddress;
    private readonly string _language;
    private readonly DateTimeOffset _occurredAt;
    private readonly InstanceSmtpConfig _instanceConfig;
    private readonly IStringLocalizer<SharedResource> _localizer;
    private readonly ILogger _logger;

    public SecurityEventEmailJob(
        SecurityEventKind kind,
        string toAddress,
        string language,
        DateTimeOffset occurredAt,
        InstanceSmtpConfig instanceConfig,
        IStringLocalizer<SharedResource> localizer,
        ILogger logger)
    {
        _kind = kind;
        _toAddress = toAddress;
        _language = language;
        _occurredAt = occurredAt;
        _instanceConfig = instanceConfig;
        _localizer = localizer;
        _logger = logger;
    }

    public async Task<(SmtpTransportSettings Transport, IReadOnlyList<string> Recipients)?> ResolveAsync(CancellationToken ct)
    {
        var resolved = await _instanceConfig.ResolveAsync(ct);
        return resolved.Enabled && resolved.Configured
            ? (resolved.Transport, new[] { _toAddress })
            : null;
    }

    /// <summary>
    /// Renders in the resolved recipient language (unsupported/absent codes fall back to
    /// English) — the ambient <see cref="CultureInfo.CurrentUICulture"/> is pinned for the
    /// duration of the lookups, then restored, same pattern as
    /// <see cref="SmtpInviteMailer.ComposeInvite"/>. The event timestamp stays in the
    /// locale-neutral ISO <c>yyyy-MM-dd HH:mm</c> form regardless of the recipient's language.
    /// </summary>
    public (string Subject, string Body) Render()
    {
        var original = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentUICulture = new CultureInfo(
                LanguageCodes.IsSupported(_language) ? _language : LanguageCodes.Default);
            string occurred = _occurredAt.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
            (string subjectKey, string bodyKey) = _kind switch
            {
                SecurityEventKind.MfaEnabled => ("email.security.mfaEnabled.subject", "email.security.mfaEnabled.body"),
                SecurityEventKind.MfaDisabled => ("email.security.mfaDisabled.subject", "email.security.mfaDisabled.body"),
                SecurityEventKind.PasswordChanged => ("email.security.passwordChanged.subject", "email.security.passwordChanged.body"),
                SecurityEventKind.EmailChanged => ("email.security.emailChanged.subject", "email.security.emailChanged.body"),
                _ => throw new ArgumentOutOfRangeException(nameof(_kind), _kind, "Unknown security event kind."),
            };
            string subject = _localizer[subjectKey];
            string body = _localizer[bodyKey, occurred];
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
            "Security event email ({EventKind}) delivered via SMTP to {RecipientDomain}.",
            _kind, ExtractDomain(_toAddress));
        return Task.CompletedTask;
    }

    public Task RecordFailureAsync(string error)
    {
        _logger.LogWarning(
            "Security event email ({EventKind}) delivery failed to {RecipientDomain}: {Error}",
            _kind, ExtractDomain(_toAddress), error);
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
