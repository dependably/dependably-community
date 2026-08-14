using Dependably.Infrastructure.Mail;

namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// Resolves whether an org's alert email channel can actually deliver, and to whom: the channel
/// gate and recipient list from <c>alert_settings</c>, carried over the one instance-level SMTP
/// transport. SMTP is an instance-level transport — an org configures how Dependably uses it (on or
/// off, and to which recipients), never how mail is carried — so the only per-org inputs are the
/// gate and the list. Kept as one seam rather than re-derived at each call site so the delivery
/// queue and the test-send endpoint cannot drift apart on what "deliverable" means.
/// </summary>
public sealed class EffectiveEmailConfigResolver
{
    private readonly AlertSettingsRepository _settings;
    private readonly InstanceSmtpConfig _instanceConfig;

    public EffectiveEmailConfigResolver(AlertSettingsRepository settings, InstanceSmtpConfig instanceConfig)
    {
        _settings = settings;
        _instanceConfig = instanceConfig;
    }

    /// <summary>The transport and recipient list an alert email actually sends through.</summary>
    public sealed record ResolvedEmailConfig(SmtpTransportSettings Transport, string[] Recipients);

    /// <summary>
    /// Returns null when the channel is disabled, has no recipients, or the instance transport is
    /// not enabled/configured — the caller (delivery queue, test-send endpoint) treats null as
    /// "nothing to send", never a fallback to some other transport.
    /// </summary>
    public async Task<ResolvedEmailConfig?> ResolveAsync(string orgId, CancellationToken ct = default)
    {
        var delivery = await _settings.GetDecryptedEmailDeliveryConfigAsync(orgId, ct);
        if (delivery is null)
        {
            return null;
        }

        var instance = await _instanceConfig.ResolveAsync(ct);
        return instance.Enabled && instance.Configured
            ? new ResolvedEmailConfig(instance.Transport, delivery.Recipients)
            : null;
    }
}
