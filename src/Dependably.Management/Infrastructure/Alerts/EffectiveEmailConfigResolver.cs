using Dependably.Infrastructure.Mail;

namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// Resolves the transport an org's alert email channel actually delivers through: the org's own
/// SMTP config when it opted out of inheritance, or the instance-level transport when it didn't
/// — genuinely evaluating the same inherit path the delivery queue and the test-send endpoint use,
/// rather than re-deriving it ad hoc at each call site.
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
    /// Returns null when the channel is disabled, has no recipients, or resolves to no usable
    /// transport (inheriting instance email that isn't enabled/configured, or an own transport
    /// that isn't fully configured) — the caller (delivery queue, test-send endpoint) treats null
    /// as "nothing to send", never a fallback to some other transport.
    /// </summary>
    public async Task<ResolvedEmailConfig?> ResolveAsync(string orgId, CancellationToken ct = default)
    {
        var delivery = await _settings.GetDecryptedEmailDeliveryConfigAsync(orgId, ct);
        if (delivery is null)
        {
            return null;
        }

        if (delivery.InheritInstance)
        {
            var instance = await _instanceConfig.ResolveAsync(ct);
            return instance.Enabled && instance.Configured
                ? new ResolvedEmailConfig(instance.Transport, delivery.Recipients)
                : null;
        }

        return delivery.OwnTransport.IsConfigured
            ? new ResolvedEmailConfig(delivery.OwnTransport, delivery.Recipients)
            : null;
    }
}
