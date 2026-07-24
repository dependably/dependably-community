using Microsoft.Extensions.Localization;

namespace Dependably.Infrastructure.Mail;

/// <summary>
/// Entry point for account-lifecycle transactional email that is not tied to a specific alert or
/// invite: the self-serve "forgot password" reset link, and account-security event notifications
/// (MFA enabled/disabled, password changed). Wraps each send as an <see cref="IEmailDeliveryJob"/>
/// and enqueues it onto the shared <see cref="EmailDeliveryQueue"/>, the same delivery core
/// <see cref="Alerts.AlertEmailQueue"/> uses.
/// </summary>
public sealed class TransactionalEmailService
{
    private readonly EmailDeliveryQueue _queue;
    private readonly InstanceSmtpConfig _instanceConfig;
    private readonly IStringLocalizer<SharedResource> _localizer;
    private readonly ILogger<TransactionalEmailService> _logger;

    public TransactionalEmailService(
        EmailDeliveryQueue queue,
        InstanceSmtpConfig instanceConfig,
        IStringLocalizer<SharedResource> localizer,
        ILogger<TransactionalEmailService> logger)
    {
        _queue = queue;
        _instanceConfig = instanceConfig;
        _localizer = localizer;
        _logger = logger;
    }

    /// <summary>
    /// Non-blocking: enqueues a password-reset email for delivery. A no-op (nothing sent, no
    /// exception) when the instance SMTP transport is not enabled/configured — the caller
    /// (<c>AuthController</c>) still returns 202 either way, since the response must never
    /// reveal whether delivery is even possible for a given account.
    /// </summary>
    public void EnqueuePasswordReset(string toAddress, string resetLink, DateTimeOffset expiresAt) =>
        _queue.Enqueue(new PasswordResetEmailJob(toAddress, resetLink, expiresAt, _instanceConfig, _localizer, _logger));

    /// <summary>
    /// Non-blocking: enqueues an "MFA enabled" notification to the acting user's own address, in
    /// their already-resolved effective language. A no-op when the instance SMTP transport is not
    /// enabled/configured — callers never gate the HTTP response on delivery.
    /// </summary>
    public void EnqueueMfaEnabled(string toAddress, string language, DateTimeOffset occurredAt) =>
        _queue.Enqueue(new SecurityEventEmailJob(
            SecurityEventKind.MfaEnabled, toAddress, language, occurredAt, _instanceConfig, _localizer, _logger));

    /// <summary>
    /// Non-blocking: enqueues an "MFA disabled" notification to the acting user's own address, in
    /// their already-resolved effective language. A no-op when the instance SMTP transport is not
    /// enabled/configured — callers never gate the HTTP response on delivery.
    /// </summary>
    public void EnqueueMfaDisabled(string toAddress, string language, DateTimeOffset occurredAt) =>
        _queue.Enqueue(new SecurityEventEmailJob(
            SecurityEventKind.MfaDisabled, toAddress, language, occurredAt, _instanceConfig, _localizer, _logger));

    /// <summary>
    /// Non-blocking: enqueues a "password changed" notification to the affected user's own
    /// address, in their already-resolved effective language. Fires at every credential-change
    /// site (self-service change, self-serve recovery reset, system-admin self-rotate, and
    /// operator-forced reset of a tenant user). A no-op when the instance SMTP transport is not
    /// enabled/configured — callers never gate the HTTP response on delivery.
    /// </summary>
    public void EnqueuePasswordChanged(string toAddress, string language, DateTimeOffset occurredAt) =>
        _queue.Enqueue(new SecurityEventEmailJob(
            SecurityEventKind.PasswordChanged, toAddress, language, occurredAt, _instanceConfig, _localizer, _logger));
}
