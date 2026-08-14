using Microsoft.Extensions.Configuration;
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
    private readonly bool _allowInsecureCredentialMail;
    private readonly IStringLocalizer<SharedResource> _localizer;
    private readonly ILogger<TransactionalEmailService> _logger;

    public TransactionalEmailService(
        EmailDeliveryQueue queue,
        InstanceSmtpConfig instanceConfig,
        IConfiguration config,
        IStringLocalizer<SharedResource> localizer,
        ILogger<TransactionalEmailService> logger)
    {
        _queue = queue;
        _instanceConfig = instanceConfig;
        // Resolved once, like WebhookSiemForwarder resolves its own insecure-override env var
        // once at construction — env vars do not change for the lifetime of the process.
        _allowInsecureCredentialMail = CredentialMailPolicy.AllowsInsecure(config);
        _localizer = localizer;
        _logger = logger;
    }

    /// <summary>
    /// Non-blocking: enqueues a password-reset email for delivery. A no-op (nothing sent, no
    /// exception) when the instance SMTP transport is not enabled/configured, or when it is
    /// configured but unencrypted and <see cref="CredentialMailPolicy"/> has not been overridden
    /// — the caller (<c>AuthController</c>) still returns 202 either way, since the response must
    /// never reveal whether delivery is even possible for a given account.
    /// </summary>
    public void EnqueuePasswordReset(string toAddress, string resetLink, DateTimeOffset expiresAt) =>
        _queue.Enqueue(new PasswordResetEmailJob(
            toAddress, resetLink, expiresAt, _instanceConfig, _allowInsecureCredentialMail, _localizer, _logger));

    /// <summary>
    /// Non-blocking: enqueues the verification link for a pending email change to the address
    /// being moved TO — possession of that mailbox is what authorizes the move. A no-op when the
    /// instance SMTP transport is not enabled/configured, or configured but unencrypted and not
    /// overridden per <see cref="CredentialMailPolicy"/>; either way the pending request simply
    /// expires unredeemed and the account keeps its current address.
    /// </summary>
    public void EnqueueEmailChangeVerification(string toAddress, string verifyLink, DateTimeOffset expiresAt) =>
        _queue.Enqueue(new EmailChangeVerificationJob(
            toAddress, verifyLink, expiresAt, _instanceConfig, _allowInsecureCredentialMail, _localizer, _logger));

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
    /// Non-blocking: enqueues an "email address changed" notification to the address the account
    /// just moved AWAY from, in the user's effective language. That mailbox has lost control of
    /// the account, so it is the one place a hostile change still surfaces to someone able to act
    /// on it. A no-op when the instance SMTP transport is not enabled/configured.
    /// </summary>
    public void EnqueueEmailChanged(string toAddress, string language, DateTimeOffset occurredAt) =>
        _queue.Enqueue(new SecurityEventEmailJob(
            SecurityEventKind.EmailChanged, toAddress, language, occurredAt, _instanceConfig, _localizer, _logger));

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
