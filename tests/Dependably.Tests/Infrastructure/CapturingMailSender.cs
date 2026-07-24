using Dependably.Infrastructure.Mail;
using Dependably.Security;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Test double for <see cref="SmtpMailSender"/> that never touches the network — it records every
/// send (transport, recipients, subject, body) and completes immediately. Opt in via
/// <see cref="DependablyFactory.MailSenderOverride"/> / <see cref="DependablyMultiFactory.MailSenderOverride"/>
/// so a test can assert exactly which address a fire site enqueued a notification to, the same
/// way <c>EmailDeliveryQueueTests.FakeMailSender</c> does for the hand-wired unit-test queue, but
/// through the real production DI wiring (real <see cref="TransactionalEmailService"/>, real
/// <see cref="InstanceSmtpConfig"/>, real controller call sites) rather than a hand-built job.
/// </summary>
public sealed class CapturingMailSender : SmtpMailSender
{
    public sealed record SentMessage(SmtpTransportSettings Transport, IReadOnlyList<string> Recipients, string Subject, string Body);

    private readonly object _lock = new();
    private readonly List<SentMessage> _sent = [];

    public CapturingMailSender() : base(new SsrfConnectCallback(_ => false))
    {
    }

    /// <summary>Snapshot of every send recorded so far, in call order.</summary>
    public IReadOnlyList<SentMessage> Sent
    {
        get
        {
            lock (_lock)
            {
                return _sent.ToList();
            }
        }
    }

    public override Task SendAsync(
        SmtpTransportSettings transport, IReadOnlyList<string> to, string subject, string body,
        CancellationToken ct = default)
    {
        lock (_lock)
        {
            _sent.Add(new SentMessage(transport, to, subject, body));
        }

        return Task.CompletedTask;
    }
}
