using System.Net.Sockets;
using Dependably.Protocol;
using MailKit;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace Dependably.Infrastructure.Mail;

/// <summary>The three failure classes an outbox delivery attempt can produce.</summary>
public static class EmailOutboxFailureClasses
{
    /// <summary>The relay could not take the message right now. Retry on the backoff.</summary>
    public const string Transient = "transient";

    /// <summary>The message or the configuration is wrong. Do not retry; dead-letter it.</summary>
    public const string Permanent = "permanent";

    /// <summary>
    /// Not recognised. Retried like a transient failure but bounded by the retry ceiling, so a
    /// novel failure degrades into "gives up eventually" rather than "dropped immediately".
    /// </summary>
    public const string Unknown = "unknown";
}

/// <summary>
/// Classifies a delivery exception as transient, permanent, or unrecognised, off the exception
/// types MailKit and the SMTP transport actually raise.
///
/// <para>
/// The split matters because it selects the terminal state: a transient failure retries, a
/// permanent one dead-letters immediately with the reason visible to an operator. Getting it wrong
/// in the permanent direction discards mail that would have been delivered a minute later, so
/// permanence is asserted only where the SMTP protocol or the message itself says so —
/// <see cref="SmtpCommandException"/> with a 5xx status, an unparseable recipient address, a
/// credential the relay refuses, and <see cref="SsrfBlockedException"/> (a relay host the guard
/// will refuse identically on every retry — a configuration error, not an outage).
/// </para>
///
/// <para>
/// Everything unmatched is <see cref="EmailOutboxFailureClasses.Unknown"/> rather than permanent.
/// That is the fail-safe direction: an unrecognised failure keeps its retries and is retired by the
/// retry/retention ceilings instead of being thrown away on the first attempt. A TLS handshake
/// failure is deliberately in that bucket and not permanent — an expired relay certificate is an
/// outage-shaped event that a renewal fixes without the message needing to change.
/// </para>
/// </summary>
public static class EmailOutboxFailureClassifier
{
    public static string Classify(Exception ex) => ex switch
    {
        // The guard resolves and vets the relay host before dialing. A blocked or unresolvable
        // host is operator configuration: every retry reaches the identical verdict.
        SsrfBlockedException => EmailOutboxFailureClasses.Permanent,

        // The protocol's own verdict. 4xx is "not now" (greylisting, mailbox busy, out of
        // resources); 5xx is "not ever, as sent" (unknown recipient, message rejected, relay
        // refused). Must precede the ProtocolException arms below — SmtpCommandException derives
        // from ProtocolException, so a broader arm placed first would swallow it.
        SmtpCommandException command => ClassifyStatus((int)command.StatusCode),

        // The relay refused the credential. MailKit surfaces the SMTP 5xx auth rejection as its own
        // type rather than an SmtpCommandException, so it is classified here on the same 5xx rule.
        AuthenticationException => EmailOutboxFailureClasses.Permanent,

        // An address that does not parse. Malformed message; retrying re-sends the same bytes.
        ParseException => EmailOutboxFailureClasses.Permanent,

        // Transport-level: the conversation broke, the socket failed, or nothing answered in time.
        SmtpProtocolException => EmailOutboxFailureClasses.Transient,
        ProtocolException => EmailOutboxFailureClasses.Transient,
        ServiceNotConnectedException => EmailOutboxFailureClasses.Transient,
        SocketException => EmailOutboxFailureClasses.Transient,
        IOException => EmailOutboxFailureClasses.Transient,
        TimeoutException => EmailOutboxFailureClasses.Transient,
        OperationCanceledException => EmailOutboxFailureClasses.Transient,

        _ => EmailOutboxFailureClasses.Unknown,
    };

    private static string ClassifyStatus(int status) => status switch
    {
        >= 400 and < 500 => EmailOutboxFailureClasses.Transient,
        >= 500 and < 600 => EmailOutboxFailureClasses.Permanent,
        _ => EmailOutboxFailureClasses.Unknown,
    };
}
