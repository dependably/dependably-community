namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// Vocabulary for <c>alert.email_status</c> — the tenant-visible projection of what happened to
/// this alert's email. It is a <b>state</b>, not a counter: writing the same value twice leaves
/// the column exactly as it was, which is what makes the outcome safe to re-project from the
/// authoritative <c>email_outbox</c> row when the original projection write did not land.
///
/// <para>
/// NULL is a fourth, unnamed value and carries no constant on purpose: it means "nothing has been
/// projected here", which is the absence these constants describe rather than a member of the set.
/// </para>
/// </summary>
public static class AlertEmailStatuses
{
    /// <summary>The relay accepted the message — the outbox row reached <c>delivered</c>.</summary>
    public const string Sent = "sent";

    /// <summary>
    /// The message will not be delivered: the outbox row reached <c>dead_letter</c> or
    /// <c>expired</c>, or the enqueue itself was refused at the outbox depth cap.
    /// </summary>
    public const string Failed = "failed";

    /// <summary>
    /// This alert's own email was folded into another alert's still-pending digest row. The
    /// digest's own delivery outcome lands on whichever alert opened it, so this alert never
    /// receives a <see cref="Sent"/>/<see cref="Failed"/> of its own.
    /// </summary>
    public const string Coalesced = "coalesced";
}
