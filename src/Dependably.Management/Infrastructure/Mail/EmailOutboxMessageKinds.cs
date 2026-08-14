namespace Dependably.Infrastructure.Mail;

/// <summary>
/// The <c>email_outbox.message_kind</c> vocabulary. The kind selects what terminal bookkeeping the
/// delivery worker performs once a message reaches a terminal state, which is why it is a column and
/// not an inference from the other fields.
/// </summary>
public static class EmailOutboxMessageKinds
{
    /// <summary>
    /// Per-org alert mail. Terminal outcomes stamp <c>alert.email_status</c> and the org's
    /// <c>alert_settings</c> delivery-health columns, keyed by <c>correlation_id</c>.
    /// </summary>
    public const string Alert = "alert";

    /// <summary>
    /// Org invite mail. Declared capacity with no writer: invite sending stays synchronous because
    /// its caller falls back to showing the invite link in the response when the relay is
    /// unavailable, and that fallback needs a per-request success/failure answer the outbox cannot
    /// give. Declared now so routing invites here later is a code change, not a schema change.
    /// </summary>
    public const string Invite = "invite";
}

/// <summary>
/// Builds the outbox coalescing key — the natural key a later burst-coalescing pass groups on.
///
/// <para>
/// The key is recorded from the first release even though nothing reads it yet. That is the whole
/// point: an outbox that only gains the column once coalescing is implemented has to backfill it
/// across an existing backlog, and the backlog is precisely the thing that exists when the feature
/// is needed. Persisting it up front makes the later change a query, not a migration.
/// </para>
///
/// <para>
/// It deliberately excludes the org: <c>org_id</c> is its own column, and grouping is
/// <c>(org_id, coalesce_key)</c> so one tenant's burst can never collapse into another's.
/// </para>
/// </summary>
public static class EmailOutboxCoalescing
{
    /// <summary>
    /// The alert-mail key: the alert kind plus the package coordinate it concerns. Falls back to the
    /// alert's dedup source reference when there is no purl (a coordinate-less alert type), so the
    /// key is never empty and never collapses unrelated alerts onto each other.
    /// </summary>
    public static string ForAlert(string alertType, string? purl, string sourceRef) =>
        $"{Alert(alertType)}:{Coordinate(purl, sourceRef)}";

    private static string Alert(string alertType) =>
        string.IsNullOrWhiteSpace(alertType) ? "unknown" : alertType;

    private static string Coordinate(string? purl, string sourceRef) =>
        string.IsNullOrWhiteSpace(purl) ? sourceRef : purl;
}
