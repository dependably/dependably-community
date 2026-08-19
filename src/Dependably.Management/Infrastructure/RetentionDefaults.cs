namespace Dependably.Infrastructure;

/// <summary>
/// The instance-wide activity-retention default, resolved in one place so the GC that enforces it
/// and the settings API that reports it can never disagree.
///
/// <c>activity_retention_days</c> is the one retention dimension whose NULL does not mean
/// unlimited: <c>keep_versions</c>, <c>keep_days</c> and <c>purge_unlisted_after_days</c> are
/// opt-in and skipped entirely when NULL, while a NULL activity window resolves to the value
/// below. That asymmetry is deliberate — <c>activity</c> rows carry per-download IP and actor
/// data (the table is marked <c>personal-data: included</c> in the schema), so they are bounded
/// by default rather than retained forever. It is also invisible to an operator unless the
/// settings surface says so, which is why this is public rather than private to the GC.
/// </summary>
public static class RetentionDefaults
{
    /// <summary>
    /// Days of <c>activity</c> history retained for an org whose <c>activity_retention_days</c>
    /// is NULL. Matches the schema column default.
    /// </summary>
    public const int ActivityRetentionDays = 90;

    /// <summary>
    /// The effective default, honouring the <c>ACTIVITY_RETENTION_DAYS</c> instance override.
    /// A non-positive or unparseable override falls back to <see cref="ActivityRetentionDays"/>
    /// rather than disabling the bound — a misconfigured value must not silently turn retention
    /// of personal data into "forever".
    /// </summary>
    public static int ResolveActivityRetentionDays(IConfiguration? config) =>
        int.TryParse(config?["ACTIVITY_RETENTION_DAYS"], out int d) && d > 0
            ? d
            : ActivityRetentionDays;
}
