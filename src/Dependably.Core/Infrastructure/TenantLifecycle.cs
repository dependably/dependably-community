namespace Dependably.Infrastructure;

/// <summary>
/// Single statement of the "does a per-tenant scheduled job or delivery worker skip a
/// non-active org" rule — the background-work analog of
/// <see cref="TenantStatusEnforcementMiddleware"/>'s inbound-request gate. That middleware only
/// sits in the HTTP pipeline, so nothing that runs off a cron schedule or a dispatch-queue timer
/// consults <c>orgs.status</c> on its own. Every per-tenant scheduled pass and delivery worker
/// applies <see cref="ActiveStatus"/> at its own per-org selection point instead of inheriting a
/// shared query or base-class hook, because the jobs differ in how they enumerate tenants: some
/// select rows joined to <c>orgs</c> per pass (<c>RetentionService</c>,
/// <c>VulnerabilityScanService</c>, <c>DeprecationRefreshService</c>'s two group queries), and
/// one drains a per-org delivery queue keyed by an envelope's own <c>OrgId</c>
/// (<c>WebhookDispatchQueue</c>), which calls <see cref="IsActive(Org?)"/> because it already
/// holds the row rather than issuing SQL. A SQL call site writes the equivalent
/// <c>o.status = 'active'</c> predicate directly in its per-org SELECT — the same textual-literal
/// convention every one of those queries already uses for <c>o.deleted_at IS NULL</c> — rather
/// than splicing this type's name into the query text.
///
/// <para>
/// Not every hosted worker in the repo is per-tenant, and not every per-tenant one is
/// egress-producing, so this rule does not apply to every <c>BackgroundService</c>/
/// <c>ScheduledBackgroundService</c> subclass uniformly — each one that does not apply it carries
/// its own <c>// suspension-ok: &lt;reason&gt;</c> marker at the site instead, because the rule's
/// premise (a tenant-owned resource, or a tenant-owned delivery target, or a per-org selection
/// point at all) does not hold for it. The shapes recur: a shared, content-addressed resource
/// with no single tenant owner (<c>CacheEvictionService</c>'s <c>cache_artifact</c> rows,
/// reachable through many orgs' <c>tenant_artifact_access</c> bindings at once — its OCI arm's
/// correctness additionally depends on releasing every holder's own claim regardless of that
/// holder's status); a delivery or alert target that is the operator's own, never a tenant's
/// (<c>SiemForwarderQueue</c>, <c>SystemSlackQueue</c>, <c>HealthcheckPinger</c>, and
/// <c>SamlCertExpiryCheckService</c> — the cert-expiry alert it emits is an audit_log write
/// platform admins read cross-tenant, and a suspended tenant is exactly who the operator most
/// needs the warning about, since their IdP cert can still expire while they are locked out and
/// reinstating them re-enables SSO immediately); a fleet-wide
/// sweep with no per-org axis at all (the OCI reconciliation/janitor jobs, the instance-wide
/// observability pollers); a write-behind flush of events a suspended org could not have
/// generated in the first place, because the request that would have produced them is already
/// refused by <see cref="TenantStatusEnforcementMiddleware"/> (<c>ActivityWriterHostedService</c>,
/// <c>DownloadCountWriterHostedService</c>); and a job whose entire worklist IS non-active orgs,
/// making "skip a non-active org" self-contradictory (<c>TenantHardDeleteService</c>, which reaps
/// on <c>deleted_at</c>, an axis independent of <c>status</c>). This list is illustrative, not
/// exhaustive or load-bearing — <c>BackgroundJobSuspensionComplianceTests</c> is what enumerates
/// every current exemption and requires each to carry its own reasoned marker; read that gate's
/// output, not this comment, for the authoritative current set.
/// </para>
///
/// <para>
/// The rule is applied <b>per org within a batch pass, never by aborting the whole pass</b>: a
/// sweep that processes many orgs in one tick skips a non-active org's rows and continues with
/// every other org's, exactly as it already does for a soft-deleted or air-gapped org. Treating
/// one suspended tenant as a reason to stop maintenance for every other tenant would be a denial
/// of service the operator inflicts on itself.
/// </para>
///
/// <para>
/// <b>Accepted consequence: freezing retention for a suspended org extends that org's data
/// lifetime.</b> <c>RetentionService</c> enforcing this rule means a suspended tenant's
/// <c>keep_versions</c>, <c>keep_days</c>, and <c>purge_unlisted_after_days</c> policies — and
/// its activity-row pruning — stop advancing for as long as the org stays non-active. A long
/// suspension therefore extends that tenant's data lifetime beyond its own configured retention
/// window; the data is not "aged out on schedule" while the org is locked out, it is frozen in
/// place. Reinstating the org resumes enforcement from wherever the clock-driven cutoffs land on
/// the next scheduled pass — there is no catch-up sweep for the frozen interval, and no separate
/// data-residency guarantee is made for a suspended tenant's retained data. A deletion-on-schedule
/// or data-residency commitment made on top of retention needs to account for this: the guarantee
/// is "ages out on schedule while active", not "ages out on schedule, full stop".
/// </para>
/// </summary>
public static class TenantLifecycle
{
    /// <summary>
    /// The only <c>orgs.status</c> value that admits scheduled background work for an org,
    /// matching the value <see cref="TenantStatusEnforcementMiddleware"/> requires for an inbound
    /// request.
    /// </summary>
    public const string ActiveStatus = "active";

    /// <summary>
    /// Status-only check, private: every SQL call site pairs <c>o.status = 'active'</c> with
    /// <c>o.deleted_at IS NULL</c> — a soft-deleted org (<see cref="OrgRepository.SoftDeleteAsync"/>)
    /// leaves <c>status</c> untouched at <c>'active'</c>, so a status-only check alone reads a
    /// soft-deleted org as active for the whole 30-day restore grace window. No caller outside
    /// this class should ever make that mistake, so this overload is not exposed publicly — it
    /// exists only as the shared primitive <see cref="IsActive(Org?)"/> builds on, never as a
    /// check a worker calls directly with just the status column.
    /// </summary>
    private static bool IsActive(string? status) =>
        string.Equals(status, ActiveStatus, StringComparison.Ordinal);

    /// <summary>
    /// Full-row check for a worker that already holds the org's row rather than issuing its own
    /// SQL predicate — see the class doc comment for why that split exists. Requires both
    /// <see cref="Org.DeletedAt"/> to be null and <see cref="Org.Status"/> to be
    /// <see cref="ActiveStatus"/>, matching every SQL call site's paired
    /// <c>o.deleted_at IS NULL AND o.status = 'active'</c> predicate — a soft-deleted org is not
    /// active even though <c>UpdateOrgStatusAsync</c> never changes its <c>status</c> column.
    /// </summary>
    public static bool IsActive(Org? org) =>
        org is not null && org.DeletedAt is null && IsActive(org.Status);
}
