using System.Threading.RateLimiting;
using Microsoft.Extensions.Configuration;

namespace Dependably.Security;

/// <summary>
/// The tenant settings behind <see cref="TenantRateLimiter"/>, resolved once at startup.
/// </summary>
/// <param name="BudgetPermits">
/// <c>TENANT_RATE_LIMIT_PERMITS</c>: requests per second one org may make on the protocol plane,
/// across all of its tokens and source addresses. Null (unset, unparseable or not positive)
/// switches the budget off.
/// </param>
/// <param name="BudgetQueue"><c>TENANT_RATE_LIMIT_QUEUE</c>: how many over-budget requests wait for a permit before a 429.</param>
/// <param name="ThrottledPermits">
/// <c>TENANT_THROTTLED_RATE_LIMIT_PERMITS</c>: requests per second for an org whose usage posture
/// is <c>downloads_throttled</c>. Always on; it replaces the budget for such an org.
/// </param>
/// <param name="ThrottledQueue"><c>TENANT_THROTTLED_RATE_LIMIT_QUEUE</c>: the throttled partition's queue depth.</param>
internal sealed record TenantRateLimitSettings(
    int? BudgetPermits,
    int BudgetQueue,
    int ThrottledPermits,
    int ThrottledQueue)
{
    /// <summary>Default queue depth for the per-tenant budget, when the budget is on.</summary>
    internal const int DefaultBudgetQueueLimit = 100;

    /// <summary>
    /// Default requests per second for a <c>downloads_throttled</c> org. Small on purpose: enough
    /// that a developer can still install a handful of packages, far too few for a CI fleet to keep
    /// pulling at volume past its egress cap.
    /// </summary>
    internal const int DefaultThrottledPermitLimit = 10;

    /// <summary>
    /// Default queue depth for the throttled partition. A short burst waits for permits rather
    /// than failing at once, which is what makes the posture a throttle and not a refusal.
    /// </summary>
    internal const int DefaultThrottledQueueLimit = 20;

    internal static TenantRateLimitSettings Resolve(IConfiguration cfg)
    {
        int? budget = int.TryParse(cfg["TENANT_RATE_LIMIT_PERMITS"], out int b) && b > 0 ? b : null;
        int budgetQueue = int.TryParse(cfg["TENANT_RATE_LIMIT_QUEUE"], out int bq) && bq >= 0
            ? bq
            : DefaultBudgetQueueLimit;
        int throttled = int.TryParse(cfg["TENANT_THROTTLED_RATE_LIMIT_PERMITS"], out int t) && t > 0
            ? t
            : DefaultThrottledPermitLimit;
        int throttledQueue = int.TryParse(cfg["TENANT_THROTTLED_RATE_LIMIT_QUEUE"], out int tq) && tq >= 0
            ? tq
            : DefaultThrottledQueueLimit;
        return new TenantRateLimitSettings(budget, budgetQueue, throttled, throttledQueue);
    }
}

/// <summary>
/// The tenant dimension of the global rate limiter, chained after the per-caller limits by
/// <see cref="Chain"/> so a request must pass both. It bounds one org's aggregate protocol-plane
/// rate however many tokens and addresses it spreads the load over. The partition comes from
/// <see cref="RateLimitPartitions.GetTenantPartitionKey"/>: <c>tenant:{id}</c> at
/// <c>TENANT_RATE_LIMIT_PERMITS</c> normally, and <c>tenant-throttled:{id}</c> at
/// <c>TENANT_THROTTLED_RATE_LIMIT_PERMITS</c> while the org's usage posture is
/// <c>downloads_throttled</c>. Like <c>download</c> and <c>push</c>, the state is per replica.
///
/// <para>
/// A rejection this limiter makes stamps the rejected partition key into
/// <c>HttpContext.Items</c> under <see cref="RejectedPartitionItemKey"/>. The chained limiter's
/// failed lease does not say which link refused it, and the rejection metric and denial audit need
/// to name the tenant dimension rather than the caller partition the request would otherwise be
/// attributed to. The chain clears the marker at the start of every acquisition pass, so it only
/// ever describes the pass whose refusal the rejection callback is reporting.
/// </para>
///
/// <para>
/// The chain charges each request at most one permit per link. <c>RateLimitingMiddleware</c>
/// tries <c>AttemptAcquire</c> on the global limiter and then the endpoint policy, and when
/// either refuses it disposes whatever it was granted and waits in <c>AcquireAsync</c> on both
/// again. Every link here is a window limiter, which does not return a permit when a lease is
/// disposed, so each pass would otherwise charge the request afresh: a tenant refusal on the first
/// try cost the caller a second per-caller permit, and an endpoint policy that refused the first
/// try (a <c>download</c> or <c>metadata</c> request queueing on its own policy) cost the org a
/// second tenant permit. The chain records on the request which links a pass was granted, and a
/// later pass of the same request at the same permit count is granted those links again without
/// drawing on them. A link that refused is not recorded, so its next pass queues on it as usual.
/// The record lives in <c>HttpContext.Items</c>, which the host resets for every request.
/// </para>
/// </summary>
internal static class TenantRateLimiter
{
    /// <summary>
    /// The policy and partition-kind label a tenant-dimension rejection reports on the rejection
    /// metric and the denial audit. A fixed value: the partition key carries the org id, which is
    /// never a metric attribute.
    /// </summary>
    internal const string PolicyLabel = "tenant";

    /// <summary>The <c>HttpContext.Items</c> key a tenant-dimension rejection records its partition under.</summary>
    internal const string RejectedPartitionItemKey = "Dependably.RateLimit.TenantRejectedPartition";

    // Sliding-window segments per one-second window, the same granularity as download/push.
    private const int WindowSegments = 4;

    /// <summary>
    /// The <c>policy</c> and bounded <c>partition</c> labels a rejection reports on
    /// <c>dependably.rate_limit.rejected</c>. A rejection by this limiter reports
    /// <see cref="PolicyLabel"/> for both; any other reports the endpoint's
    /// <c>[EnableRateLimiting]</c> policy (or <c>unknown</c>, for the per-caller global limits) and
    /// the caller's partition kind.
    /// </summary>
    internal static (string Policy, string Partition) AttributeRejection(HttpContext ctx, int ipv6Prefix)
    {
        if (ctx.Items.ContainsKey(RejectedPartitionItemKey))
        {
            return (PolicyLabel, PolicyLabel);
        }

        string policy = ctx.GetEndpoint()
            ?.Metadata.GetMetadata<Microsoft.AspNetCore.RateLimiting.EnableRateLimitingAttribute>()
            ?.PolicyName ?? "unknown";
        return (policy, RateLimitPartitions.GetMetricLabel(ctx, ipv6Prefix));
    }

    /// <summary>
    /// The <c>GlobalLimiter</c>: <paramref name="perCaller"/> first, then the tenant dimension
    /// built from <paramref name="settings"/>. A request is granted only when both links grant it.
    /// The per-caller link goes first so a caller its own limit refuses never draws on its org's
    /// shared budget. The returned limiter owns and disposes both links.
    /// </summary>
    internal static PartitionedRateLimiter<HttpContext> Chain(
        PartitionedRateLimiter<HttpContext> perCaller, TenantRateLimitSettings settings) =>
        Chain(perCaller, Create(settings));

    /// <summary>
    /// <see cref="Chain(PartitionedRateLimiter{HttpContext}, TenantRateLimitSettings)"/> over a
    /// tenant link built by <see cref="Create"/>, for a caller that needs to read the tenant
    /// link's statistics.
    /// </summary>
    internal static PartitionedRateLimiter<HttpContext> Chain(
        PartitionedRateLimiter<HttpContext> perCaller, PartitionedRateLimiter<HttpContext> tenant)
    {
        ArgumentNullException.ThrowIfNull(perCaller);
        ArgumentNullException.ThrowIfNull(tenant);
        return new CallerThenTenantLimiter(perCaller, tenant);
    }

    internal static PartitionedRateLimiter<HttpContext> Create(TenantRateLimitSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var inner = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
        {
            string? key = RateLimitPartitions.GetTenantPartitionKey(ctx, settings.BudgetPermits is not null);
            if (key is null)
            {
                return RateLimitPartition.GetNoLimiter("none");
            }

            bool throttled = key.StartsWith(RateLimitPartitions.TenantThrottledPartitionPrefix, StringComparison.Ordinal);
            int permits = throttled ? settings.ThrottledPermits : settings.BudgetPermits!.Value;
            int queue = throttled ? settings.ThrottledQueue : settings.BudgetQueue;
            return RateLimitPartition.GetSlidingWindowLimiter(key, _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = permits,
                Window = TimeSpan.FromSeconds(1),
                SegmentsPerWindow = WindowSegments,
                QueueLimit = queue,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            });
        });
        return new RejectionMarkingLimiter(inner, settings.BudgetPermits is not null);
    }

    private sealed class RejectionMarkingLimiter(PartitionedRateLimiter<HttpContext> inner, bool budgetEnabled)
        : PartitionedRateLimiter<HttpContext>
    {
        public override RateLimiterStatistics? GetStatistics(HttpContext resource) => inner.GetStatistics(resource);

        protected override RateLimitLease AttemptAcquireCore(HttpContext resource, int permitCount) =>
            Mark(resource, inner.AttemptAcquire(resource, permitCount));

        protected override async ValueTask<RateLimitLease> AcquireAsyncCore(
            HttpContext resource, int permitCount, CancellationToken cancellationToken) =>
            Mark(resource, await inner.AcquireAsync(resource, permitCount, cancellationToken));

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }

            base.Dispose(disposing);
        }

        protected override ValueTask DisposeAsyncCore() => inner.DisposeAsync();

        // The marker reflects this limiter's latest answer for the request, not any earlier one.
        // RateLimitingMiddleware tries AttemptAcquire and then, on a refusal, AcquireAsync: a
        // tenant refusal on the first try followed by a queued grant must not leave the marker
        // behind, or a later refusal by the endpoint's own policy would be attributed to the
        // tenant dimension.
        private RateLimitLease Mark(HttpContext resource, RateLimitLease lease)
        {
            if (lease.IsAcquired)
            {
                resource.Items.Remove(RejectedPartitionItemKey);
            }
            else
            {
                resource.Items[RejectedPartitionItemKey] =
                    RateLimitPartitions.GetTenantPartitionKey(resource, budgetEnabled) ?? "tenant:unknown";
            }

            return lease;
        }
    }

    /// <summary>
    /// The per-caller link chained to the tenant link. See the remarks on
    /// <see cref="TenantRateLimiter"/> for why a request's charges are remembered across passes.
    /// </summary>
    private sealed class CallerThenTenantLimiter(
        PartitionedRateLimiter<HttpContext> perCaller, PartitionedRateLimiter<HttpContext> tenant)
        : PartitionedRateLimiter<HttpContext>
    {
        // Which links an earlier pass of this request was granted, and at what permit count.
        private const string ChargesItemKey = "Dependably.RateLimit.ChainCharges";

        public override RateLimiterStatistics? GetStatistics(HttpContext resource)
        {
            var caller = perCaller.GetStatistics(resource);
            var org = tenant.GetStatistics(resource);
            return caller is null || org is null
                ? caller ?? org
                : new RateLimiterStatistics
                {
                    CurrentAvailablePermits = Math.Min(caller.CurrentAvailablePermits, org.CurrentAvailablePermits),
                    CurrentQueuedCount = caller.CurrentQueuedCount + org.CurrentQueuedCount,
                    TotalFailedLeases = caller.TotalFailedLeases + org.TotalFailedLeases,
                    TotalSuccessfulLeases = Math.Min(caller.TotalSuccessfulLeases, org.TotalSuccessfulLeases),
                };
        }

        protected override RateLimitLease AttemptAcquireCore(HttpContext resource, int permitCount)
        {
            resource.Items.Remove(RejectedPartitionItemKey);
            var paid = PaidFor(resource, permitCount);
            var caller = paid.Caller ? new PrepaidLease() : perCaller.AttemptAcquire(resource, permitCount);
            if (!caller.IsAcquired)
            {
                return caller;
            }

            RateLimitLease org;
            try
            {
                org = paid.Tenant ? new PrepaidLease() : tenant.AttemptAcquire(resource, permitCount);
            }
            catch
            {
                caller.Dispose();
                throw;
            }

            return Settle(resource, permitCount, caller, org);
        }

        protected override async ValueTask<RateLimitLease> AcquireAsyncCore(
            HttpContext resource, int permitCount, CancellationToken cancellationToken)
        {
            resource.Items.Remove(RejectedPartitionItemKey);
            var paid = PaidFor(resource, permitCount);
            var caller = paid.Caller
                ? new PrepaidLease()
                : await perCaller.AcquireAsync(resource, permitCount, cancellationToken);
            if (!caller.IsAcquired)
            {
                return caller;
            }

            RateLimitLease org;
            try
            {
                org = paid.Tenant
                    ? new PrepaidLease()
                    : await tenant.AcquireAsync(resource, permitCount, cancellationToken);
            }
            catch
            {
                caller.Dispose();
                throw;
            }

            return Settle(resource, permitCount, caller, org);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                perCaller.Dispose();
                tenant.Dispose();
            }

            base.Dispose(disposing);
        }

        protected override async ValueTask DisposeAsyncCore()
        {
            await perCaller.DisposeAsync();
            await tenant.DisposeAsync();
        }

        // The links an earlier pass of this request already paid for at this permit count. A
        // zero-permit probe pays for nothing, so it is never recorded and never stands in for a
        // real acquisition.
        private static Charges PaidFor(HttpContext resource, int permitCount) =>
            permitCount > 0 && resource.Items[ChargesItemKey] is Charges charges && charges.PermitCount == permitCount
                ? charges
                : Charges.None;

        // Records what this pass was granted (a granted per-caller link is paid for even when the
        // tenant link then refuses), and answers with the chain's lease: both links' grants, or the
        // refusing tenant lease.
        private static RateLimitLease Settle(HttpContext resource, int permitCount, RateLimitLease caller, RateLimitLease org)
        {
            if (permitCount > 0)
            {
                resource.Items[ChargesItemKey] = new Charges(permitCount, Caller: true, Tenant: org.IsAcquired);
            }

            if (org.IsAcquired)
            {
                return new ChainedLease(caller, org);
            }

            caller.Dispose();
            return org;
        }

        private sealed record Charges(int PermitCount, bool Caller, bool Tenant)
        {
            internal static readonly Charges None = new(0, false, false);
        }
    }

    /// <summary>
    /// A link's grant on a later pass of a request that link already charged: it draws no permit,
    /// so there is nothing to release.
    /// </summary>
    private sealed class PrepaidLease : RateLimitLease
    {
        public override bool IsAcquired => true;

        public override IEnumerable<string> MetadataNames => [];

        public override bool TryGetMetadata(string metadataName, out object? metadata)
        {
            metadata = null;
            return false;
        }
    }

    /// <summary>A grant from both links: disposing it releases both leases.</summary>
    private sealed class ChainedLease(RateLimitLease caller, RateLimitLease org) : RateLimitLease
    {
        public override bool IsAcquired => true;

        public override IEnumerable<string> MetadataNames =>
            caller.MetadataNames.Concat(org.MetadataNames).Distinct(StringComparer.Ordinal);

        public override bool TryGetMetadata(string metadataName, out object? metadata) =>
            caller.TryGetMetadata(metadataName, out metadata) || org.TryGetMetadata(metadataName, out metadata);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                caller.Dispose();
                org.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
