using Microsoft.Extensions.Configuration;

namespace Dependably.Security;

/// <summary>
/// Resolves the configurable rate-limit ceilings that are not owned by a single policy body:
/// the GlobalLimiter's two per-minute limits — the management per-principal limit
/// (<c>MANAGEMENT_RATE_LIMIT_PERMITS</c>) applied to authenticated <c>/api/v1/*</c> traffic with
/// no more specific policy, and the default-deny protocol limit
/// (<c>PROTOCOL_DEFAULT_RATE_LIMIT_PERMITS</c>) the GlobalLimiter applies to a controller action
/// that declares no explicit policy (protocol registry routes, plus non-<c>/api/v1</c> management
/// routes such as <c>/saml/*</c>) — and the <c>push</c> policy's permit and queue depths.
///
/// <para>
/// The management and protocol ceilings are env-configurable rather than a boolean disable switch
/// (a production footgun): a bounded internal client — e.g. a DAST scan that authenticates as one
/// system principal and fires thousands of requests — can be handed a very high limit for the
/// duration of the scan. A high (not infinite) limit still bounds a real DoS while leaving a
/// bounded scan unthrottled, so the scanner probes every endpoint instead of hitting a 429 flood
/// that both perturbs the active scan (spurious findings) and leaves real endpoints unprobed.
/// </para>
///
/// <para>
/// The push ceilings live here rather than inline in the policy body so the shipped defaults are
/// unit-assertable. Both test and CI harnesses raise <c>PUSH_RATE_LIMIT_PERMITS</c> far past any
/// reachable burst to stop a shared fixture self-throttling, which means no end-to-end run
/// exercises the value real clients actually meet; pinning it in a unit test is what keeps the
/// default honest.
/// </para>
/// </summary>
internal static class RateLimitCeilings
{
    /// <summary>Default per-principal ceiling (requests/min) for authenticated <c>/api/v1/*</c>.</summary>
    internal const int DefaultManagementPermitLimit = 300;

    /// <summary>Default-deny ceiling (requests/min per IP) for a policy-less controller action.</summary>
    internal const int DefaultProtocolPermitLimit = 300;

    /// <summary>Default sliding-window ceiling (requests/sec per token) for publish routes.</summary>
    internal const int DefaultPushPermitLimit = 20;

    /// <summary>
    /// Default queue depth for the <c>push</c> policy. A publish client bursts structurally — an
    /// OCI push spends three requests per layer (POST to open the upload, PATCH the chunk, PUT to
    /// finalize) and runs several layers concurrently, so a multi-layer image crosses a
    /// per-second permit ceiling in normal operation. Queueing absorbs that burst in microseconds
    /// while the permit ceiling still bounds sustained abuse; a zero queue instead fails the push
    /// outright, because the OCI clients do not honour <c>Retry-After</c> on a write.
    /// </summary>
    internal const int DefaultPushQueueLimit = 100;

    internal static int ResolveManagementPermitLimit(IConfiguration cfg) =>
        int.TryParse(cfg["MANAGEMENT_RATE_LIMIT_PERMITS"], out int m) ? m : DefaultManagementPermitLimit;

    internal static int ResolveProtocolDefaultPermitLimit(IConfiguration cfg) =>
        int.TryParse(cfg["PROTOCOL_DEFAULT_RATE_LIMIT_PERMITS"], out int pd) ? pd : DefaultProtocolPermitLimit;

    internal static int ResolvePushPermitLimit(IConfiguration cfg) =>
        int.TryParse(cfg["PUSH_RATE_LIMIT_PERMITS"], out int pp) ? pp : DefaultPushPermitLimit;

    internal static int ResolvePushQueueLimit(IConfiguration cfg) =>
        int.TryParse(cfg["PUSH_RATE_LIMIT_QUEUE"], out int pq) ? pq : DefaultPushQueueLimit;
}
