using Dependably.Infrastructure.Observability;

namespace Dependably.Security;

/// <summary>
/// Extension methods for <see cref="IUpstreamUrlValidator"/> that bridge the
/// reason-typed <see cref="IUpstreamUrlValidator.CheckAsync"/> result to the
/// boolean <c>IsAllowedAsync</c> surface used by pre-fetch call sites and to the
/// reason-tagged <c>dependably.security.upstream_url_blocks</c> counter.
/// </summary>
public static class UpstreamUrlValidatorExtensions
{
    /// <summary>
    /// Calls <see cref="IUpstreamUrlValidator.CheckAsync"/>, emits the
    /// <c>dependably.security.upstream_url_blocks</c> counter with the appropriate
    /// <c>reason</c> attribute when blocked, and returns <c>true</c> only when the
    /// URL is allowed.
    /// </summary>
    public static async Task<bool> IsAllowedAsync(
        this IUpstreamUrlValidator validator,
        string url,
        string? orgId,
        CancellationToken ct = default)
    {
        var block = await validator.CheckAsync(url, orgId, ct).ConfigureAwait(false);
        switch (block)
        {
            case UpstreamUrlBlock.BlockedRange:
                DependablyMeter.UpstreamUrlBlocks.Add(1,
                    new KeyValuePair<string, object?>("reason", "blocked_range"));
                return false;

            case UpstreamUrlBlock.DnsFailure:
                DependablyMeter.UpstreamUrlBlocks.Add(1,
                    new KeyValuePair<string, object?>("reason", "dns_failure"));
                return false;

            default:
                return true;
        }
    }
}
