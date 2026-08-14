using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Infrastructure;

/// <summary>
/// Decides whether the per-request session-validity lookups (<see cref="UserTokenVersionStore"/>,
/// the system-admin token-version store, and the JWT revocation store) may answer from a
/// process-local cache.
///
/// <para><b>The rule: they may, unless this deployment has peers.</b> Each of those stores fronts
/// its DB read with a 60-second in-process cache and evicts the affected key on the node that
/// performs the logout / password change / MFA disable. On a single-replica deployment that
/// eviction is the whole invalidation and the cache costs nothing in correctness. On a
/// multi-replica one it is not: a sibling replica that cached "not revoked" a moment earlier keeps
/// honouring the killed session until its own TTL rolls, so a stolen cookie survives the logout
/// that was supposed to end it — for up to a minute, per replica.</para>
///
/// <para><b>Why the cache is dropped rather than invalidated across replicas.</b> The
/// cross-replica channel this codebase already has (<c>IMetadataInvalidationBus</c>) is
/// best-effort by contract: it never throws, is not awaited, and degrades to TTL expiry when the
/// broker is unreachable. That is the right posture for rendered-metadata freshness and the wrong
/// one for session revocation, which is a security decision — a dropped message would leave a
/// revoked session live while looking like it had been propagated, and the TTL would still be the
/// real bound. Reading through to the database instead makes the bound exact: the next request on
/// any replica sees the revocation. The cost is two indexed primary-key lookups per
/// management-plane request that presents a session JWT — HA mode already mandates Postgres, and
/// the registry protocol plane authenticates with API tokens and never reaches these stores, so
/// this is SPA/admin traffic, not the artifact hot path.</para>
/// </summary>
public static class SessionRevocationCachePolicy
{
    /// <summary>Value of <c>DEPENDABLY_DEPLOYMENT_MODE</c> that declares a multi-replica deployment.</summary>
    public const string HighAvailabilityMode = "ha";

    /// <summary>
    /// True when this process may have sibling replicas serving the same database, i.e.
    /// <c>DEPENDABLY_DEPLOYMENT_MODE=ha</c>. Any other value (including unset) is a single-replica
    /// deployment: a file-backed SQLite install cannot have peers at all
    /// (<c>InstanceLock</c> refuses a second writer), and an operator running several replicas
    /// against Postgres declares that mode to get the Redis-backed lockout store and distributed
    /// lock, so the same flag is the honest discriminator here.
    /// </summary>
    public static bool HasPeerReplicas(IConfiguration config) =>
        string.Equals(
            config["DEPENDABLY_DEPLOYMENT_MODE"]?.Trim(),
            HighAvailabilityMode,
            StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The memory cache the session-validity stores should use: the registered one on a
    /// single-replica deployment, or <see langword="null"/> (read through to the database on every
    /// request) when this deployment has peers.
    /// </summary>
    public static IMemoryCache? SessionCacheOrNull(IServiceProvider services) =>
        HasPeerReplicas(services.GetRequiredService<IConfiguration>())
            ? null
            : services.GetService<IMemoryCache>();
}
