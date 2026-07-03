using Dependably.Infrastructure;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit;

/// <summary>
/// The edge background-job allowlist: in <c>DEPLOYMENT_MODE=edge</c>, <see cref="AirGapMode"/>
/// force-disables every <c>BackgroundJobs.Known</c> job except the cache-only allowlist
/// (cache-eviction / oci-staging-janitor / blob-size-poller / healthcheck-pinger). An explicit
/// <c>DISABLE_BACKGROUND_JOBS</c> entry still adds on top. Non-edge behavior is unchanged: no job
/// is disabled unless named in the denylist.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EdgeBackgroundJobAllowlistTests
{
    // The exact 4 jobs an edge node keeps.
    private static readonly string[] EdgeAllowed =
        ["cache-eviction", "oci-staging-janitor", "blob-size-poller", "healthcheck-pinger"];

    // Every other job in the known registry — all must be disabled in edge mode.
    private static readonly string[] EdgeDisabled =
    [
        "vuln-scan", "vuln-rescan", "threat-feed", "deprecation-refresh", "retention",
        "orphan-reconciler", "tenant-hard-delete", "tenant-count-poller", "stats-refresh",
        "saml-cert-expiry",
    ];

    private static AirGapMode Build(string? deploymentMode = null, string? disableJobs = null, string? airGapped = null) =>
        new(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["DEPLOYMENT_MODE"] = deploymentMode,
            ["DISABLE_BACKGROUND_JOBS"] = disableJobs,
            ["AIR_GAPPED"] = airGapped,
        }).Build());

    [Fact]
    public void Edge_RunsOnlyTheAllowlistedJobs()
    {
        var mode = Build(deploymentMode: "edge");

        foreach (string job in EdgeAllowed)
        {
            Assert.False(mode.IsJobDisabled(job), $"edge must run allowlisted job '{job}'");
        }

        foreach (string job in EdgeDisabled)
        {
            Assert.True(mode.IsJobDisabled(job), $"edge must force-disable non-allowlisted job '{job}'");
        }
    }

    [Fact]
    public void Edge_ExplicitDenylistDisablesAnAllowlistedJobToo()
    {
        // The edge allowlist is a floor, not a ceiling: an operator can still turn OFF an
        // allowlisted job by naming it in DISABLE_BACKGROUND_JOBS. The other three stay on.
        var mode = Build(deploymentMode: "edge", disableJobs: "cache-eviction");

        Assert.True(mode.IsJobDisabled("cache-eviction"));
        Assert.False(mode.IsJobDisabled("oci-staging-janitor"));
        Assert.False(mode.IsJobDisabled("blob-size-poller"));
        Assert.False(mode.IsJobDisabled("healthcheck-pinger"));
    }

    [Fact]
    public void NonEdge_NothingDisabledUnlessNamedInDenylist()
    {
        var mode = Build(deploymentMode: "single");

        // Both allowlisted and non-allowlisted jobs run in single mode.
        foreach (string job in EdgeAllowed.Concat(EdgeDisabled))
        {
            Assert.False(mode.IsJobDisabled(job), $"single mode must not disable '{job}'");
        }
    }

    [Fact]
    public void NonEdge_DenylistStillDisablesNamedJobs()
    {
        var mode = Build(deploymentMode: "single", disableJobs: "stats-refresh, vuln-scan");

        Assert.True(mode.IsJobDisabled("stats-refresh"));
        Assert.True(mode.IsJobDisabled("vuln-scan"));
        Assert.False(mode.IsJobDisabled("retention"));
    }

    [Fact]
    public void DefaultMode_IsNotEdge_NothingForceDisabled()
    {
        // DEPLOYMENT_MODE unset defaults to 'single' — the edge allowlist must not engage.
        var mode = Build(deploymentMode: null);
        Assert.False(mode.IsJobDisabled("retention"));
        Assert.False(mode.IsJobDisabled("tenant-count-poller"));
    }

    [Fact]
    public void Edge_AllowedSet_MatchesTheAgreedFourJobs()
    {
        // Pin the allowlist contents so a future edit that adds/removes a job is a red test,
        // forcing a deliberate decision rather than a silent scope change.
        var mode = Build(deploymentMode: "edge");
        string[] known = new[]
        {
            "vuln-scan", "vuln-rescan", "threat-feed", "deprecation-refresh", "healthcheck-pinger",
            "cache-eviction", "retention", "orphan-reconciler", "oci-staging-janitor",
            "tenant-hard-delete", "blob-size-poller", "tenant-count-poller", "stats-refresh",
            "saml-cert-expiry",
        };
        string[] running = known.Where(j => !mode.IsJobDisabled(j)).OrderBy(j => j, StringComparer.Ordinal).ToArray();
        Assert.Equal(
            EdgeAllowed.OrderBy(j => j, StringComparer.Ordinal).ToArray(),
            running);
    }
}
