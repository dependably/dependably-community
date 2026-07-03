using Dependably.Infrastructure;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Test factory for <see cref="IEdgeMode"/>. <see cref="Disabled"/> builds a non-edge instance
/// (the default for tests that construct an <c>UpstreamUrlValidator</c> directly and do not care
/// about the edge allowlist). <see cref="Edge"/> builds an edge instance pointed at a master URL.
/// </summary>
public static class TestEdgeMode
{
    public static IEdgeMode Disabled() =>
        new EdgeMode(new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>()).Build());

    public static IEdgeMode Edge(string masterUrl, string masterToken = "edge-token") =>
        new EdgeMode(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["DEPLOYMENT_MODE"] = "edge",
            ["EDGE_MASTER_URL"] = masterUrl,
            ["EDGE_MASTER_TOKEN"] = masterToken,
        }).Build());

    /// <summary>A non-edge publish guard for controller unit tests that never exercise edge mode.</summary>
    public static Dependably.Infrastructure.Edge.EdgePublishGuard DisabledPublishGuard() =>
        new(Disabled());
}
