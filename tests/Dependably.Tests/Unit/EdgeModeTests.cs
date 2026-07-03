using Dependably.Infrastructure;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit;

/// <summary>
/// Parsing and validation for the headless edge deployment mode: <see cref="EdgeMode"/> config
/// binding, the per-ecosystem single-upstream prefix table, and the fail-fast startup guard.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EdgeModeTests
{
    private static IConfiguration Config(Dictionary<string, string?> values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    [Fact]
    public void EdgeMode_NonEdgeDeployment_IsNotEdgeAndFieldsEmpty()
    {
        var mode = new EdgeMode(Config(new()
        {
            ["DEPLOYMENT_MODE"] = "single",
            ["EDGE_MASTER_URL"] = "https://master.example.com",
            ["EDGE_MASTER_TOKEN"] = "tok",
        }));

        Assert.False(mode.IsEdge);
        // Outside edge mode the edge fields are inert even if the env vars are set.
        Assert.Equal("", mode.MasterUrl);
        Assert.Equal("", mode.MasterHost);
        Assert.Equal("", mode.MasterToken);
    }

    [Fact]
    public void EdgeMode_Edge_ParsesUrlHostAndTokenAndTrimsTrailingSlash()
    {
        var mode = new EdgeMode(Config(new()
        {
            ["DEPLOYMENT_MODE"] = "edge",
            ["EDGE_MASTER_URL"] = "https://master.internal.lan:8443/",
            ["EDGE_MASTER_TOKEN"] = "  edge-tok  ",
        }));

        Assert.True(mode.IsEdge);
        Assert.Equal("https://master.internal.lan:8443", mode.MasterUrl);
        Assert.Equal("master.internal.lan", mode.MasterHost);
        Assert.Equal("edge-tok", mode.MasterToken);
    }

    [Fact]
    public void EdgeMode_Edge_MissingUrl_LeavesHostEmpty()
    {
        var mode = new EdgeMode(Config(new() { ["DEPLOYMENT_MODE"] = "edge" }));

        Assert.True(mode.IsEdge);
        Assert.Equal("", mode.MasterUrl);
        Assert.Equal("", mode.MasterHost);
    }

    [Fact]
    public void ResolveRows_SeedsCanonicalPrefixPerEcosystem()
    {
        var rows = EdgeUpstreamSeeder.ResolveRows("https://master.example.com");
        var map = rows.ToDictionary(r => r.Ecosystem, r => r.Url);

        Assert.Equal("https://master.example.com", map["pypi"]);
        Assert.Equal("https://master.example.com/npm", map["npm"]);
        Assert.Equal("https://master.example.com/nuget", map["nuget"]);
        Assert.Equal("https://master.example.com/maven", map["maven"]);
        Assert.Equal("https://master.example.com/rpm", map["rpm"]);
        Assert.Equal("https://master.example.com/go", map["golang"]);
        Assert.Equal("https://master.example.com/cargo", map["cargo"]);
        // OCI is a host-only row (Distribution Spec mandates /v2/ at the host root).
        Assert.Equal("master.example.com", EdgeUpstreamSeeder.ResolveOciHost("https://master.example.com"));
    }

    [Fact]
    public void ResolveRows_TrimsTrailingSlashOnBase()
    {
        var rows = EdgeUpstreamSeeder.ResolveRows("https://m.example/");
        Assert.Equal("https://m.example/npm", rows.Single(r => r.Ecosystem == "npm").Url);
    }

    // ── Startup guard ────────────────────────────────────────────────────────

    [Fact]
    public void Validate_NonEdge_DoesNotThrow()
    {
        Program.ValidateEdgeConfigurationForTest(Config(new() { ["DEPLOYMENT_MODE"] = "single" }));
    }

    [Fact]
    public void Validate_Edge_MissingMasterUrl_ThrowsNamingTheVar()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            Program.ValidateEdgeConfigurationForTest(Config(new()
            {
                ["DEPLOYMENT_MODE"] = "edge",
                ["EDGE_MASTER_TOKEN"] = "tok",
            })));

        Assert.Contains("EDGE_MASTER_URL", ex.Message);
    }

    [Fact]
    public void Validate_Edge_MissingMasterToken_ThrowsNamingTheVar()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            Program.ValidateEdgeConfigurationForTest(Config(new()
            {
                ["DEPLOYMENT_MODE"] = "edge",
                ["EDGE_MASTER_URL"] = "https://master.example.com",
            })));

        Assert.Contains("EDGE_MASTER_TOKEN", ex.Message);
    }

    [Fact]
    public void Validate_Edge_BothMissing_ThrowsNamingBoth()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            Program.ValidateEdgeConfigurationForTest(Config(new() { ["DEPLOYMENT_MODE"] = "edge" })));

        Assert.Contains("EDGE_MASTER_URL", ex.Message);
        Assert.Contains("EDGE_MASTER_TOKEN", ex.Message);
    }

    [Fact]
    public void Validate_Edge_NonAbsoluteUrl_Throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            Program.ValidateEdgeConfigurationForTest(Config(new()
            {
                ["DEPLOYMENT_MODE"] = "edge",
                ["EDGE_MASTER_URL"] = "master.example.com",
                ["EDGE_MASTER_TOKEN"] = "tok",
            })));

        Assert.Contains("EDGE_MASTER_URL", ex.Message);
    }

    [Fact]
    public void Validate_Edge_ValidConfig_DoesNotThrow()
    {
        Program.ValidateEdgeConfigurationForTest(Config(new()
        {
            ["DEPLOYMENT_MODE"] = "edge",
            ["EDGE_MASTER_URL"] = "https://master.example.com",
            ["EDGE_MASTER_TOKEN"] = "tok",
        }));
    }
}
