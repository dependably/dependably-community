extern alias edge;
using Microsoft.Extensions.Configuration;
using EdgeProgram = edge::Program;

namespace Dependably.Tests.Unit;

/// <summary>
/// The Edge composition root's constitutional startup guard. Edge identity is not derived from
/// <c>DEPLOYMENT_MODE</c> — the edge image IS an edge — so the guard treats any tenancy value
/// (single/multi/header/bound) as a hard misconfiguration and fails fast with a clear message,
/// and it requires the master URL/token exactly as the runtime edge path does. Asserted directly
/// against the validator so the fail-fast behaviour is pinned without booting a host.
/// </summary>
public sealed class EdgeRootStartupGuardTests
{
    private static IConfiguration Config(params (string Key, string? Value)[] pairs) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(pairs.ToDictionary(p => p.Key, p => p.Value))
            .Build();

    [Theory]
    [InlineData("single")]
    [InlineData("multi")]
    [InlineData("header")]
    [InlineData("bound")]
    public void TenancyDeploymentMode_FailsFast(string mode)
    {
        var config = Config(
            ("DEPLOYMENT_MODE", mode),
            ("EDGE_MASTER_URL", "https://master.example.com"),
            ("EDGE_MASTER_TOKEN", "tok"));

        var ex = Assert.Throws<InvalidOperationException>(
            () => EdgeProgram.ValidateEdgeConfigurationForTest(config));
        Assert.Contains(mode, ex.Message);
        Assert.Contains("management", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void UnsetDeploymentMode_TreatedAsEdge_NoTenancyThrow()
    {
        // Absent DEPLOYMENT_MODE is the edge default; with master config present the guard passes.
        var config = Config(
            ("EDGE_MASTER_URL", "https://master.example.com"),
            ("EDGE_MASTER_TOKEN", "tok"));

        EdgeProgram.ValidateEdgeConfigurationForTest(config);
    }

    [Fact]
    public void ExplicitEdgeMode_Passes_WhenMasterConfigured()
    {
        var config = Config(
            ("DEPLOYMENT_MODE", "edge"),
            ("EDGE_MASTER_URL", "https://master.example.com"),
            ("EDGE_MASTER_TOKEN", "tok"));

        EdgeProgram.ValidateEdgeConfigurationForTest(config);
    }

    [Theory]
    [InlineData(null, "tok", "EDGE_MASTER_URL")]
    [InlineData("https://master.example.com", null, "EDGE_MASTER_TOKEN")]
    public void MissingMasterConfig_FailsFast(string? url, string? token, string expectedInMessage)
    {
        var config = Config(
            ("EDGE_MASTER_URL", url),
            ("EDGE_MASTER_TOKEN", token));

        var ex = Assert.Throws<InvalidOperationException>(
            () => EdgeProgram.ValidateEdgeConfigurationForTest(config));
        Assert.Contains(expectedInMessage, ex.Message);
    }

    [Fact]
    public void NonAbsoluteMasterUrl_FailsFast()
    {
        var config = Config(
            ("EDGE_MASTER_URL", "master.example.com"),
            ("EDGE_MASTER_TOKEN", "tok"));

        Assert.Throws<InvalidOperationException>(
            () => EdgeProgram.ValidateEdgeConfigurationForTest(config));
    }

    /// <summary>
    /// Multi-replica edge is not a supported topology (#465): this composition root registers
    /// <c>InProcessDistributedLock</c> unconditionally and runs the full background-service set, so
    /// N edge replicas sharing one Postgres database would let every replica win every leader-lock
    /// acquisition and run every scheduled job concurrently — including
    /// <c>OrphanBlobReconcilerService</c> deleting blobs from N replicas at once. DB_PROVIDER=postgres
    /// must fail fast rather than silently permit that topology.
    /// </summary>
    [Fact]
    public void PostgresDbProvider_FailsFast()
    {
        var config = Config(
            ("DB_PROVIDER", "postgres"),
            ("EDGE_MASTER_URL", "https://master.example.com"),
            ("EDGE_MASTER_TOKEN", "tok"));

        var ex = Assert.Throws<InvalidOperationException>(
            () => EdgeProgram.ValidateEdgeConfigurationForTest(config));
        Assert.Contains("DB_PROVIDER", ex.Message);
        Assert.Contains("postgres", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("sqlite")]
    [InlineData(null)]
    public void NonPostgresDbProvider_Passes(string? provider)
    {
        var config = Config(
            ("DB_PROVIDER", provider),
            ("EDGE_MASTER_URL", "https://master.example.com"),
            ("EDGE_MASTER_TOKEN", "tok"));

        EdgeProgram.ValidateEdgeConfigurationForTest(config);
    }

    /// <summary>
    /// The other half of the same guard (#465): DEPENDABLY_DEPLOYMENT_MODE=ha names Redis-coordinated
    /// multi-replica orchestration the edge root cannot honour — it has no Redis wiring and no
    /// leader-aware background services — so it must fail fast rather than silently run every
    /// scheduled job on every replica.
    /// </summary>
    [Fact]
    public void HaDeploymentMode_FailsFast()
    {
        var config = Config(
            ("DEPENDABLY_DEPLOYMENT_MODE", "ha"),
            ("EDGE_MASTER_URL", "https://master.example.com"),
            ("EDGE_MASTER_TOKEN", "tok"));

        var ex = Assert.Throws<InvalidOperationException>(
            () => EdgeProgram.ValidateEdgeConfigurationForTest(config));
        Assert.Contains("DEPENDABLY_DEPLOYMENT_MODE", ex.Message);
        Assert.Contains("ha", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("standalone")]
    [InlineData(null)]
    public void NonHaDeploymentMode_Passes(string? mode)
    {
        var config = Config(
            ("DEPENDABLY_DEPLOYMENT_MODE", mode),
            ("EDGE_MASTER_URL", "https://master.example.com"),
            ("EDGE_MASTER_TOKEN", "tok"));

        EdgeProgram.ValidateEdgeConfigurationForTest(config);
    }
}
