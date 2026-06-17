using Dapper;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class PublishGateTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static IConfiguration Cfg(string? enforcement, string? airGap = null) =>
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["CLAIM_ENFORCEMENT"] = enforcement,
            ["AIR_GAPPED"] = airGap
        }).Build();

    private ClaimResolver Resolver(IConfiguration cfg) =>
        new(new ClaimRepository(_db), new AirGapMode(cfg));

    private async Task SeedClaim(string ecosystem, string name, string state)
    {
        await new ClaimRepository(_db).ApplyTransitionAsync(new ClaimTransition
        {
            ClaimId = Guid.NewGuid().ToString("D"),
            HistoryId = Guid.NewGuid().ToString("D"),
            OrgId = "o1",
            Ecosystem = ecosystem,
            Name = name,
            PriorState = null,
            NewState = state,
            Reason = "test",
            OccurredAt = TestTime.KnownNow
        });
    }

    [Fact]
    public async Task EnforcementOff_AlwaysPasses()
    {
        var cfg = Cfg(enforcement: "off");
        var gate = new PublishGate(cfg, Resolver(cfg));
        Assert.False(gate.IsEnforced);
        Assert.Null(await gate.CheckAsync("o1", "npm", "anything"));
    }

    [Fact]
    public async Task EnforcementOn_UnclaimedConnected_Rejects409()
    {
        var cfg = Cfg(enforcement: "on");
        var gate = new PublishGate(cfg, Resolver(cfg));
        Assert.True(gate.IsEnforced);

        var result = await gate.CheckAsync("o1", "npm", "ghost");
        Assert.NotNull(result);
        var oar = Assert.IsType<ObjectResult>(result);
        Assert.Equal(409, oar.StatusCode);
        var problem = Assert.IsType<ProblemDetails>(oar.Value);
        Assert.Equal(409, problem.Status);
        Assert.Contains("ghost", problem.Detail!);
    }

    [Fact]
    public async Task EnforcementOn_LocalOnlyClaim_Passes()
    {
        await SeedClaim("npm", "internal-lib", ClaimStateMachine.LocalOnly);
        var cfg = Cfg(enforcement: "on");
        var gate = new PublishGate(cfg, Resolver(cfg));
        Assert.Null(await gate.CheckAsync("o1", "npm", "internal-lib"));
    }

    [Fact]
    public async Task EnforcementOn_MixedClaim_Passes()
    {
        await SeedClaim("npm", "internal-lib", ClaimStateMachine.Mixed);
        var cfg = Cfg(enforcement: "on");
        var gate = new PublishGate(cfg, Resolver(cfg));
        Assert.Null(await gate.CheckAsync("o1", "npm", "internal-lib"));
    }

    [Fact]
    public async Task EnforcementOn_AirGapImplicitLocalOnly_Passes()
    {
        // Air-gap deployments default every name to local_only, so the gate is effectively
        // a no-op even when enforcement is on.
        var cfg = Cfg(enforcement: "on", airGap: "true");
        var gate = new PublishGate(cfg, Resolver(cfg));
        Assert.Null(await gate.CheckAsync("o1", "npm", "any-name"));
    }

    [Fact]
    public async Task EnforcementOn_StructuredProblemIncludesEcosystemAndName()
    {
        var cfg = Cfg(enforcement: "on");
        var gate = new PublishGate(cfg, Resolver(cfg));
        var result = (ObjectResult)(await gate.CheckAsync("o1", "pypi", "requests"))!;
        var problem = (ProblemDetails)result.Value!;
        Assert.Equal("pypi", problem.Extensions["ecosystem"]);
        Assert.Equal("requests", problem.Extensions["name"]);
    }
}
