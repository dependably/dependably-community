using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class ClaimResolverTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static AirGapMode AirGap(bool enabled) =>
        new(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["AIR_GAPPED"] = enabled ? "true" : null })
            .Build());

    private async Task SeedClaim(string ecosystem, string name, string state)
    {
        var repo = new ClaimRepository(_db);
        await repo.ApplyTransitionAsync(new ClaimTransition
        {
            ClaimId = Guid.NewGuid().ToString("D"),
            HistoryId = Guid.NewGuid().ToString("D"),
            OrgId = "o1",
            Ecosystem = ecosystem,
            Name = name,
            PriorState = null,
            NewState = state,
            Reason = "test",
            OccurredAt = DateTimeOffset.UtcNow
        });
    }

    [Fact]
    public async Task NoClaim_ConnectedMode_ReturnsUnclaimedImplicit()
    {
        var resolver = new ClaimResolver(new ClaimRepository(_db), AirGap(false));
        var eff = await resolver.ResolveAsync("o1", "npm", "ghost");
        Assert.Equal(ClaimStateMachine.Unclaimed, eff.State);
        Assert.True(eff.IsImplicit);
        Assert.Null(eff.Row);
    }

    [Fact]
    public async Task NoClaim_AirGapMode_ReturnsLocalOnlyImplicit()
    {
        var resolver = new ClaimResolver(new ClaimRepository(_db), AirGap(true));
        var eff = await resolver.ResolveAsync("o1", "npm", "ghost");
        Assert.Equal(ClaimStateMachine.LocalOnly, eff.State);
        Assert.True(eff.IsImplicit);
    }

    [Fact]
    public async Task ExplicitClaim_OverridesAirGapImplicit()
    {
        await SeedClaim("npm", "lodash", ClaimStateMachine.Mixed);
        var resolver = new ClaimResolver(new ClaimRepository(_db), AirGap(true));
        var eff = await resolver.ResolveAsync("o1", "npm", "lodash");
        Assert.Equal(ClaimStateMachine.Mixed, eff.State);
        Assert.False(eff.IsImplicit);
        Assert.NotNull(eff.Row);
    }

    [Fact]
    public async Task CanPublish_UnclaimedConnected_False()
    {
        var resolver = new ClaimResolver(new ClaimRepository(_db), AirGap(false));
        Assert.False(await resolver.CanPublishAsync("o1", "npm", "ghost"));
    }

    [Fact]
    public async Task CanPublish_LocalOnly_True()
    {
        await SeedClaim("npm", "x", ClaimStateMachine.LocalOnly);
        var resolver = new ClaimResolver(new ClaimRepository(_db), AirGap(false));
        Assert.True(await resolver.CanPublishAsync("o1", "npm", "x"));
    }

    [Fact]
    public async Task CanPublish_AirGapImplicit_True()
    {
        var resolver = new ClaimResolver(new ClaimRepository(_db), AirGap(true));
        Assert.True(await resolver.CanPublishAsync("o1", "npm", "anything"));
    }
}
