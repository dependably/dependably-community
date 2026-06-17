using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;

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
            OccurredAt = TestTime.KnownNow
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

    // ── hosted-name shadowing guard (implicit local_only) ─────────────────────

    [Fact]
    public async Task NoClaim_HostedVersionExists_ReturnsLocalOnlyImplicit()
    {
        // The dependency-confusion guard: a name the org has uploaded must not resolve as
        // unclaimed (which would let upstream shadow it).
        string pkgId = await Tests.Infrastructure.Seeding.PackageSeeder.InsertAsync(_db, "o1", "npm", "internal-lib");
        await Tests.Infrastructure.Seeding.PackageSeeder.InsertVersionAsync(
            _db, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/internal-lib@1.0.0", origin: "uploaded");

        var resolver = new ClaimResolver(new ClaimRepository(_db), AirGap(false));
        var eff = await resolver.ResolveAsync("o1", "npm", "internal-lib");

        Assert.Equal(ClaimStateMachine.LocalOnly, eff.State);
        Assert.True(eff.IsImplicit);
        Assert.False(await resolver.IsProxyFetchAllowedAsync("o1", "npm", "internal-lib"));
    }

    [Fact]
    public async Task NoClaim_OnlyProxyVersionsExist_StaysUnclaimed()
    {
        // Proxy-cached content is upstream's, not the org's — it must not flip the implicit
        // state, or every cached name would silently stop proxying.
        string pkgId = await Tests.Infrastructure.Seeding.PackageSeeder.InsertAsync(_db, "o1", "npm", "public-lib");
        await Tests.Infrastructure.Seeding.PackageSeeder.InsertVersionAsync(
            _db, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/public-lib@1.0.0", origin: "proxy");

        var resolver = new ClaimResolver(new ClaimRepository(_db), AirGap(false));
        var eff = await resolver.ResolveAsync("o1", "npm", "public-lib");

        Assert.Equal(ClaimStateMachine.Unclaimed, eff.State);
        Assert.True(eff.IsImplicit);
    }

    [Fact]
    public async Task ExplicitMixedClaim_OverridesHostedImplicitLocalOnly()
    {
        // The operator opt-in: an explicit mixed claim keeps upstream merging on a hosted name.
        string pkgId = await Tests.Infrastructure.Seeding.PackageSeeder.InsertAsync(_db, "o1", "npm", "optin-lib");
        await Tests.Infrastructure.Seeding.PackageSeeder.InsertVersionAsync(
            _db, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/optin-lib@1.0.0", origin: "uploaded");
        await SeedClaim("npm", "optin-lib", ClaimStateMachine.Mixed);

        var resolver = new ClaimResolver(new ClaimRepository(_db), AirGap(false));
        var eff = await resolver.ResolveAsync("o1", "npm", "optin-lib");

        Assert.Equal(ClaimStateMachine.Mixed, eff.State);
        Assert.False(eff.IsImplicit);
        Assert.True(await resolver.IsProxyFetchAllowedAsync("o1", "npm", "optin-lib"));
    }

    [Fact]
    public async Task HostedImplicitLocalOnly_IsOrgScoped()
    {
        // Org A's hosted name must not flip org B's resolution for the same name.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o2', 'beta')");
        }

        string pkgId = await Tests.Infrastructure.Seeding.PackageSeeder.InsertAsync(_db, "o1", "npm", "shared-name");
        await Tests.Infrastructure.Seeding.PackageSeeder.InsertVersionAsync(
            _db, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/shared-name@1.0.0", origin: "uploaded");

        var resolver = new ClaimResolver(new ClaimRepository(_db), AirGap(false));
        Assert.Equal(ClaimStateMachine.LocalOnly, (await resolver.ResolveAsync("o1", "npm", "shared-name")).State);
        Assert.Equal(ClaimStateMachine.Unclaimed, (await resolver.ResolveAsync("o2", "npm", "shared-name")).State);
    }
}
