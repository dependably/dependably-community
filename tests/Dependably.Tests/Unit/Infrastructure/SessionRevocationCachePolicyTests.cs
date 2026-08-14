using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Pins the cross-replica half of session revocation: on a deployment that can have peers, the
/// per-request "is this session still valid" lookups must not answer from a process-local cache.
///
/// <para>Both stores evict their own entry when the local process performs the logout or the
/// password change, so a single-process test of the store in isolation cannot see the problem.
/// What these tests do instead is mutate the database directly — exactly what a sibling replica's
/// revocation looks like from here — and then ask this process. Under
/// <c>DEPENDABLY_DEPLOYMENT_MODE=ha</c> the answer must already reflect it; under the default
/// single-replica mode the cached answer is correct and deliberately kept, because there is no
/// peer that could have made that change.</para>
///
/// <para>The stores are resolved through the real registration extensions rather than constructed
/// directly: the defect this pins lives in the wiring (which cache a store is handed), so a test
/// that news up the store itself would pass no matter how it is registered.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SessionRevocationCachePolicyTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private ServiceProvider BuildProvider(string? deploymentMode)
    {
        var settings = new Dictionary<string, string?>();
        if (deploymentMode is not null)
        {
            settings["DEPENDABLY_DEPLOYMENT_MODE"] = deploymentMode;
        }

        IConfiguration config = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();

        var services = new ServiceCollection();
        services.AddSingleton(config);
        services.AddSingleton<IMetadataStore>(_db);
        services.AddSingleton(TestTime.Frozen());
        services.AddSingleton<TimeProvider>(sp => sp.GetRequiredService<Microsoft.Extensions.Time.Testing.FakeTimeProvider>());
        services.AddMemoryCache();
        services.AddDependablyRepositories(config);
        services.AddDependablyManagementRepositories();
        return services.BuildServiceProvider();
    }

    // A peer replica's logout, as this process would observe it: a row appearing in
    // jwt_revocations without any local RevokeAsync call to evict the local cache.
    private async Task RevokeOnAPeerAsync(string jti)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO jwt_revocations (jti, expires_at) VALUES (@jti, @exp)",
            new { jti, exp = TestTime.KnownNow.AddHours(1).ToUtcIso() });
    }

    private async Task SeedUserAsync(string userId, string orgId = "org-session-cache")
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@orgId, @slug) ON CONFLICT DO NOTHING",
            new { orgId, slug = orgId });
        await conn.ExecuteAsync(
            """
            INSERT INTO users (id, tenant_id, email, password_hash, role, token_version)
            VALUES (@userId, @orgId, @email, 'x', 'member', 1)
            """,
            new { userId, orgId, email = userId + "@example.test" });
    }

    // A peer replica's password change: token_version moves on with no local Invalidate call.
    private async Task BumpTokenVersionOnAPeerAsync(string userId)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            // xtenant: keyed by the users primary key, which is already tenant-bound.
            "UPDATE users SET token_version = token_version + 1 WHERE id = @userId",
            new { userId });
    }

    [Fact]
    public async Task HaMode_RevocationOnAPeer_IsHonouredOnTheNextRequest()
    {
        await using var sp = BuildProvider("ha");
        var revocations = sp.GetRequiredService<JwtRevocationRepository>();

        // Warm whatever this process would cache.
        Assert.False(await revocations.IsRevokedAsync("jti-ha"));

        await RevokeOnAPeerAsync("jti-ha");

        Assert.True(await revocations.IsRevokedAsync("jti-ha"));
    }

    [Fact]
    public async Task SingleReplicaMode_KeepsTheNegativeCache()
    {
        // The counterpart assertion: dropping the cache everywhere would put two DB reads on
        // every authenticated request of every deployment, and a lone process has no peer whose
        // revocation it could be missing.
        await using var sp = BuildProvider(deploymentMode: null);
        var revocations = sp.GetRequiredService<JwtRevocationRepository>();

        Assert.False(await revocations.IsRevokedAsync("jti-standalone"));
        await RevokeOnAPeerAsync("jti-standalone");

        Assert.False(await revocations.IsRevokedAsync("jti-standalone"));
    }

    [Fact]
    public async Task HaMode_TokenVersionBumpOnAPeer_IsVisibleOnTheNextRequest()
    {
        const string userId = "user-ha-tver";
        await SeedUserAsync(userId);

        await using var sp = BuildProvider("ha");
        var versions = sp.GetRequiredService<UserTokenVersionStore>();

        Assert.Equal(1, await versions.GetCurrentVersionAsync(userId));

        await BumpTokenVersionOnAPeerAsync(userId);

        Assert.Equal(2, await versions.GetCurrentVersionAsync(userId));
    }

    [Fact]
    public void HasPeerReplicas_ReadsTheDeploymentMode()
    {
        static IConfiguration Cfg(string? mode) => new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["DEPENDABLY_DEPLOYMENT_MODE"] = mode })
            .Build();

        Assert.True(SessionRevocationCachePolicy.HasPeerReplicas(Cfg("ha")));
        Assert.True(SessionRevocationCachePolicy.HasPeerReplicas(Cfg(" HA ")));
        Assert.False(SessionRevocationCachePolicy.HasPeerReplicas(Cfg("standalone")));
        Assert.False(SessionRevocationCachePolicy.HasPeerReplicas(Cfg(null)));
    }
}
