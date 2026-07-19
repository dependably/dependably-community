using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Tokens;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The validation-side half of jwt_secret rotation. JwtBearer captures TokenValidationParameters
/// once, so a key copied in at startup can never see a rotation; these tests pin that the provider
/// re-reads the row, that it trusts the current secret and nothing else (no grace window), and
/// that the cross-replica convergence window is exactly the configured refresh interval — no wider.
/// </summary>
[Trait("Category", "Unit")]
public sealed class JwtSigningKeyProviderTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private JwtSigningKeyProvider NewProvider(FakeTimeProvider clock, string? refreshSeconds = null)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            { ["Auth:JwtSigningKeyRefreshSeconds"] = refreshSeconds })
            .Build();
        return new JwtSigningKeyProvider(
            new OrgRepository(_db), clock, config, NullLogger<JwtSigningKeyProvider>.Instance);
    }

    private async Task SetSecretAsync(string value)
    {
        await using var conn = await _db.OpenAsync();
        // xtenant: jwt_secret is an instance-wide secret, not scoped to any tenant.
        await conn.ExecuteAsync(
            """
            INSERT INTO instance_settings (key, value) VALUES ('jwt_secret', @value)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            new { value });
    }

    private static byte[] SingleKeyBytes(JwtSigningKeyProvider provider) =>
        Assert.IsType<SymmetricSecurityKey>(Assert.Single(provider.CurrentKeys)).Key;

    [Fact]
    public async Task CurrentKeys_BeforeAnyLoad_IsEmptySoValidationFailsClosed()
    {
        var provider = NewProvider(TestTime.Frozen());

        // No placeholder key: an unloaded provider hands the bearer scheme nothing to verify
        // against, so every token is rejected rather than checked against guessable bytes.
        Assert.Empty(provider.CurrentKeys);
    }

    [Fact]
    public async Task TryReloadAsync_NoJwtSecretRow_ReturnsFalseAndLoadsNothing()
    {
        var provider = NewProvider(TestTime.Frozen());

        Assert.False(await provider.TryReloadAsync());
        Assert.Empty(provider.CurrentKeys);
    }

    [Fact]
    public async Task TryReloadAsync_LoadsTheStoredSecret()
    {
        await SetSecretAsync("secret-one");
        var provider = NewProvider(TestTime.Frozen());

        Assert.True(await provider.TryReloadAsync());
        Assert.Equal(Encoding.UTF8.GetBytes("secret-one"), SingleKeyBytes(provider));
    }

    [Fact]
    public async Task TryReloadAsync_AfterRotation_ReplacesKeyAndDropsTheOldOne()
    {
        await SetSecretAsync("secret-one");
        var provider = NewProvider(TestTime.Frozen());
        await provider.TryReloadAsync();

        await SetSecretAsync("secret-two");
        Assert.True(await provider.TryReloadAsync());

        // The whole rotation contract: the new secret is trusted, and the superseded one is not
        // retained alongside it. Single() is the no-grace-window assertion.
        Assert.Equal(Encoding.UTF8.GetBytes("secret-two"), SingleKeyBytes(provider));
    }

    [Fact]
    public async Task RefreshIfStaleAsync_WithinRefreshInterval_KeepsServingTheCachedKey()
    {
        await SetSecretAsync("secret-one");
        var clock = TestTime.Frozen();
        var provider = NewProvider(clock, refreshSeconds: "30");
        await provider.TryReloadAsync();

        await SetSecretAsync("secret-two");
        clock.Advance(TimeSpan.FromSeconds(29));
        await provider.RefreshIfStaleAsync();

        // This is the bounded window, asserted rather than assumed: a replica that did not
        // perform the rotation keeps honouring the old secret until its interval elapses.
        Assert.Equal(Encoding.UTF8.GetBytes("secret-one"), SingleKeyBytes(provider));
    }

    [Fact]
    public async Task RefreshIfStaleAsync_AfterRefreshInterval_PicksUpTheRotatedSecret()
    {
        await SetSecretAsync("secret-one");
        var clock = TestTime.Frozen();
        var provider = NewProvider(clock, refreshSeconds: "30");
        await provider.TryReloadAsync();

        await SetSecretAsync("secret-two");
        clock.Advance(TimeSpan.FromSeconds(30));
        await provider.RefreshIfStaleAsync();

        Assert.Equal(Encoding.UTF8.GetBytes("secret-two"), SingleKeyBytes(provider));
    }

    [Fact]
    public async Task RefreshIfStaleAsync_ZeroInterval_ReReadsOnEveryCall()
    {
        await SetSecretAsync("secret-one");
        var clock = TestTime.Frozen();
        var provider = NewProvider(clock, refreshSeconds: "0");
        await provider.TryReloadAsync();

        await SetSecretAsync("secret-two");
        // No clock movement: interval 0 means the cache is always stale, closing the
        // cross-replica window entirely at the cost of a read per validation.
        await provider.RefreshIfStaleAsync();

        Assert.Equal(Encoding.UTF8.GetBytes("secret-two"), SingleKeyBytes(provider));
    }

    [Fact]
    public async Task RefreshInterval_DefaultsToOneSecond_WhenUnconfiguredOrInvalid()
    {
        Assert.Equal(TimeSpan.FromSeconds(1), NewProvider(TestTime.Frozen()).RefreshInterval);
        Assert.Equal(TimeSpan.FromSeconds(1), NewProvider(TestTime.Frozen(), "not-a-number").RefreshInterval);
        // A negative interval would mean "always stale" by accident; reject it back to the default.
        Assert.Equal(TimeSpan.FromSeconds(1), NewProvider(TestTime.Frozen(), "-5").RefreshInterval);
        Assert.Equal(TimeSpan.FromSeconds(90), NewProvider(TestTime.Frozen(), "90").RefreshInterval);
    }

    [Fact]
    public async Task RefreshIfStaleAsync_ReadFails_RetainsLastGoodKeyRatherThanSigningEveryoneOut()
    {
        await SetSecretAsync("secret-one");
        var clock = TestTime.Frozen();
        var provider = NewProvider(clock, refreshSeconds: "30");
        await provider.TryReloadAsync();

        // Break the metadata store the way a transient DB outage would.
        await _db.DisposeAsync();
        clock.Advance(TimeSpan.FromSeconds(60));
        await provider.RefreshIfStaleAsync();

        // Availability call, stated explicitly: a failed refresh must not drop the key and log
        // every session out on a DB blip. A DB this replica cannot read is also one no rotation
        // could have been committed through.
        Assert.Equal(Encoding.UTF8.GetBytes("secret-one"), SingleKeyBytes(provider));
    }
}
