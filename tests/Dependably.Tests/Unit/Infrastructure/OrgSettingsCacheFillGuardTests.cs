using System.Data.Common;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Caching;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Fill-after-invalidate coverage for <see cref="OrgRepository.GetSettingsAsync"/>'s settings
/// cache. A fill that read the settings row before a settings write and stores after that write's
/// invalidation must not re-cache the pre-change row: the next read returns the committed
/// settings. <see cref="AfterDbReadHookStore"/> runs the racing write exactly between the fill's
/// read and its cache write, so the interleaving is deterministic. Each replica's memory cache runs
/// on a frozen clock, so the settings entry's one-second TTL never lapses mid-test and a cached
/// entry is only ever gone because something expired it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OrgSettingsCacheFillGuardTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public OrgSettingsCacheFillGuardTests(InMemoryDbFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task FillThatReadTheOldRow_FinishingAfterAProxySettingsWrite_DoesNotRecacheIt()
    {
        var (orgId, hooked, replica) = await ReplicaAsync();
        var settings = new OrgSettingsRepository(_fixture.Store, replica.Orgs);

        // The proxy-settings write: commit, then invalidate the settings cache.
        hooked.AfterRead = () => settings.UpsertProxySettingsAsync(
            orgId, new ProxyPolicySettings(BlockDeprecated: "block_all"));

        var inFlight = await replica.Orgs.GetSettingsAsync(orgId);
        Assert.Equal("off", inFlight!.BlockDeprecated); // read before the write committed

        Assert.False(replica.HasCachedSettings(orgId));
        Assert.Equal("block_all", (await replica.Orgs.GetSettingsAsync(orgId))!.BlockDeprecated);
    }

    [Fact]
    public async Task FillThatReadTheOldRow_FinishingAfterAnInternalOrgRepositoryWrite_DoesNotRecacheIt()
    {
        var (orgId, hooked, replica) = await ReplicaAsync();

        // OrgRepository's own settings write, on the same (cached) repository the fill runs on.
        hooked.AfterRead = () => replica.Orgs.UpsertLicensePolicyModeAsync(orgId, "block");

        var inFlight = await replica.Orgs.GetSettingsAsync(orgId);
        Assert.Equal("off", inFlight!.LicenseEnforcementMode);

        Assert.False(replica.HasCachedSettings(orgId));
        Assert.Equal("block", (await replica.Orgs.GetSettingsAsync(orgId))!.LicenseEnforcementMode);
    }

    [Fact]
    public async Task FillThatReadTheOldRow_FinishingAfterAReceivedOrgWideMessage_DoesNotRecacheIt()
    {
        var (orgId, hooked, replica) = await ReplicaAsync();

        // A peer replica committed the change; this replica hears the org-wide message mid-fill.
        hooked.AfterRead = async () =>
        {
            await SetBlockDeprecatedAsync(orgId, "block_all");
            replica.Endpoint.Receive(
                MetadataInvalidationCodec.Encode(MetadataInvalidation.ForOrg(orgId), origin: "peer"));
        };

        var inFlight = await replica.Orgs.GetSettingsAsync(orgId);
        Assert.Equal("off", inFlight!.BlockDeprecated);
        Assert.Equal(1, replica.Endpoint.Applied);

        Assert.False(replica.HasCachedSettings(orgId));
        Assert.Equal("block_all", (await replica.Orgs.GetSettingsAsync(orgId))!.BlockDeprecated);
    }

    /// <summary>
    /// Adversarial twin: an ordinary fill with no concurrent change caches what it read, so the
    /// next read is served from the cache even though the row has since changed out of band (a
    /// write that never invalidated, which only the TTL bounds).
    /// </summary>
    [Fact]
    public async Task OrdinaryFill_WithNoConcurrentInvalidation_Caches()
    {
        var (orgId, _, replica) = await ReplicaAsync();

        Assert.Equal("off", (await replica.Orgs.GetSettingsAsync(orgId))!.BlockDeprecated);
        Assert.True(replica.HasCachedSettings(orgId));

        await SetBlockDeprecatedAsync(orgId, "block_all");
        Assert.Equal("off", (await replica.Orgs.GetSettingsAsync(orgId))!.BlockDeprecated);
    }

    /// <summary>
    /// Adversarial twin: an invalidation for another org landing in the window leaves this org's
    /// fill alone. The guard is per org, so a busy instance does not turn every concurrent fill
    /// into a miss.
    /// </summary>
    [Fact]
    public async Task FillStraddlingAnotherOrgsInvalidation_StillCaches()
    {
        var (orgId, hooked, replica) = await ReplicaAsync();
        string otherOrg = await OrgSeeder.InsertAsync(_fixture.Store, $"sfg-other-{Guid.NewGuid():N}");
        hooked.AfterRead = () =>
        {
            replica.Orgs.InvalidateSettingsCache(otherOrg);
            return Task.CompletedTask;
        };

        Assert.NotNull(await replica.Orgs.GetSettingsAsync(orgId));

        Assert.True(replica.HasCachedSettings(orgId));
    }

    [Fact]
    public async Task ReadThatThrowsAfterTheGuardIsMinted_DoesNotRetainIt()
    {
        var orgs = new OrgRepository(new ThrowingStore(), new MemoryCache(new MemoryCacheOptions()));

        await Assert.ThrowsAsync<InvalidOperationException>(() => orgs.GetSettingsAsync("any-org"));

        Assert.Equal(0, orgs.SettingsFillGuardCount);
    }

    [Fact]
    public async Task InvalidatingACachedEntry_RetiresItsGuard()
    {
        var (orgId, _, replica) = await ReplicaAsync();
        await replica.Orgs.GetSettingsAsync(orgId);
        Assert.Equal(1, replica.Orgs.SettingsFillGuardCount);

        replica.Orgs.InvalidateSettingsCache(orgId);

        Assert.Equal(0, replica.Orgs.SettingsFillGuardCount);
    }

    // ── Overlapping fills of one generation ─────────────────────────────────

    /// <summary>
    /// Two misses for one org that overlap both take the same generation. The second fill to store
    /// replaces the first fill's entry, and that replacement must not retire the generation the
    /// surviving entry is bound to: the cache keeps a live entry and the next read is a hit. Retiring
    /// on the replacement empties the cache on every overlapping fill, so a burst of concurrent
    /// misses reads the store on every request.
    /// </summary>
    [Fact]
    public async Task OverlappingFillsOfOneGeneration_LeaveTheSurvivingEntryCached()
    {
        var (orgId, hooked, cache, orgs) = await ObservedRepositoryAsync();

        // Fill B starts and finishes inside fill A's read, so A's store replaces B's entry.
        hooked.AfterRead = () => orgs.GetSettingsAsync(orgId);
        Assert.Equal("off", (await orgs.GetSettingsAsync(orgId))!.BlockDeprecated);
        await cache.WhenEvictedAsync(SettingsKey(orgId), EvictionReason.Replaced);

        Assert.True(cache.TryGetValue(SettingsKey(orgId), out _));
        // A third read is a hit: an out-of-band row change (no invalidation) is not seen.
        await SetBlockDeprecatedAsync(orgId, "block_all");
        Assert.Equal("off", (await orgs.GetSettingsAsync(orgId))!.BlockDeprecated);
    }

    /// <summary>
    /// A stale fill (its generation cancelled by a write it overlapped) that stores over a good
    /// entry from a later generation is expired on insert and displaces the good entry. The
    /// displaced entry's generation is retired with it, so nothing is left in the guard map, and
    /// the next read misses and reads the committed row: never a stale hit.
    /// </summary>
    [Fact]
    public async Task StaleFillStoringOverAGoodEntry_NeverServesStaleSettings_AndLeavesNoGuard()
    {
        var (orgId, hooked, cache, orgs) = await ObservedRepositoryAsync();
        var settings = new OrgSettingsRepository(_fixture.Store, orgs);

        hooked.AfterRead = async () =>
        {
            await settings.UpsertProxySettingsAsync(orgId, new ProxyPolicySettings(BlockDeprecated: "block_all"));
            Assert.Equal("block_all", (await orgs.GetSettingsAsync(orgId))!.BlockDeprecated); // good entry
        };
        Assert.Equal("off", (await orgs.GetSettingsAsync(orgId))!.BlockDeprecated); // the stale fill
        await cache.WhenEvictedAsync(SettingsKey(orgId), EvictionReason.Replaced);

        Assert.Equal(0, orgs.SettingsFillGuardCount);
        Assert.Equal("block_all", (await orgs.GetSettingsAsync(orgId))!.BlockDeprecated);

        cache.Inner.Compact(1.0);
        await cache.WhenAllEvictedAsync();
        Assert.Equal(0, orgs.SettingsFillGuardCount);
    }

    /// <summary>
    /// Churn across every shape the counted guard handles (overlapping fills of one generation,
    /// fills straddling an invalidation, a stale fill storing over a good entry, and a burst of
    /// unsynchronized concurrent misses) leaves the guard map empty once the cached entries are
    /// gone: no generation outlives the entries bound to it.
    /// </summary>
    [Fact]
    public async Task GuardMapDrainsAfterChurn()
    {
        var (orgId, hooked, cache, orgs) = await ObservedRepositoryAsync();

        Func<Task> overlappingFill = () => orgs.GetSettingsAsync(orgId);
        Func<Task> invalidate = () =>
        {
            orgs.InvalidateSettingsCache(orgId);
            return Task.CompletedTask;
        };
        Func<Task> invalidateThenGoodFill = async () =>
        {
            orgs.InvalidateSettingsCache(orgId);
            await orgs.GetSettingsAsync(orgId);
        };
        Func<Task>[] windows = [overlappingFill, invalidate, invalidateThenGoodFill];

        for (int round = 0; round < 12; round++)
        {
            hooked.AfterRead = windows[round % windows.Length];
            await orgs.GetSettingsAsync(orgId);
            if (round % 4 == 3)
            {
                orgs.InvalidateSettingsCache(orgId);
            }
        }

        await Task.WhenAll(Enumerable.Range(0, 32).Select(i => Task.Run(async () =>
        {
            if (i % 8 == 0)
            {
                orgs.InvalidateSettingsCache(orgId);
            }

            await orgs.GetSettingsAsync(orgId);
        })));

        cache.Inner.Compact(1.0);
        await cache.WhenAllEvictedAsync();
        Assert.Equal(0, orgs.SettingsFillGuardCount);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string SettingsKey(string orgId) => "org-settings:" + orgId;

    private async Task<(string OrgId, AfterDbReadHookStore Hooked, EvictionObservingCache Cache, OrgRepository Orgs)> ObservedRepositoryAsync()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sfg-obs-{Guid.NewGuid():N}");
        var hooked = new AfterDbReadHookStore(_fixture.Store);
        var time = TestTime.Frozen();
        var cache = new EvictionObservingCache(time);
        return (orgId, hooked, cache, new OrgRepository(hooked, cache, time));
    }

    private async Task<(string OrgId, AfterDbReadHookStore Hooked, TestInvalidationReplica Replica)> ReplicaAsync()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sfg-{Guid.NewGuid():N}");
        var hooked = new AfterDbReadHookStore(_fixture.Store);
        var replica = TestInvalidationReplica.Join(
            new InMemoryInvalidationChannel(), hooked, TestTime.Frozen());
        return (orgId, hooked, replica);
    }

    private async Task SetBlockDeprecatedAsync(string orgId, string mode)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET block_deprecated = @mode WHERE org_id = @orgId",
            new { mode, orgId });
    }

    private sealed class ThrowingStore : IMetadataStore
    {
        public DbProvider Provider => DbProvider.Sqlite;

        public Task<DbConnection> OpenAsync(CancellationToken ct = default) =>
            throw new InvalidOperationException("Simulates a refused DB open after the fill guard is minted.");
    }
}
