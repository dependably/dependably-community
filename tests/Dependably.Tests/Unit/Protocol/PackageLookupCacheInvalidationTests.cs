using Dependably.Protocol;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// <see cref="PackageLookupCache.InvalidateOrg"/> expires one org's cached lookup outcomes —
/// including one whose computation straddles the call — and no other org's.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PackageLookupCacheInvalidationTests
{
    private const string OrgA = "org-a";
    private const string OrgB = "org-b";

    private static string Key(string orgId) => PackageLookupCache.KeyFor(orgId, "npm", "left-pad", null);

    private static Task<PackageLookupOutcome> ComputeAsync() =>
        Task.FromResult(PackageLookupOutcome.VersionRequired("npm"));

    [Fact]
    public async Task InvalidateOrg_ExpiresThatOrgsOutcomes_AndKeepsOtherOrgs()
    {
        var cache = new PackageLookupCache(TestTime.Frozen());
        await cache.SingleFlightAsync(Key(OrgA), ComputeAsync, CancellationToken.None);
        await cache.SingleFlightAsync(Key(OrgB), ComputeAsync, CancellationToken.None);

        cache.InvalidateOrg(OrgA);

        Assert.Null(cache.TryGet(Key(OrgA)));
        Assert.NotNull(cache.TryGet(Key(OrgB)));
    }

    [Fact]
    public async Task InvalidateOrg_ThenARecompute_CachesTheFreshOutcome()
    {
        var cache = new PackageLookupCache(TestTime.Frozen());
        await cache.SingleFlightAsync(Key(OrgA), ComputeAsync, CancellationToken.None);
        cache.InvalidateOrg(OrgA);

        int computed = 0;
        Task<PackageLookupOutcome> Counting()
        {
            computed++;
            return ComputeAsync();
        }

        await cache.SingleFlightAsync(Key(OrgA), Counting, CancellationToken.None);
        await cache.SingleFlightAsync(Key(OrgA), Counting, CancellationToken.None);

        Assert.Equal(1, computed);
        Assert.NotNull(cache.TryGet(Key(OrgA)));
    }

    [Fact]
    public async Task InvalidateOrg_DuringAComputation_DoesNotLetThatOutcomeServe()
    {
        // The computation read the pre-invalidation state; storing it as live would serve that
        // state for the full TTL after the change that invalidated it.
        var cache = new PackageLookupCache(TestTime.Frozen());

        var outcome = await cache.SingleFlightAsync(Key(OrgA), () =>
        {
            cache.InvalidateOrg(OrgA);
            return ComputeAsync();
        }, CancellationToken.None);

        Assert.Equal(PackageLookupStatus.VersionRequired, outcome.Status);
        Assert.Null(cache.TryGet(Key(OrgA)));
    }

    /// <summary>
    /// Org ids arriving over the invalidation channel are not bounded by this replica's tenants,
    /// so the bookkeeping must not keep one entry per id it has ever seen.
    /// </summary>
    [Fact]
    public void InvalidateOrg_ForManyDistinctOrgs_KeepsTheBookkeepingBounded()
    {
        var cache = new PackageLookupCache(TestTime.Frozen());

        for (int i = 0; i < 20_000; i++)
        {
            cache.InvalidateOrg($"org-{i}");
        }

        Assert.InRange(cache.InvalidatedOrgCount, 1, 4096);
    }

    /// <summary>
    /// The cap's clear must not resurrect anything: an outcome cached before its org's
    /// invalidation stays expired after that org's invalidation point has been cleared away by
    /// thousands of later ones, and so does one whose org was invalidated while it computed.
    /// </summary>
    [Fact]
    public async Task OutcomesCachedBeforeAnInvalidation_StayExpired_AfterTheBookkeepingIsCleared()
    {
        var cache = new PackageLookupCache(TestTime.Frozen());
        await cache.SingleFlightAsync(Key(OrgA), ComputeAsync, CancellationToken.None);
        cache.InvalidateOrg(OrgA);

        var straddling = await cache.SingleFlightAsync(Key(OrgB), () =>
        {
            cache.InvalidateOrg(OrgB);
            for (int i = 0; i < 5_000; i++)
            {
                cache.InvalidateOrg($"peer-org-{i}");
            }

            return ComputeAsync();
        }, CancellationToken.None);

        Assert.Equal(PackageLookupStatus.VersionRequired, straddling.Status);
        Assert.Null(cache.TryGet(Key(OrgA)));
        Assert.Null(cache.TryGet(Key(OrgB)));
    }

    /// <summary>
    /// Clearing the bookkeeping expires what was cached before it, once; outcomes computed
    /// afterwards cache normally.
    /// </summary>
    [Fact]
    public async Task AfterTheBookkeepingIsCleared_NewOutcomesCacheNormally()
    {
        var cache = new PackageLookupCache(TestTime.Frozen());
        for (int i = 0; i < 5_000; i++)
        {
            cache.InvalidateOrg($"peer-org-{i}");
        }

        await cache.SingleFlightAsync(Key(OrgA), ComputeAsync, CancellationToken.None);

        Assert.NotNull(cache.TryGet(Key(OrgA)));
    }
}
