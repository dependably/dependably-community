using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// A reserved-namespace mutation expires every cached answer derived from the old list for that
/// org — rendered metadata (through the org's <see cref="OrgCacheEpochStore"/> epoch) and
/// package-lookup outcomes — and leaves every other org's entries alone.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ReservedNamespaceDerivedCacheTests : IClassFixture<InMemoryDbFixture>
{
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    private readonly InMemoryDbFixture _fixture;

    public ReservedNamespaceDerivedCacheTests(InMemoryDbFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task Add_ExpiresTheOrgsRenderedMetadataAndLookups_AndNoOtherOrgs()
    {
        var h = await HarnessAsync();
        await h.SeedBothOrgsAsync();

        await h.Service.AddAsync(h.OrgA, "maven", "com.acme", createdBy: null);

        Assert.False(h.Metadata.TryGet(Harness.MetadataKey(h.OrgA), out _));
        Assert.Null(h.Lookups.TryGet(Harness.LookupKey(h.OrgA)));
        Assert.True(h.Metadata.TryGet(Harness.MetadataKey(h.OrgB), out _));
        Assert.NotNull(h.Lookups.TryGet(Harness.LookupKey(h.OrgB)));
    }

    [Fact]
    public async Task Delete_ExpiresTheOrgsRenderedMetadataAndLookups_AndNoOtherOrgs()
    {
        var h = await HarnessAsync();
        var entry = await h.Service.AddAsync(h.OrgA, "maven", "com.acme", createdBy: null);
        await h.SeedBothOrgsAsync();

        Assert.Equal(1, await h.Service.DeleteAsync(h.OrgA, entry.Id));

        Assert.False(h.Metadata.TryGet(Harness.MetadataKey(h.OrgA), out _));
        Assert.Null(h.Lookups.TryGet(Harness.LookupKey(h.OrgA)));
        Assert.True(h.Metadata.TryGet(Harness.MetadataKey(h.OrgB), out _));
        Assert.NotNull(h.Lookups.TryGet(Harness.LookupKey(h.OrgB)));
    }

    [Fact]
    public async Task DeleteOfAnotherOrgsEntry_RemovesNothing_AndExpiresNothing()
    {
        // The delete is org-scoped: naming org B's entry from org A removes no row, so neither
        // org's derived caches have anything to answer differently.
        var h = await HarnessAsync();
        var entryOfB = await h.Service.AddAsync(h.OrgB, "maven", "com.acme", createdBy: null);
        await h.SeedBothOrgsAsync();

        Assert.Equal(0, await h.Service.DeleteAsync(h.OrgA, entryOfB.Id));

        Assert.True(h.Metadata.TryGet(Harness.MetadataKey(h.OrgA), out _));
        Assert.True(h.Metadata.TryGet(Harness.MetadataKey(h.OrgB), out _));
        Assert.NotNull(h.Lookups.TryGet(Harness.LookupKey(h.OrgA)));
        Assert.NotNull(h.Lookups.TryGet(Harness.LookupKey(h.OrgB)));
    }

    private async Task<Harness> HarnessAsync()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"rns-epoch-a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"rns-epoch-b-{Guid.NewGuid():N}");
        var memory = new MemoryCache(new MemoryCacheOptions());
        var epoch = new OrgCacheEpochStore();
        var time = TestTime.Frozen();
        var lookups = new PackageLookupCache(time);
        var metadata = new RenderedResponseCache<MavenMetadataKey>(memory, MetadataCacheKeys.MavenMetadata, epoch);
        var service = new ReservedNamespaceService(_fixture.Store, memory, time, epoch, lookups);
        return new Harness(orgA, orgB, service, metadata, lookups);
    }

    private sealed record Harness(
        string OrgA,
        string OrgB,
        ReservedNamespaceService Service,
        RenderedResponseCache<MavenMetadataKey> Metadata,
        PackageLookupCache Lookups)
    {
        public static MavenMetadataKey MetadataKey(string orgId) => new(orgId, "com.acme.internal", "lib");

        public static string LookupKey(string orgId) => PackageLookupCache.KeyFor(orgId, "maven", "com.acme.internal:lib", null);

        // Both orgs hold a rendered document and a lookup outcome for the same coordinate, so an
        // assertion on one org cannot pass because the other's entry was never there.
        public async Task SeedBothOrgsAsync()
        {
            foreach (string orgId in new[] { OrgA, OrgB })
            {
                Metadata.Set(MetadataKey(orgId), [1, 2, 3], Ttl);
                await Lookups.SingleFlightAsync(
                    LookupKey(orgId),
                    () => Task.FromResult(PackageLookupOutcome.VersionRequired("maven")),
                    CancellationToken.None);
                Assert.True(Metadata.TryGet(MetadataKey(orgId), out _));
                Assert.NotNull(Lookups.TryGet(LookupKey(orgId)));
            }
        }
    }
}
