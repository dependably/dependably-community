using Dependably.Infrastructure.Caching;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Builds a <see cref="MetadataInvalidationCoordinator"/> over the real per-ecosystem caches and
/// their real <see cref="MetadataCacheKeys"/> formatters. Tests that only need the mutation path
/// to have somewhere to send an invalidation call <see cref="Coordinator()"/>; tests that assert
/// on the caches or the broadcast build one with <see cref="Build"/> and keep the pieces.
/// </summary>
internal static class TestMetadataInvalidation
{
    /// <summary>A coordinator over private caches and a no-op bus — the "just satisfy DI" form.</summary>
    internal static MetadataInvalidationCoordinator Coordinator() => Build().Coordinator;

    /// <summary>A coordinator over private caches and a no-op bus, sharing <paramref name="memory"/>.</summary>
    internal static MetadataInvalidationCoordinator Coordinator(IMemoryCache memory) =>
        Build(memory).Coordinator;

    /// <summary>
    /// A coordinator that evicts through the caller's own <paramref name="maven"/> cache instance —
    /// mirroring production, where the read path and the coordinator resolve the same DI singleton.
    /// The other ecosystems get private caches the caller does not assert on.
    /// </summary>
    internal static MetadataInvalidationCoordinator ForMaven(RenderedResponseCache<MavenMetadataKey> maven)
    {
        var harness = Build();
        return new MetadataInvalidationCoordinator(
            harness.Npm, harness.PyPi, harness.NuGet, maven, harness.RpmLocal, harness.RpmMerged, harness.Bus);
    }

    /// <summary>
    /// Builds a coordinator plus every cache it evicts through, all over one
    /// <see cref="IMemoryCache"/>. <paramref name="bus"/> defaults to the no-op bus.
    /// </summary>
    internal static TestInvalidationHarness Build(IMemoryCache? memory = null, IMetadataInvalidationBus? bus = null)
    {
        var cache = memory ?? new MemoryCache(new MemoryCacheOptions { SizeLimit = 8 * 1024 * 1024 });
        var npm = new RenderedResponseCache<NpmPackumentKey>(cache, MetadataCacheKeys.NpmPackument);
        var pypi = new RenderedResponseCache<PyPiSimpleIndexKey>(cache, MetadataCacheKeys.PyPiSimpleIndex);
        var nuget = new RenderedResponseCache<NuGetRegistrationKey>(cache, MetadataCacheKeys.NuGetRegistration);
        var maven = new RenderedResponseCache<MavenMetadataKey>(cache, MetadataCacheKeys.MavenMetadata);
        var rpmLocal = new RenderedResponseCache<RpmLocalRepodataKey>(cache, MetadataCacheKeys.RpmLocalRepodata);
        var rpmMerged = new MetadataResponseCache<RpmMergedRepodataKey, MergedRepodataCache>(
            cache, MetadataCacheKeys.RpmMergedRepodata);

        var effectiveBus = bus ?? new NullMetadataInvalidationBus();
        return new TestInvalidationHarness(
            new MetadataInvalidationCoordinator(npm, pypi, nuget, maven, rpmLocal, rpmMerged, effectiveBus),
            cache, npm, pypi, nuget, maven, rpmLocal, rpmMerged, effectiveBus);
    }
}

/// <summary>The coordinator under test plus every cache and the bus it was built over.</summary>
internal sealed record TestInvalidationHarness(
    MetadataInvalidationCoordinator Coordinator,
    IMemoryCache Memory,
    RenderedResponseCache<NpmPackumentKey> Npm,
    RenderedResponseCache<PyPiSimpleIndexKey> PyPi,
    RenderedResponseCache<NuGetRegistrationKey> NuGet,
    RenderedResponseCache<MavenMetadataKey> Maven,
    RenderedResponseCache<RpmLocalRepodataKey> RpmLocal,
    MetadataResponseCache<RpmMergedRepodataKey, MergedRepodataCache> RpmMerged,
    IMetadataInvalidationBus Bus);

/// <summary>
/// An <see cref="IMetadataInvalidationBus"/> that records what the mutation path handed it, so a
/// test can assert on the broadcast coordinates without a broker.
/// </summary>
internal sealed class RecordingMetadataInvalidationBus : IMetadataInvalidationBus
{
    private readonly List<MetadataInvalidation> _published = new();

    internal IReadOnlyList<MetadataInvalidation> Published
    {
        get
        {
            lock (_published)
            {
                return _published.ToList();
            }
        }
    }

    public void Publish(MetadataInvalidation invalidation)
    {
        lock (_published)
        {
            _published.Add(invalidation);
        }
    }
}
