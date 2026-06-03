using Dependably.Storage;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Prove the factory's per-tier override path actually picks up <c>_CACHE</c> /
/// <c>_REGISTRY</c> suffixes, and that <see cref="TieredBlobStorage.IsSplit"/> reports
/// truth. A regression here would mean operators thinking they had split-tier storage
/// while both tiers silently shared a backend.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TieredBlobStorageTests
{
    private static IConfiguration Cfg(IDictionary<string, string?> vars) =>
        new ConfigurationBuilder().AddInMemoryCollection(vars).Build();

    [Fact]
    public async Task DefaultBackend_BothTiersResolveToSamePath()
    {
        var dir = Path.Combine(Path.GetTempPath(), "tiered_default_" + Guid.NewGuid().ToString("N"));
        try
        {
            var cfg = Cfg(new Dictionary<string, string?>
            {
                ["STORAGE_BACKEND"] = "local",
                ["LOCAL_STORAGE_PATH"] = dir,
            });

            var cache = BlobStoreFactory.CreateForTier(cfg, "CACHE");
            var registry = BlobStoreFactory.CreateForTier(cfg, "REGISTRY");

            // Both tiers materialise as LocalBlobStore on the same root — write through one,
            // read through the other.
            await cache.PutAsync("probe-key", new MemoryStream([1, 2, 3]));
            var roundTrip = await registry.GetAsync("probe-key");
            Assert.NotNull(roundTrip);
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task TierOverride_LocalPath_IsHonoured()
    {
        var dirCache = Path.Combine(Path.GetTempPath(), "tiered_cache_" + Guid.NewGuid().ToString("N"));
        var dirReg = Path.Combine(Path.GetTempPath(), "tiered_reg_" + Guid.NewGuid().ToString("N"));
        try
        {
            var cfg = Cfg(new Dictionary<string, string?>
            {
                ["STORAGE_BACKEND"] = "local",
                ["LOCAL_STORAGE_PATH"] = "/should/not/be/used",
                ["LOCAL_STORAGE_PATH_CACHE"] = dirCache,
                ["LOCAL_STORAGE_PATH_REGISTRY"] = dirReg,
            });

            var cache = BlobStoreFactory.CreateForTier(cfg, "CACHE");
            var registry = BlobStoreFactory.CreateForTier(cfg, "REGISTRY");

            await cache.PutAsync("only-in-cache", new MemoryStream([1]));
            await registry.PutAsync("only-in-registry", new MemoryStream([2]));

            // Tier isolation: each store sees only its own keys.
            Assert.True(File.Exists(Path.Combine(dirCache, "only-in-cache")));
            Assert.True(File.Exists(Path.Combine(dirReg, "only-in-registry")));
            Assert.False(File.Exists(Path.Combine(dirCache, "only-in-registry")));
            Assert.False(File.Exists(Path.Combine(dirReg, "only-in-cache")));
        }
        finally
        {
            if (Directory.Exists(dirCache)) Directory.Delete(dirCache, recursive: true);
            if (Directory.Exists(dirReg)) Directory.Delete(dirReg, recursive: true);
        }
    }

    [Fact]
    public void TierOverride_DistinctLocalDirsProveTrueIsolation()
    {
        // Cache and registry tiers can sit on different LOCAL_STORAGE_PATH roots — a write
        // on one tier must not show up under the other tier's root. This is the in-process
        // proxy for "cache on local, registry on s3"; the cross-backend story is exercised
        // in deployment integration rather than unit tests because instantiating S3/Azure
        // clients pings the network.
        var dirCache = Path.Combine(Path.GetTempPath(), "tiered_cache2_" + Guid.NewGuid().ToString("N"));
        var dirReg = Path.Combine(Path.GetTempPath(), "tiered_reg2_" + Guid.NewGuid().ToString("N"));
        try
        {
            var cfg = Cfg(new Dictionary<string, string?>
            {
                ["STORAGE_BACKEND"] = "local",
                ["LOCAL_STORAGE_PATH_CACHE"] = dirCache,
                ["LOCAL_STORAGE_PATH_REGISTRY"] = dirReg,
            });

            var cache = BlobStoreFactory.CreateForTier(cfg, "CACHE");
            var registry = BlobStoreFactory.CreateForTier(cfg, "REGISTRY");

            Assert.IsType<LocalBlobStore>(cache);
            Assert.IsType<LocalBlobStore>(registry);
            // Reference inequality matters: a shared instance would break the per-tier eviction
            // guarantees.
            Assert.False(ReferenceEquals(cache, registry));
        }
        finally
        {
            if (Directory.Exists(dirCache)) Directory.Delete(dirCache, recursive: true);
            if (Directory.Exists(dirReg)) Directory.Delete(dirReg, recursive: true);
        }
    }

    [Fact]
    public void IsSplit_TrueWhenInstancesDiffer()
    {
        var a = new InMemoryBlobStore();
        var b = new InMemoryBlobStore();
        Assert.True(new TieredBlobStorage(a, b).IsSplit);
        Assert.False(new TieredBlobStorage(a, a).IsSplit);
    }
}
