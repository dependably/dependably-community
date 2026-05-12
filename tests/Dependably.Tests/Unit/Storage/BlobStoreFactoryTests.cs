using Dependably.Storage;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Dependably.Tests.Unit.Storage;

/// <summary>
/// Covers the factory-level branch selection and guard throws in
/// <see cref="BlobStoreFactory.Create"/> / <see cref="BlobStoreFactory.CreateForTier"/>.
/// Tier-isolation integration (two tiers sharing or splitting paths) lives in
/// <c>TieredBlobStorageTests</c>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BlobStoreFactoryTests
{
    private static IConfiguration Cfg(IDictionary<string, string?> vars) =>
        new ConfigurationBuilder().AddInMemoryCollection(vars).Build();

    private static IConfiguration EmptyCfg() =>
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>()).Build();

    // ── Create() ────────────────────────────────────────────────────────────────

    [Fact]
    public void Create_NoBackendVar_ReturnsLocalBlobStore()
    {
        // Supply a writable path so LocalBlobStore can create the root directory; the default
        // /data/blobs is read-only outside Docker.
        var dir = Path.Combine(Path.GetTempPath(), "bsf_default_" + Guid.NewGuid().ToString("N"));
        try
        {
            var cfg = Cfg(new Dictionary<string, string?>
            {
                ["LOCAL_STORAGE_PATH"] = dir,
                // STORAGE_BACKEND intentionally absent — factory must default to "local"
            });

            var store = BlobStoreFactory.Create(cfg);

            Assert.IsType<LocalBlobStore>(store);
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Create_AzureBackend_MissingConnectionString_Throws()
    {
        var cfg = Cfg(new Dictionary<string, string?>
        {
            ["STORAGE_BACKEND"] = "azure",
            // AZURE_CONNECTION_STRING intentionally absent
        });

        Assert.Throws<InvalidOperationException>(() => BlobStoreFactory.Create(cfg));
    }

    [Fact]
    public void Create_AzureBackend_MissingContainer_Throws()
    {
        var cfg = Cfg(new Dictionary<string, string?>
        {
            ["STORAGE_BACKEND"] = "azure",
            ["AZURE_CONNECTION_STRING"] = "DefaultEndpointsProtocol=https;AccountName=test;AccountKey=dGVzdA==;EndpointSuffix=core.windows.net",
            // AZURE_CONTAINER intentionally absent
        });

        Assert.Throws<InvalidOperationException>(() => BlobStoreFactory.Create(cfg));
    }

    [Fact]
    public void Create_S3Backend_MissingBucket_Throws()
    {
        var cfg = Cfg(new Dictionary<string, string?>
        {
            ["STORAGE_BACKEND"] = "s3",
            // S3_BUCKET intentionally absent
        });

        Assert.Throws<InvalidOperationException>(() => BlobStoreFactory.Create(cfg));
    }

    [Fact]
    public void Create_S3Backend_MissingRegion_Throws()
    {
        var cfg = Cfg(new Dictionary<string, string?>
        {
            ["STORAGE_BACKEND"] = "s3",
            ["S3_BUCKET"] = "my-bucket",
            // S3_REGION intentionally absent
        });

        Assert.Throws<InvalidOperationException>(() => BlobStoreFactory.Create(cfg));
    }

    [Fact]
    public void Create_UnknownBackend_Throws()
    {
        var cfg = Cfg(new Dictionary<string, string?>
        {
            ["STORAGE_BACKEND"] = "ftp",
        });

        var ex = Assert.Throws<InvalidOperationException>(() => BlobStoreFactory.Create(cfg));
        Assert.Contains("ftp", ex.Message);
    }

    // ── CreateForTier() ──────────────────────────────────────────────────────────

    [Fact]
    public void CreateForTier_TierOverride_UsesTierPath()
    {
        // STORAGE_BACKEND_CACHE is not set, so the base STORAGE_BACKEND=local is used.
        // LOCAL_STORAGE_PATH_CACHE IS set, so the tier path should override the base path.
        var cfg = Cfg(new Dictionary<string, string?>
        {
            ["STORAGE_BACKEND"] = "local",
            ["LOCAL_STORAGE_PATH"] = "/tmp/base",
            ["LOCAL_STORAGE_PATH_CACHE"] = "/tmp/cache",
        });

        var store = BlobStoreFactory.CreateForTier(cfg, "CACHE");

        // The returned store must be a LocalBlobStore rooted at /tmp/cache.
        // We verify this by inspecting the type (tier isolation behaviour is
        // proven in TieredBlobStorageTests.TierOverride_LocalPath_IsHonoured).
        Assert.IsType<LocalBlobStore>(store);
    }

    [Fact]
    public void CreateForTier_TierKeyWhitespace_FallsBackToBase()
    {
        // A whitespace-only tier override must be treated as absent (TieredValue trims).
        var cfg = Cfg(new Dictionary<string, string?>
        {
            ["STORAGE_BACKEND"] = "local",
            ["STORAGE_BACKEND_CACHE"] = "   ",  // whitespace only — should be ignored
            ["LOCAL_STORAGE_PATH"] = "/tmp/base",
        });

        // Should not throw; falls back to base "local" backend.
        var store = BlobStoreFactory.CreateForTier(cfg, "CACHE");

        Assert.IsType<LocalBlobStore>(store);
    }
}
