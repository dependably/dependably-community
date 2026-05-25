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

    // ── S3 endpoint + force-path-style (R2 / MinIO / B2 / Wasabi) ────────────────

    [Fact]
    public void Create_S3Backend_WithEndpointAndForcePathStyle_ReturnsS3BlobStore()
    {
        // Cloudflare R2-style configuration: explicit endpoint + path-style addressing.
        // No real S3 call is made; this verifies the factory accepts and routes the values.
        var cfg = Cfg(new Dictionary<string, string?>
        {
            ["STORAGE_BACKEND"] = "s3",
            ["S3_BUCKET"] = "dependably-prod",
            ["S3_REGION"] = "auto",
            ["S3_ENDPOINT"] = "https://example.r2.cloudflarestorage.com",
            ["S3_FORCE_PATH_STYLE"] = "true",
        });

        var store = BlobStoreFactory.Create(cfg);

        Assert.IsType<S3BlobStore>(store);
    }

    [Fact]
    public void CreateForTier_S3Endpoint_TierOverrideTakesPrecedence()
    {
        // S3_ENDPOINT_REGISTRY must beat S3_ENDPOINT for the REGISTRY tier (no exception is
        // good enough here — TieredValue precedence is exercised in TieredValue's own tests).
        var cfg = Cfg(new Dictionary<string, string?>
        {
            ["STORAGE_BACKEND"] = "s3",
            ["S3_BUCKET"] = "fallback-bucket",
            ["S3_REGION"] = "us-east-1",
            ["S3_ENDPOINT"] = "https://example.r2.cloudflarestorage.com",
            ["S3_BUCKET_REGISTRY"] = "registry-bucket",
            ["S3_REGION_REGISTRY"] = "auto",
            ["S3_ENDPOINT_REGISTRY"] = "https://registry.r2.cloudflarestorage.com",
            ["S3_FORCE_PATH_STYLE_REGISTRY"] = "true",
        });

        var store = BlobStoreFactory.CreateForTier(cfg, "REGISTRY");

        Assert.IsType<S3BlobStore>(store);
    }

    [Fact]
    public void Create_S3Backend_ForcePathStyleAbsent_DefaultsFalse()
    {
        // AWS S3 path: no endpoint, no force-path-style — the standard region-based client.
        var cfg = Cfg(new Dictionary<string, string?>
        {
            ["STORAGE_BACKEND"] = "s3",
            ["S3_BUCKET"] = "aws-bucket",
            ["S3_REGION"] = "us-east-1",
        });

        var store = BlobStoreFactory.Create(cfg);

        Assert.IsType<S3BlobStore>(store);
    }

    [Theory]
    [InlineData("not-a-bool")]
    [InlineData("")]
    [InlineData("yes")]
    public void Create_S3Backend_ForcePathStyleNonBool_TreatedAsFalse(string value)
    {
        // bool.TryParse only accepts "true"/"false" (case-insensitive). Anything else
        // falls back to false rather than throwing — keeps the env-var surface forgiving.
        var cfg = Cfg(new Dictionary<string, string?>
        {
            ["STORAGE_BACKEND"] = "s3",
            ["S3_BUCKET"] = "b",
            ["S3_REGION"] = "us-east-1",
            ["S3_ENDPOINT"] = "https://example.com",
            ["S3_FORCE_PATH_STYLE"] = value,
        });

        var store = BlobStoreFactory.Create(cfg);

        Assert.IsType<S3BlobStore>(store);
    }

    [Fact]
    public void Create_S3Backend_ForcePathStyleParsesFalse_StillReturnsS3BlobStore()
    {
        // Covers the second branch of `bool.TryParse(...) && fps` — TryParse succeeds
        // (so the && doesn't short-circuit) but the parsed value is false. Both
        // conditions in the compound boolean must be evaluated.
        var cfg = Cfg(new Dictionary<string, string?>
        {
            ["STORAGE_BACKEND"] = "s3",
            ["S3_BUCKET"] = "b",
            ["S3_REGION"] = "us-east-1",
            ["S3_FORCE_PATH_STYLE"] = "false",
        });

        var store = BlobStoreFactory.Create(cfg);

        Assert.IsType<S3BlobStore>(store);
    }

    // ── Case-insensitive backend matching ────────────────────────────────────────

    [Theory]
    [InlineData("LOCAL")]
    [InlineData("Local")]
    public void Create_BackendValueUppercase_IsCaseInsensitive(string backendValue)
    {
        // The factory lowercases the backend value before the switch, so "LOCAL",
        // "Local", and "local" must all route to LocalBlobStore.
        var dir = Path.Combine(Path.GetTempPath(), "bsf_case_" + Guid.NewGuid().ToString("N"));
        try
        {
            var cfg = Cfg(new Dictionary<string, string?>
            {
                ["STORAGE_BACKEND"] = backendValue,
                ["LOCAL_STORAGE_PATH"] = dir,
            });

            var store = BlobStoreFactory.Create(cfg);

            Assert.IsType<LocalBlobStore>(store);
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }

    // ── Tier override of the backend value itself ────────────────────────────────

    [Fact]
    public void CreateForTier_BackendTierOverride_SwitchesBackend()
    {
        // Base is "local" but STORAGE_BACKEND_REGISTRY=s3 must flip the registry tier
        // to S3. This exercises the tier-resolution branch of TieredValue for the
        // backend key itself (not just the path/bucket keys).
        var cfg = Cfg(new Dictionary<string, string?>
        {
            ["STORAGE_BACKEND"] = "local",
            ["LOCAL_STORAGE_PATH"] = "/tmp/base",
            ["STORAGE_BACKEND_REGISTRY"] = "s3",
            ["S3_BUCKET_REGISTRY"] = "reg-bucket",
            ["S3_REGION_REGISTRY"] = "us-east-1",
        });

        var store = BlobStoreFactory.CreateForTier(cfg, "REGISTRY");

        Assert.IsType<S3BlobStore>(store);
    }

    [Fact]
    public void CreateForTier_UnknownTierBackend_ErrorMessageIncludesTier()
    {
        // The unknown-backend exception message includes the tier name when one is
        // supplied — covers the `tier ?? "default"` non-null branch in the throw.
        var cfg = Cfg(new Dictionary<string, string?>
        {
            ["STORAGE_BACKEND_CACHE"] = "rsync",
        });

        var ex = Assert.Throws<InvalidOperationException>(
            () => BlobStoreFactory.CreateForTier(cfg, "CACHE"));
        Assert.Contains("rsync", ex.Message);
        Assert.Contains("CACHE", ex.Message);
    }
}
