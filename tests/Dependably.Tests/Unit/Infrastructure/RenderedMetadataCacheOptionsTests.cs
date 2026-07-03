using Dependably.Infrastructure;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Pins the configurable-TTL fix for the rendered-metadata response caches (npm packument,
/// NuGet registration, PyPI simple index, Maven metadata): those TTLs used to be compile-time
/// constants with no env-var knob, making CONTRIBUTING.md's documented HA mitigation ("keep
/// metadata TTLs short in multi-instance deployments") impossible to apply. This is what an
/// operator sets to shorten the post-publish staleness window on non-publishing replicas.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RenderedMetadataCacheOptionsTests
{
    private static IConfiguration Config(IDictionary<string, string?> values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    [Fact]
    public void Resolve_NoConfig_UsesDocumentedDefaults()
    {
        var opts = RenderedMetadataCacheOptions.Resolve(Config(new Dictionary<string, string?>()));

        Assert.Equal(TimeSpan.FromSeconds(RenderedMetadataCacheOptions.DefaultLocalTtlSeconds), opts.LocalTtl);
        Assert.Equal(TimeSpan.FromSeconds(RenderedMetadataCacheOptions.DefaultProxyTtlSeconds), opts.ProxyTtl);
    }

    [Fact]
    public void Resolve_LocalTtlConfigured_HonorsOperatorValue()
    {
        // The concrete operator scenario from the issue: shorten the local TTL in an HA
        // deployment so non-publishing replicas stop serving stale packument/registration/
        // simple-index bodies for as long.
        var opts = RenderedMetadataCacheOptions.Resolve(Config(new Dictionary<string, string?>
        {
            ["METADATA_LOCAL_CACHE_TTL_SECONDS"] = "30",
        }));

        Assert.Equal(TimeSpan.FromSeconds(30), opts.LocalTtl);
        Assert.Equal(TimeSpan.FromSeconds(RenderedMetadataCacheOptions.DefaultProxyTtlSeconds), opts.ProxyTtl);
    }

    [Fact]
    public void Resolve_ProxyTtlConfigured_HonorsOperatorValue()
    {
        var opts = RenderedMetadataCacheOptions.Resolve(Config(new Dictionary<string, string?>
        {
            ["METADATA_PROXY_CACHE_TTL_SECONDS"] = "15",
        }));

        Assert.Equal(TimeSpan.FromSeconds(RenderedMetadataCacheOptions.DefaultLocalTtlSeconds), opts.LocalTtl);
        Assert.Equal(TimeSpan.FromSeconds(15), opts.ProxyTtl);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-5")]
    [InlineData("not-a-number")]
    public void Resolve_NonPositiveOrUnparseableLocalTtl_FallsBackToDefault_DoesNotDisableCache(string raw)
    {
        // A non-positive or garbage value must not silently disable the cache (TimeSpan.Zero
        // would do that in the downstream GetOrRebuildAsync/Set call sites) — fall back to the
        // documented default instead.
        var opts = RenderedMetadataCacheOptions.Resolve(Config(new Dictionary<string, string?>
        {
            ["METADATA_LOCAL_CACHE_TTL_SECONDS"] = raw,
        }));

        Assert.Equal(TimeSpan.FromSeconds(RenderedMetadataCacheOptions.DefaultLocalTtlSeconds), opts.LocalTtl);
    }

    [Fact]
    public void Resolve_BothConfigured_HonorsBothIndependently()
    {
        var opts = RenderedMetadataCacheOptions.Resolve(Config(new Dictionary<string, string?>
        {
            ["METADATA_LOCAL_CACHE_TTL_SECONDS"] = "45",
            ["METADATA_PROXY_CACHE_TTL_SECONDS"] = "10",
        }));

        Assert.Equal(TimeSpan.FromSeconds(45), opts.LocalTtl);
        Assert.Equal(TimeSpan.FromSeconds(10), opts.ProxyTtl);
    }
}
