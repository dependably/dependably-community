using Dependably.Infrastructure;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Resolution of the shared staging path + disk floor. Both UpstreamClient and the
/// staging-disk machinery read these resolved values, so the parse rules (path fallback
/// to temp; floor &gt;=0 kept incl. explicit-0 opt-out, negative/unparseable → 512 MiB)
/// are locked down here.
/// </summary>
[Trait("Category", "Unit")]
public sealed class StagingOptionsTests
{
    private static IConfiguration Config(params (string Key, string? Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries.ToDictionary(e => e.Key, e => e.Value))
            .Build();

    [Fact]
    public void Resolve_ProxyStagingPathSet_UsesConfiguredPath()
    {
        var options = StagingOptions.Resolve(Config(("PROXY_STAGING_PATH", "/data/staging")));
        Assert.Equal("/data/staging", options.Path);
    }

    [Fact]
    public void Resolve_ProxyStagingPathUnset_FallsBackToTempDir()
    {
        var options = StagingOptions.Resolve(Config());
        Assert.Equal(Path.GetTempPath(), options.Path);
    }

    [Fact]
    public void Resolve_ProxyStagingPathWhitespace_FallsBackToTempDir()
    {
        var options = StagingOptions.Resolve(Config(("PROXY_STAGING_PATH", "   ")));
        Assert.Equal(Path.GetTempPath(), options.Path);
    }

    [Fact]
    public void Resolve_FloorExplicitZero_KeepsZeroOptOut()
    {
        var options = StagingOptions.Resolve(Config(("STAGING_DISK_FLOOR_BYTES", "0")));
        Assert.Equal(0L, options.FloorBytes);
    }

    [Fact]
    public void Resolve_FloorPositive_UsesConfiguredValue()
    {
        var options = StagingOptions.Resolve(Config(("STAGING_DISK_FLOOR_BYTES", "1048576")));
        Assert.Equal(1048576L, options.FloorBytes);
    }

    [Fact]
    public void Resolve_FloorNegative_FallsBackToDefault()
    {
        var options = StagingOptions.Resolve(Config(("STAGING_DISK_FLOOR_BYTES", "-1")));
        Assert.Equal(StagingOptions.DefaultFloorBytes, options.FloorBytes);
    }

    [Fact]
    public void Resolve_FloorUnparseable_FallsBackToDefault()
    {
        var options = StagingOptions.Resolve(Config(("STAGING_DISK_FLOOR_BYTES", "not-a-number")));
        Assert.Equal(StagingOptions.DefaultFloorBytes, options.FloorBytes);
    }

    [Fact]
    public void Resolve_FloorUnset_FallsBackToDefault()
    {
        var options = StagingOptions.Resolve(Config());
        Assert.Equal(StagingOptions.DefaultFloorBytes, options.FloorBytes);
        Assert.Equal(512L * 1024 * 1024, options.FloorBytes);
    }
}
