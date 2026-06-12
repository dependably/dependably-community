using Dependably.Infrastructure;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class AirGapModeTests
{
    private static AirGapMode Build(string? airGapped, string? disableJobs = null, string? osvMode = null)
    {
        var dict = new Dictionary<string, string?>
        {
            ["AIR_GAPPED"] = airGapped,
            ["DISABLE_BACKGROUND_JOBS"] = disableJobs,
            ["OSV_MODE"] = osvMode,
        };
        var cfg = new ConfigurationBuilder().AddInMemoryCollection(dict).Build();
        return new AirGapMode(cfg);
    }

    // ── IsEnabled ────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("true")]
    [InlineData("True")]
    [InlineData("TRUE")]
    [InlineData("1")]
    public void TrueValues_Enabled(string v) => Assert.True(Build(v).IsEnabled);

    [Theory]
    [InlineData("false")]
    [InlineData("0")]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("yes")]      // only the documented values count as on
    [InlineData("on")]
    public void FalseOrUnknownValues_NotEnabled(string? v) => Assert.False(Build(v).IsEnabled);

    // ── DisabledJobs parsing ─────────────────────────────────────────────────────

    [Fact]
    public void DisabledJobs_EmptyString_ParsesAsEmpty()
    {
        var mode = Build(null, "");
        Assert.Empty(mode.DisabledJobs);
    }

    [Fact]
    public void DisabledJobs_NullVar_ParsesAsEmpty()
    {
        var mode = Build(null, null);
        Assert.Empty(mode.DisabledJobs);
    }

    [Fact]
    public void DisabledJobs_SingleKnownJob_Parsed()
    {
        var mode = Build(null, "vuln-scan");
        Assert.Contains("vuln-scan", mode.DisabledJobs);
        Assert.Single(mode.DisabledJobs);
    }

    [Fact]
    public void DisabledJobs_MultipleKnownJobs_AllParsed()
    {
        var mode = Build(null, "vuln-scan,vuln-rescan,deprecation-refresh");
        Assert.Equal(3, mode.DisabledJobs.Count);
        Assert.Contains("vuln-scan", mode.DisabledJobs);
        Assert.Contains("vuln-rescan", mode.DisabledJobs);
        Assert.Contains("deprecation-refresh", mode.DisabledJobs);
    }

    [Fact]
    public void DisabledJobs_SpacesAroundCommas_Trimmed()
    {
        var mode = Build(null, " vuln-scan , vuln-rescan ");
        Assert.Contains("vuln-scan", mode.DisabledJobs);
        Assert.Contains("vuln-rescan", mode.DisabledJobs);
    }

    [Fact]
    public void DisabledJobs_CaseInsensitiveLookup()
    {
        var mode = Build(null, "VULN-SCAN");
        Assert.True(mode.IsJobDisabled("vuln-scan"));
    }

    [Fact]
    public void DisabledJobs_UnknownJobName_StillAddedToSet()
    {
        // Unknown names are still added to DisabledJobs (with a logged warning).
        // The set is case-insensitive so the lookup works regardless.
        var mode = Build(null, "not-a-real-job");
        Assert.Contains("not-a-real-job", mode.DisabledJobs);
    }

    // ── IsJobDisabled ─────────────────────────────────────────────────────────────

    [Fact]
    public void IsJobDisabled_AirGapEnabled_AllJobsDisabled()
    {
        var mode = Build("true");
        Assert.True(mode.IsJobDisabled("vuln-scan"));
        Assert.True(mode.IsJobDisabled("vuln-rescan"));
        Assert.True(mode.IsJobDisabled("deprecation-refresh"));
        Assert.True(mode.IsJobDisabled("cache-eviction"));
        Assert.True(mode.IsJobDisabled("retention"));
    }

    [Fact]
    public void IsJobDisabled_AirGapDisabled_JobNotInList_ReturnsFalse()
    {
        var mode = Build(null, "vuln-scan");
        Assert.False(mode.IsJobDisabled("cache-eviction"));
    }

    [Fact]
    public void IsJobDisabled_AirGapDisabled_JobInList_ReturnsTrue()
    {
        var mode = Build(null, "cache-eviction,retention");
        Assert.True(mode.IsJobDisabled("cache-eviction"));
        Assert.True(mode.IsJobDisabled("retention"));
        Assert.False(mode.IsJobDisabled("vuln-scan"));
    }

    [Fact]
    public void IsJobDisabled_NeitherAirGapNorList_AllEnabled()
    {
        var mode = Build(null, null);
        Assert.False(mode.IsJobDisabled("vuln-scan"));
        Assert.False(mode.IsJobDisabled("deprecation-refresh"));
        Assert.False(mode.IsJobDisabled("cache-eviction"));
    }

    [Fact]
    public void IsJobDisabled_AirGapPlusDisableList_AirGapWins()
    {
        // Even if a job is NOT in DisabledJobs, IsEnabled=true makes all jobs disabled.
        var mode = Build("true", "vuln-scan");
        Assert.True(mode.IsJobDisabled("cache-eviction"));
    }
}
