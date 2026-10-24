using Dependably.Infrastructure;
using Dependably.Infrastructure.Startup;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class DisableBackgroundJobsSettingTests
{
    private static AirGapMode Mode(string? disableJobs, string? airGapped = null, string? deploymentMode = null) =>
        new(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["DISABLE_BACKGROUND_JOBS"] = disableJobs,
            ["AIR_GAPPED"] = airGapped,
            ["DEPLOYMENT_MODE"] = deploymentMode,
        }).Build());

    // ── Parser ───────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("true")]
    [InlineData("TRUE")]
    [InlineData("1")]
    [InlineData("all")]
    [InlineData("All")]
    public void WholeSetValues_ParseAsAllJobs(string value)
    {
        var parsed = DisableBackgroundJobsSetting.Parse(value);
        Assert.True(parsed.AllJobs);
        Assert.Equal(
            BackgroundJobs.Known.Except(["cache-eviction", "oci-staging-janitor", "npm-manifest-rescan"]).Order(),
            parsed.Names.Order());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    [InlineData(",")]
    [InlineData("false")]
    [InlineData("False")]
    [InlineData("0")]
    public void OffValues_ParseAsNothingDisabled(string? value)
    {
        var parsed = DisableBackgroundJobsSetting.Parse(value);
        Assert.False(parsed.AllJobs);
        Assert.Empty(parsed.Names);
    }

    [Fact]
    public void NamedList_ParsesOnlyThoseNames()
    {
        var parsed = DisableBackgroundJobsSetting.Parse(" Vuln-Scan , threat-feed,,");
        Assert.False(parsed.AllJobs);
        Assert.Equal(2, parsed.Names.Count);
        Assert.Contains("vuln-scan", parsed.Names);
        Assert.Contains("threat-feed", parsed.Names);
    }

    [Fact]
    public void EveryKnownName_ParsesAsAList()
    {
        // The full list spelled out is still a list, not the whole-set switch: existing
        // deployments that enumerate every job keep their exact meaning.
        string all = string.Join(",", BackgroundJobs.Known);
        var parsed = DisableBackgroundJobsSetting.Parse(all);
        Assert.False(parsed.AllJobs);
        Assert.Equal(BackgroundJobs.Known.Count, parsed.Names.Count);
    }

    [Fact]
    public void UnknownName_ErrorNamesTheTokenAndEveryKnownName()
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => DisableBackgroundJobsSetting.Parse("vuln-scan,kev-feed"));

        Assert.Contains("unknown job name 'kev-feed'", ex.Message, StringComparison.Ordinal);
        foreach (string job in BackgroundJobs.Known)
        {
            Assert.Contains(job, ex.Message, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("true,vuln-scan", "true")]
    [InlineData("vuln-scan, ALL", "ALL")]
    [InlineData("0,threat-feed", "0")]
    public void SwitchValueInList_ErrorNamesTheToken(string value, string token)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => DisableBackgroundJobsSetting.Parse(value));
        Assert.Contains($"contains '{token}' inside a list", ex.Message, StringComparison.Ordinal);
    }

    // ── Startup ──────────────────────────────────────────────────────────────────

    // The regression the fail-closed parse exists for: an unrecognised value used to log a
    // warning and boot with every job running.
    [Fact]
    public void Startup_UnknownValue_FailsBoot()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration["DISABLE_BACKGROUND_JOBS"] = "vuln-scna";

        var ex = Assert.Throws<InvalidOperationException>(() => builder.AddDependablyBackgroundServices());
        Assert.Contains("'vuln-scna'", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("true")]
    [InlineData("false")]
    [InlineData("vuln-scan,vuln-rescan,sbom-scan,threat-feed,deprecation-refresh,license-backfill,oci-blob-sweep")]
    public void Startup_RecognisedValue_Registers(string? value)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration["DISABLE_BACKGROUND_JOBS"] = value;

        var ex = Record.Exception(() => builder.AddDependablyBackgroundServices());

        Assert.Null(ex);
    }

    // ── Instance report ──────────────────────────────────────────────────────────

    [Fact]
    public void Reason_WholeSetSwitch_IsReportedDistinctlyFromANamedList()
    {
        var all = Mode("true");
        var named = Mode("vuln-scan");

        Assert.True(all.DisablesAllJobs);
        Assert.False(named.DisablesAllJobs);
        Assert.Equal("DISABLE_BACKGROUND_JOBS=true", BackgroundJobDisabledReason.For(all, "vuln-scan"));
        Assert.Equal("DISABLE_BACKGROUND_JOBS=true", BackgroundJobDisabledReason.For(all, "retention"));
        Assert.Equal("DISABLE_BACKGROUND_JOBS", BackgroundJobDisabledReason.For(named, "vuln-scan"));
        Assert.Null(BackgroundJobDisabledReason.For(named, "retention"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("false")]
    [InlineData("0")]
    public void Reason_OffValue_ReportsEveryJobRunning(string? value)
    {
        var mode = Mode(value);
        Assert.False(mode.DisablesAllJobs);
        foreach (string job in BackgroundJobs.Known)
        {
            Assert.Null(BackgroundJobDisabledReason.For(mode, job));
        }
    }

    [Fact]
    public void Reason_AirGapTakesPrecedenceOverTheSwitch()
    {
        var mode = Mode("true", airGapped: "true");
        Assert.Equal("AIR_GAPPED=true", BackgroundJobDisabledReason.For(mode, "vuln-scan"));
    }

    [Fact]
    public void Reason_EdgeForcedDisable_IsNotAttributedToTheSwitch()
    {
        var mode = Mode(null, deploymentMode: "edge");
        Assert.Equal("DEPLOYMENT_MODE=edge", BackgroundJobDisabledReason.For(mode, "vuln-scan"));
        Assert.Null(BackgroundJobDisabledReason.For(mode, "cache-eviction"));

        var switched = Mode("true", deploymentMode: "edge");
        Assert.Equal("DISABLE_BACKGROUND_JOBS=true", BackgroundJobDisabledReason.For(switched, "healthcheck-pinger"));
        Assert.Null(BackgroundJobDisabledReason.For(switched, "cache-eviction"));
    }

    [Theory]
    [InlineData("true", null)]
    [InlineData(null, "true")]
    public void Reason_HousekeepingJobs_RunUnderTheWholeSetSwitchAndAirGap(string? disableJobs, string? airGapped)
    {
        var mode = Mode(disableJobs, airGapped: airGapped);
        Assert.Null(BackgroundJobDisabledReason.For(mode, "cache-eviction"));
        Assert.Null(BackgroundJobDisabledReason.For(mode, "oci-staging-janitor"));
    }

    [Fact]
    public void Reason_NamedHousekeepingJobUnderAirGap_IsAttributedToTheList()
    {
        // AIR_GAPPED alone leaves eviction running, so the stop belongs to the named entry.
        var mode = Mode("cache-eviction", airGapped: "true");
        Assert.Equal("DISABLE_BACKGROUND_JOBS", BackgroundJobDisabledReason.For(mode, "cache-eviction"));
        Assert.Equal("AIR_GAPPED=true", BackgroundJobDisabledReason.For(mode, "retention"));
    }
}
