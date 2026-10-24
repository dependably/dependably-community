using Dependably.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

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

    private static (AirGapMode Mode, List<string> Warnings) BuildWithWarningCapture(string? disableJobs)
    {
        var dict = new Dictionary<string, string?>
        {
            ["AIR_GAPPED"] = null,
            ["DISABLE_BACKGROUND_JOBS"] = disableJobs,
            ["OSV_MODE"] = null,
        };
        var cfg = new ConfigurationBuilder().AddInMemoryCollection(dict).Build();
        var warnings = new List<string>();
        var logger = new CapturingLogger(warnings);
        return (new AirGapMode(cfg, logger), warnings);
    }

    // Minimal logger that captures only Warning-level messages.
    private sealed class CapturingLogger(List<string> sink) : ILogger<AirGapMode>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => level >= LogLevel.Warning;
        public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? ex, Func<TState, Exception?, string> formatter)
        {
            if (level >= LogLevel.Warning)
            {
                sink.Add(formatter(state, ex));
            }
        }
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
    public void FalseOrUnknownAirGapValues_NotEnabled(string? v) => Assert.False(Build(v).IsEnabled);

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

    // ── Whole-set switch ─────────────────────────────────────────────────────────

    [Theory]
    [InlineData("true")]
    [InlineData("True")]
    [InlineData("TRUE")]
    [InlineData("1")]
    [InlineData("all")]
    [InlineData("ALL")]
    [InlineData(" true ")]
    public void WholeSetValue_DisablesEveryKnownJobExceptHousekeeping(string value)
    {
        var mode = Build(null, value);

        foreach (string job in BackgroundJobs.Known)
        {
            bool housekeeping = job is "cache-eviction" or "oci-staging-janitor" or "npm-manifest-rescan";
            Assert.True(housekeeping != mode.IsJobDisabled(job),
                $"DISABLE_BACKGROUND_JOBS={value}: '{job}' disabled={mode.IsJobDisabled(job)}");
        }

        Assert.False(mode.IsEnabled);
    }

    [Fact]
    public void HousekeepingExemption_IsExactlyTheLocalJobs()
    {
        // Pinned so widening the exemption (which would leave a job running under the whole-set
        // switch and AIR_GAPPED) is a deliberate, reviewed change.
        Assert.Equal(
            new[] { "cache-eviction", "npm-manifest-rescan", "oci-staging-janitor" },
            BackgroundJobs.HousekeepingExemptFromWholeSet.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void WholeSetValue_DisablesAJobNameOutsideTheRegistryToo()
    {
        // A job that forgot to register in BackgroundJobs.Known is still off: the whole-set switch
        // means "no background job runs", not "every job this build happened to list".
        var mode = Build(null, "true");
        Assert.True(mode.IsJobDisabled("a-job-added-later"));
    }

    [Theory]
    [InlineData("false")]
    [InlineData("FALSE")]
    [InlineData("0")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void OffValue_DisablesNoJob(string? value)
    {
        var mode = Build(null, value);

        foreach (string job in BackgroundJobs.Known)
        {
            Assert.False(mode.IsJobDisabled(job), $"DISABLE_BACKGROUND_JOBS='{value}' must leave '{job}' running");
        }

        Assert.Empty(mode.DisabledJobs);
    }

    [Fact]
    public void NamedList_DisablesOnlyTheNamedJobs()
    {
        // Twin of the whole-set test: a list keeps its per-name meaning and does not spill over.
        var mode = Build(null, "vuln-scan,threat-feed");

        foreach (string job in BackgroundJobs.Known)
        {
            bool expected = job is "vuln-scan" or "threat-feed";
            Assert.Equal(expected, mode.IsJobDisabled(job));
        }
    }

    // ── Unrecognised values fail closed ──────────────────────────────────────────

    [Theory]
    [InlineData("not-a-real-job")]
    [InlineData("vuln-scan,not-a-real-job")]
    [InlineData("vulnscan")]          // a typo of a real name
    [InlineData("yes")]               // a boolean spelling the switch does not accept
    [InlineData("on")]
    [InlineData("none")]
    public void UnknownToken_FailsConstruction_NamingTheTokenAndTheKnownNames(string value)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => Build(null, value));

        string bad = value.Split(',').Select(t => t.Trim()).First(t => !BackgroundJobs.Known.Contains(t));
        Assert.Contains($"'{bad}'", ex.Message);
        Assert.Contains("DISABLE_BACKGROUND_JOBS", ex.Message);
        foreach (string job in BackgroundJobs.Known)
        {
            Assert.Contains(job, ex.Message);
        }
    }

    [Theory]
    [InlineData("true,vuln-scan")]
    [InlineData("vuln-scan,TRUE")]
    [InlineData("all,threat-feed")]
    [InlineData("1,retention")]
    [InlineData("false,vuln-scan")]
    [InlineData("0,vuln-scan")]
    [InlineData("true,false")]
    public void SwitchValueInsideAList_FailsConstruction(string value)
    {
        // true/1/all and false/0 switch the whole job set; inside a list their meaning is
        // ambiguous ("everything" or "this name"?), so the value is refused rather than guessed.
        var ex = Assert.Throws<InvalidOperationException>(() => Build(null, value));
        Assert.Contains("DISABLE_BACKGROUND_JOBS", ex.Message);
        Assert.Contains("on its own", ex.Message);
    }

    [Fact]
    public void NoKnownJobNameCollidesWithASwitchValue()
    {
        // A job named "all" (or "true") would make the whole-set switch and the job name
        // indistinguishable; the registry must never contain one.
        foreach (string reserved in new[] { "true", "1", "all", "false", "0" })
        {
            Assert.DoesNotContain(reserved, BackgroundJobs.Known);
        }
    }

    [Fact]
    public void DisabledJobs_ThreatFeed_IsKnownName_NoWarning()
    {
        // "threat-feed" is the job name used by ThreatFeedRefreshService. It must be
        // in KnownJobNames so that DISABLE_BACKGROUND_JOBS=threat-feed does not emit
        // a spurious "unknown job name" warning.
        var (mode, warnings) = BuildWithWarningCapture("threat-feed");
        Assert.Contains("threat-feed", mode.DisabledJobs);
        Assert.DoesNotContain(warnings, w => w.Contains("unknown job name", StringComparison.OrdinalIgnoreCase));
    }

    // ── IsJobDisabled ─────────────────────────────────────────────────────────────

    [Fact]
    public void IsJobDisabled_AirGapEnabled_AllJobsDisabledExceptHousekeeping()
    {
        var mode = Build("true");
        Assert.True(mode.IsJobDisabled("vuln-scan"));
        Assert.True(mode.IsJobDisabled("vuln-rescan"));
        Assert.True(mode.IsJobDisabled("deprecation-refresh"));
        Assert.True(mode.IsJobDisabled("retention"));
        Assert.False(mode.IsJobDisabled("cache-eviction"));
        Assert.False(mode.IsJobDisabled("oci-staging-janitor"));
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
        // Even if a job is NOT in DisabledJobs, IsEnabled=true disables it (housekeeping aside).
        var mode = Build("true", "vuln-scan");
        Assert.True(mode.IsJobDisabled("retention"));
    }

    [Fact]
    public void AirGapExemption_IsExactlyTheDatabaseOnlyScanSweep()
    {
        // Pinned so leaving another job running under AIR_GAPPED is a deliberate, reviewed change.
        Assert.Equal(new[] { "oci-scan-sweep" }, BackgroundJobs.AirGapExempt.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void IsJobDisabled_AirGapLeavesTheScanSweepRunning_ButEveryOtherSwitchStopsIt()
    {
        Assert.False(Build("true").IsJobDisabled("oci-scan-sweep"));
        Assert.Null(BackgroundJobDisabledReason.For(Build("true"), "oci-scan-sweep"));

        Assert.True(Build(null, "true").IsJobDisabled("oci-scan-sweep"));
        Assert.Equal(BackgroundJobDisabledReason.AllJobs, BackgroundJobDisabledReason.For(Build(null, "true"), "oci-scan-sweep"));
        Assert.Equal(BackgroundJobDisabledReason.AllJobs, BackgroundJobDisabledReason.For(Build("true", "true"), "oci-scan-sweep"));

        Assert.True(Build("true", "oci-scan-sweep").IsJobDisabled("oci-scan-sweep"));
        Assert.Equal(BackgroundJobDisabledReason.Named, BackgroundJobDisabledReason.For(Build("true", "oci-scan-sweep"), "oci-scan-sweep"));

        var edge = new AirGapMode(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["AIR_GAPPED"] = "true", ["DEPLOYMENT_MODE"] = "edge" })
            .Build());
        Assert.True(edge.IsJobDisabled("oci-scan-sweep"));
        Assert.Equal(BackgroundJobDisabledReason.Edge, BackgroundJobDisabledReason.For(edge, "oci-scan-sweep"));

        // The exemption is the sweep's alone: every other non-housekeeping job still reports air-gap.
        Assert.Equal(BackgroundJobDisabledReason.AirGapped, BackgroundJobDisabledReason.For(Build("true"), "oci-blob-sweep"));
    }

    [Fact]
    public void IsJobDisabled_AirGapPlusNamedHousekeepingJob_NamedEntryStopsIt()
    {
        var mode = Build("true", "cache-eviction");
        Assert.True(mode.IsJobDisabled("cache-eviction"));
        Assert.False(mode.IsJobDisabled("oci-staging-janitor"));
    }
}
