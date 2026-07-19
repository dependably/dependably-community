using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Unit coverage for the OSV → npm advisory projection: severity band mapping, affected-interval
/// containment, and <c>vulnerable_versions</c> range rendering.
///
/// The interval work carries the correctness risk. OSV's <c>fixed</c> event is an <b>exclusive</b>
/// upper bound, so an off-by-one there reports already-patched versions as vulnerable;
/// <c>last_affected</c> is <b>inclusive</b> and is the opposite trap.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NpmAdvisoryProjectionTests
{
    // ── severity mapping ─────────────────────────────────────────────────────

    /// <summary>
    /// OSV's CVSS bands map onto npm's vocabulary (info|low|moderate|high|critical). MEDIUM is
    /// npm's "moderate" — the one band whose name differs.
    /// </summary>
    [Theory]
    [InlineData("CRITICAL", "critical")]
    [InlineData("HIGH", "high")]
    [InlineData("MEDIUM", "moderate")]
    [InlineData("LOW", "low")]
    [InlineData("NONE", "info")]
    public void Severity_MapsOsvBandToNpmVocabulary(string osvBand, string expected) =>
        Assert.Equal(expected, NpmAdvisoryProjection.Severity(Advisory("GHSA-x", severity: osvBand)));

    /// <summary>
    /// An advisory OSV could not score is "info", never "low". It must land inside npm's
    /// vocabulary: npm-audit-report's exit-code table ignores any severity outside that set, so an
    /// invented label like "unscored" would silently drop out of audit gating entirely.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("SOMETHING-ELSE")]
    public void Severity_UnscoredIsInfoNotLow(string? severity)
    {
        string mapped = NpmAdvisoryProjection.Severity(Advisory("GHSA-x", severity: severity));

        Assert.Equal("info", mapped);
        Assert.NotEqual("low", mapped);
    }

    /// <summary>
    /// Malicious-package reports carry no CVSS by design but are the highest-signal finding OSV
    /// emits — the block gate already treats them independently of any score. They project to
    /// critical rather than falling into the unscored "info" bucket.
    /// </summary>
    [Fact]
    public void Severity_MaliciousPackageIsCriticalDespiteNoScore() =>
        Assert.Equal("critical", NpmAdvisoryProjection.Severity(Advisory("MAL-2024-1234", severity: null)));

    // ── interval containment ─────────────────────────────────────────────────

    /// <summary>
    /// [4.0.0, 4.17.21): everything from the introduced version up to — but excluding — the fix.
    /// 4.17.21 itself is patched; 3.9.9 predates the introduction.
    /// </summary>
    [Theory]
    [InlineData("4.0.0", true)]     // exactly at introduced — inclusive lower bound
    [InlineData("4.17.20", true)]   // inside
    [InlineData("4.17.21", false)]  // exactly at fixed — exclusive upper bound
    [InlineData("4.17.22", false)]  // past the fix
    [InlineData("3.9.9", false)]    // before introduced
    public void Affects_HalfOpenFixedInterval(string version, bool expected)
    {
        var detail = Detail("""
            { "affected": [ { "package": { "ecosystem": "npm", "name": "lodash" },
              "ranges": [ { "type": "SEMVER",
                "events": [ { "introduced": "4.0.0" }, { "fixed": "4.17.21" } ] } ] } ] }
            """);

        Assert.Equal(expected, NpmAdvisoryProjection.Affects(detail, "lodash", version));
    }

    /// <summary>
    /// last_affected is inclusive — the mirror image of fixed. Getting these two the same way
    /// round is exactly the off-by-one that misreports a boundary version.
    /// </summary>
    [Theory]
    [InlineData("1.5.0", true)]   // exactly at last_affected — inclusive
    [InlineData("1.4.9", true)]
    [InlineData("1.5.1", false)]
    public void Affects_ClosedLastAffectedInterval(string version, bool expected)
    {
        var detail = Detail("""
            { "affected": [ { "package": { "ecosystem": "npm", "name": "pkg" },
              "ranges": [ { "type": "SEMVER",
                "events": [ { "introduced": "1.0.0" }, { "last_affected": "1.5.0" } ] } ] } ] }
            """);

        Assert.Equal(expected, NpmAdvisoryProjection.Affects(detail, "pkg", version));
    }

    /// <summary>An interval left open by a trailing introduced runs to every later version.</summary>
    [Theory]
    [InlineData("0.9.0", false)]
    [InlineData("2.0.0", true)]
    [InlineData("99.0.0", true)]
    public void Affects_OpenEndedInterval(string version, bool expected)
    {
        var detail = Detail("""
            { "affected": [ { "package": { "ecosystem": "npm", "name": "pkg" },
              "ranges": [ { "type": "SEMVER", "events": [ { "introduced": "2.0.0" } ] } ] } ] }
            """);

        Assert.Equal(expected, NpmAdvisoryProjection.Affects(detail, "pkg", version));
    }

    /// <summary>Multiple disjoint intervals: a version in the gap between them is unaffected.</summary>
    [Theory]
    [InlineData("1.0.5", true)]
    [InlineData("1.5.0", false)]  // in the gap: fixed at 1.1.0, reintroduced at 2.0.0
    [InlineData("2.0.1", true)]
    [InlineData("2.1.0", false)]
    public void Affects_MultipleDisjointIntervals(string version, bool expected)
    {
        var detail = Detail("""
            { "affected": [ { "package": { "ecosystem": "npm", "name": "pkg" },
              "ranges": [ { "type": "SEMVER", "events": [
                { "introduced": "1.0.0" }, { "fixed": "1.1.0" },
                { "introduced": "2.0.0" }, { "fixed": "2.1.0" } ] } ] } ] }
            """);

        Assert.Equal(expected, NpmAdvisoryProjection.Affects(detail, "pkg", version));
    }

    /// <summary>OSV also enumerates exact affected versions; a version outside the list is clean.</summary>
    [Theory]
    [InlineData("1.0.0", true)]
    [InlineData("1.0.2", true)]
    [InlineData("1.0.1", false)]
    public void Affects_EnumeratedVersionsList(string version, bool expected)
    {
        var detail = Detail("""
            { "affected": [ { "package": { "ecosystem": "npm", "name": "pkg" },
              "versions": [ "1.0.0", "1.0.2" ] } ] }
            """);

        Assert.Equal(expected, NpmAdvisoryProjection.Affects(detail, "pkg", version));
    }

    /// <summary>
    /// GIT ranges hold commit hashes, never package versions. They are skipped — and because
    /// skipping leaves no usable interval data, the advisory falls back to the source's verdict
    /// rather than being silently dropped.
    /// </summary>
    [Fact]
    public void Affects_GitRangeIsNotVersionComparedAndFallsBackToReporting()
    {
        var detail = Detail("""
            { "affected": [ { "package": { "ecosystem": "npm", "name": "pkg" },
              "ranges": [ { "type": "GIT", "repo": "https://example.test/pkg",
                "events": [ { "introduced": "abc123" }, { "fixed": "def456" } ] } ] } ] }
            """);

        Assert.True(NpmAdvisoryProjection.Affects(detail, "pkg", "1.0.0"));
    }

    /// <summary>
    /// Fail-safe, never fail-open: an advisory with no parseable detail carries no interval data,
    /// so the querying source's verdict stands and it stays in the report.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("{ not json")]
    public void Affects_NoUsableDetailDefersToSource(string? rawJson) =>
        Assert.True(NpmAdvisoryProjection.Affects(
            NpmAdvisoryProjection.TryParseDetail(rawJson), "pkg", "1.0.0"));

    // ── vulnerable_versions rendering ────────────────────────────────────────

    [Fact]
    public void VulnerableVersions_RendersHalfOpenInterval()
    {
        var detail = Detail("""
            { "affected": [ { "package": { "ecosystem": "npm", "name": "pkg" },
              "ranges": [ { "type": "SEMVER",
                "events": [ { "introduced": "4.0.0" }, { "fixed": "4.17.21" } ] } ] } ] }
            """);

        Assert.Equal(">=4.0.0 <4.17.21", NpmAdvisoryProjection.VulnerableVersions(detail, "pkg", []));
    }

    /// <summary>introduced:"0" means "since the first release" — it renders as no lower bound.</summary>
    [Fact]
    public void VulnerableVersions_IntroducedZeroRendersUpperBoundOnly()
    {
        var detail = Detail("""
            { "affected": [ { "package": { "ecosystem": "npm", "name": "pkg" },
              "ranges": [ { "type": "SEMVER",
                "events": [ { "introduced": "0" }, { "fixed": "2.0.0" } ] } ] } ] }
            """);

        Assert.Equal("<2.0.0", NpmAdvisoryProjection.VulnerableVersions(detail, "pkg", []));
    }

    [Fact]
    public void VulnerableVersions_LastAffectedRendersInclusiveUpperBound()
    {
        var detail = Detail("""
            { "affected": [ { "package": { "ecosystem": "npm", "name": "pkg" },
              "ranges": [ { "type": "SEMVER",
                "events": [ { "introduced": "1.0.0" }, { "last_affected": "1.5.0" } ] } ] } ] }
            """);

        Assert.Equal(">=1.0.0 <=1.5.0", NpmAdvisoryProjection.VulnerableVersions(detail, "pkg", []));
    }

    [Fact]
    public void VulnerableVersions_JoinsMultipleIntervalsWithOr()
    {
        var detail = Detail("""
            { "affected": [ { "package": { "ecosystem": "npm", "name": "pkg" },
              "ranges": [ { "type": "SEMVER", "events": [
                { "introduced": "1.0.0" }, { "fixed": "1.1.0" },
                { "introduced": "2.0.0" }, { "fixed": "2.1.0" } ] } ] } ] }
            """);

        Assert.Equal(
            ">=1.0.0 <1.1.0 || >=2.0.0 <2.1.0",
            NpmAdvisoryProjection.VulnerableVersions(detail, "pkg", []));
    }

    /// <summary>An entry with only an enumerated versions[] pins those exact versions.</summary>
    [Fact]
    public void VulnerableVersions_RendersEnumeratedVersionsAsExactList()
    {
        var detail = Detail("""
            { "affected": [ { "package": { "ecosystem": "npm", "name": "pkg" },
              "versions": [ "1.0.0", "1.0.2" ] } ] }
            """);

        Assert.Equal("1.0.0 || 1.0.2", NpmAdvisoryProjection.VulnerableVersions(detail, "pkg", []));
    }

    /// <summary>
    /// The critical fallback: metavuln-calculator coerces a missing or empty
    /// <c>vulnerable_versions</c> to <c>*</c>, marking every version of the package vulnerable. So
    /// when nothing renders from the OSV data, the versions this request already proved affected
    /// are named explicitly — never an empty string.
    /// </summary>
    [Fact]
    public void VulnerableVersions_UnrenderableRangeFallsBackToKnownAffectedVersions()
    {
        var detail = NpmAdvisoryProjection.TryParseDetail("""{ "id": "GHSA-x" }""");

        string range = NpmAdvisoryProjection.VulnerableVersions(detail, "pkg", ["1.2.3", "1.2.4"]);

        Assert.Equal("1.2.3 || 1.2.4", range);
        Assert.NotEmpty(range);
    }

    /// <summary>Never an empty string, even with nothing at all to go on.</summary>
    [Fact]
    public void VulnerableVersions_NothingKnownStillNeverEmpty() =>
        Assert.Equal("*", NpmAdvisoryProjection.VulnerableVersions(null, "pkg", []));

    // ── CWE extraction ───────────────────────────────────────────────────────

    [Fact]
    public void ExtractCweIds_ReadsDatabaseSpecificCweIds()
    {
        var detail = Detail("""{ "database_specific": { "cwe_ids": [ "CWE-79", "CWE-1321" ] } }""");

        Assert.Equal(["CWE-79", "CWE-1321"], NpmAdvisoryProjection.ExtractCweIds(detail!.DatabaseSpecific));
    }

    /// <summary>Absent or malformed CWE data degrades to an empty array, never an error.</summary>
    [Theory]
    [InlineData("""{ "database_specific": { } }""")]
    [InlineData("""{ "database_specific": { "cwe_ids": "not-an-array" } }""")]
    [InlineData("""{ }""")]
    public void ExtractCweIds_MalformedDegradesToEmpty(string rawJson) =>
        Assert.Empty(NpmAdvisoryProjection.ExtractCweIds(Detail(rawJson)?.DatabaseSpecific));

    // ── helpers ──────────────────────────────────────────────────────────────

    private static Dependably.Infrastructure.OsvDetail? Detail(string rawJson) =>
        NpmAdvisoryProjection.TryParseDetail(rawJson);

    private static OsvAdvisory Advisory(string id, string? severity) =>
        new(
            Id: id,
            Aliases: [],
            Summary: "summary",
            Severity: severity,
            CvssScore: null,
            AffectedPackages: [],
            Published: null,
            Modified: null,
            IsHydrated: true,
            RawJson: null);
}
