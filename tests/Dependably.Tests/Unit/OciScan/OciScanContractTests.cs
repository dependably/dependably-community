using System.Text.Json;
using Dependably.Infrastructure.OciScan;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.OciScan;

/// <summary>
/// The scan API's contract with a scanner: who may hold <c>scan:oci</c>, how settings parse, how
/// a posted OSV record becomes an advisory, and which result bodies are refused whole.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciScanContractTests
{
    private const string DsaRecord = """
        {
          "id": "DSA-5000-1",
          "aliases": ["CVE-2026-0001"],
          "summary": "openssl issue",
          "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
          "affected": [{ "package": { "ecosystem": "Debian:12", "name": "openssl" }, "versions": ["3.0.11-1~deb12u1"] }]
        }
        """;

    // ── scan:oci ─────────────────────────────────────────────────────────────────

    [Fact]
    public void ScanOci_IsRequestable_AndHeldByAdminAndOwnerOnly()
    {
        Assert.Contains(Capabilities.ScanOci, Capabilities.Requestable);
        Assert.Contains(Capabilities.ScanOci, Capabilities.ForRole("admin"));
        Assert.Contains(Capabilities.ScanOci, Capabilities.ForRole("owner"));
        Assert.DoesNotContain(Capabilities.ScanOci, Capabilities.ForRole("member"));
        Assert.DoesNotContain(Capabilities.ScanOci, Capabilities.ForRole("auditor"));
    }

    [Theory]
    [InlineData("member", false)]
    [InlineData("auditor", false)]
    [InlineData("admin", true)]
    public void OnlyAnAdminCanMintAScannerToken(string role, bool allowed)
    {
        bool ok = Capabilities.TryNormalizeAndAuthorize(
            [Capabilities.ScanOci], Capabilities.ForRole(role), out _, out _, out _, out _);
        Assert.Equal(allowed, ok);
    }

    // ── Settings ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Options_DefaultToOff()
    {
        var options = OciScanOptions.FromConfiguration(new ConfigurationBuilder().Build());
        Assert.False(options.Enabled);
        Assert.Equal(TimeSpan.FromMinutes(10), options.HeartbeatWindow);
        Assert.Equal(TimeSpan.FromMinutes(15), options.Lease);
        Assert.Equal(5, options.MaxAttempts);
    }

    [Theory]
    [InlineData("OCI_SCAN_ENABLED", "yes")]
    [InlineData("OCI_SCAN_LEASE", "fifteen minutes")]
    [InlineData("OCI_SCAN_HEARTBEAT_WINDOW", "-00:05:00")]
    [InlineData("OCI_SCAN_MAX_ATTEMPTS", "0")]
    public void Options_RefuseAValueTheyCannotUse(string key, string value)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { [key] = value })
            .Build();
        Assert.Throws<InvalidOperationException>(() => OciScanOptions.FromConfiguration(config));
    }

    // ── OSV records ──────────────────────────────────────────────────────────────

    [Fact]
    public void OsvRecord_ParsesWithTheSameScoringAsOsv()
    {
        var advisory = OsvRecordParser.TryParse(JsonDocument.Parse(DsaRecord).RootElement);

        Assert.NotNull(advisory);
        Assert.Equal("DSA-5000-1", advisory.Id);
        Assert.Equal(["CVE-2026-0001"], advisory.Aliases);
        Assert.Equal(9.8, advisory.CvssScore);
        Assert.True(advisory.IsHydrated);
        Assert.Equal("openssl", Assert.Single(advisory.AffectedPackages).Name);
        Assert.NotNull(advisory.RawJson);
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("""{"summary":"no id"}""")]
    [InlineData("""{"id":"  "}""")]
    [InlineData("""{"id":"X","aliases":"not-a-list"}""")]
    public void OsvRecord_RefusesWhatIsNotARecord(string json)
        => Assert.Null(OsvRecordParser.TryParse(JsonDocument.Parse(json).RootElement));

    // ── Result bodies ────────────────────────────────────────────────────────────

    [Fact]
    public void Result_AWellFormedBodyIsAccepted()
    {
        var (invalid, advisories) = OciScanResultWriter.Validate(Body());
        Assert.Null(invalid);
        Assert.Contains("DSA-5000-1", advisories.Keys);
    }

    [Fact]
    public void Result_AFindingMustCarryItsAdvisoryRecord()
        => AssertInvalid(Body(advisories: []), "vulns", "error.ociScan.vulnUnknown");

    [Fact]
    public void Result_NeedsAtLeastOnePlatform()
        => AssertInvalid(new OciScanResultRequest([], [], null), "platforms", "error.ociScan.platformsRequired");

    [Fact]
    public void Result_PlatformNamesAreDistinct()
    {
        var platform = Platform();
        AssertInvalid(new OciScanResultRequest([platform, platform], [Record()], null), "platforms", "error.ociScan.platformInvalid");
    }

    [Fact]
    public void Result_RefusesAnUnknownReachability()
        => AssertInvalid(Body(reachability: "maybe"), "vulns", "error.ociScan.reachabilityInvalid");

    [Fact]
    public void Result_RefusesAnEmptyGap()
        => AssertInvalid(Body(gaps: [" "]), "gaps", "error.ociScan.gapsInvalid");

    [Fact]
    public void Result_RefusesAComponentWithoutAVersion()
    {
        var component = Component() with { Version = null };
        AssertInvalid(
            new OciScanResultRequest([Platform() with { Components = [component] }], [Record()], null),
            "components", "error.ociScan.componentInvalid");
    }

    [Fact]
    public void Result_ContentGapsMustBeASubsetOfGaps()
    {
        var body = new OciScanResultRequest(
            [Platform(gaps: ["platforms not scanned: linux/s390x"]) with { ContentGaps = ["layer 3: unreadable"] }],
            [Record()], null);
        AssertInvalid(body, "contentGaps", "error.ociScan.contentGapsNotSubset");
    }

    [Fact]
    public void Result_ContentGapsThatAreGapsAreAccepted()
    {
        var body = new OciScanResultRequest(
            [Platform(gaps: ["platforms not scanned: linux/s390x", "vulnerability matching: rpm"])
                with { ContentGaps = ["platforms not scanned: linux/s390x"] }],
            [Record()], null);
        Assert.Null(OciScanResultWriter.Validate(body).Invalid);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("maybe")]
    public void Result_RefusesAComponentVerdictWithoutAKnownStatus(string? status)
    {
        var component = Component() with { Verdict = new OciScanComponentVerdict(status, null, null) };
        AssertInvalid(
            new OciScanResultRequest([Platform() with { Components = [component] }], [Record()], null),
            "verdict", "error.ociScan.verdictInvalid");
    }

    // ── Settings: rescan age ─────────────────────────────────────────────────────

    [Fact]
    public void Options_RescanAgeDefaultsToADay_AndReadsWholeHours()
    {
        Assert.Equal(TimeSpan.FromHours(24), OciScanOptions.FromConfiguration(new ConfigurationBuilder().Build()).RescanAge);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["OCI_SCAN_RESCAN_AGE_HOURS"] = "6" })
            .Build();
        Assert.Equal(TimeSpan.FromHours(6), OciScanOptions.FromConfiguration(config).RescanAge);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-3")]
    [InlineData("1.5")]
    [InlineData("daily")]
    [InlineData("876001")]
    [InlineData("100000000")]
    [InlineData("2147483647")]
    public void Options_RescanAgeRefusesAValueItCannotUse(string value)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["OCI_SCAN_RESCAN_AGE_HOURS"] = value })
            .Build();
        Assert.Throws<InvalidOperationException>(() => OciScanOptions.FromConfiguration(config));
    }

    [Fact]
    public void Options_RescanAgeAcceptsItsCap_AndTheSweepCanSubtractIt()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["OCI_SCAN_RESCAN_AGE_HOURS"] = "876000" })
            .Build();
        var age = OciScanOptions.FromConfiguration(config).RescanAge;
        Assert.Equal(TimeSpan.FromHours(OciScanOptions.MaxRescanAgeHours), age);
        // The sweep's threshold is now minus the age; at the cap that must not overflow.
        _ = TestTime.KnownNow - age;
    }

    // ── Claim kinds ──────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("scan", false)]
    [InlineData("scan,future-kind", false)]
    [InlineData("scan,rematch", true)]
    [InlineData(" rematch ", true)]
    [InlineData("SCAN,REMATCH", true)]
    [InlineData("rematched", false)]
    public void Kinds_OnlyANamedRematchOptsIn(string? kinds, bool expected)
        => Assert.Equal(expected, OciScanKinds.IncludesRematch(kinds));

    // ── Match bodies ─────────────────────────────────────────────────────────────

    [Fact]
    public void Matches_AWellFormedBodyIsAccepted()
    {
        var (invalid, advisories) = OciScanResultWriter.ValidateMatches(MatchBody());
        Assert.Null(invalid);
        Assert.Contains("DSA-5000-1", advisories.Keys);
    }

    [Fact]
    public void Matches_AFindingMustCarryItsAdvisoryRecord()
        => AssertMatchInvalid(MatchBody() with { Advisories = [] }, "vulns", "error.ociScan.vulnUnknown");

    [Fact]
    public void Matches_EachPlatformNeedsItsCoverageId()
        => AssertMatchInvalid(
            MatchBody(MatchPlatform() with { CoverageId = " " }), "platforms", "error.ociScan.matchPlatformInvalid");

    [Fact]
    public void Matches_PlatformNamesAreDistinct()
        => AssertMatchInvalid(
            new OciScanMatchRequest([MatchPlatform(), MatchPlatform() with { CoverageId = "other" }], [Record()], null),
            "platforms", "error.ociScan.matchPlatformInvalid");

    [Fact]
    public void Matches_RefusesAnEmptyMatchGap()
        => AssertMatchInvalid(MatchBody(MatchPlatform() with { MatchGaps = [""] }), "matchGaps", "error.ociScan.gapsInvalid");

    [Fact]
    public void Matches_RefusesAFindingWithoutAComponent()
        => AssertMatchInvalid(
            MatchBody(MatchPlatform() with { Findings = [new OciScanMatchFinding(null, ["DSA-5000-1"])] }),
            "findings", "error.ociScan.findingUnknown");

    [Fact]
    public void Matches_NeedAtLeastOnePlatform()
        => AssertMatchInvalid(new OciScanMatchRequest([], [], null), "platforms", "error.ociScan.platformsRequired");

    private static void AssertMatchInvalid(OciScanMatchRequest body, string field, string key)
    {
        var (invalid, _) = OciScanResultWriter.ValidateMatches(body);
        Assert.NotNull(invalid);
        Assert.Equal(field, invalid.Field);
        Assert.Equal(key, invalid.ErrorKey);
    }

    private static OciScanMatchPlatform MatchPlatform() => new(
        Platform: "linux/amd64", CoverageId: "cov-1", OsvSource: "remote", ScannerVersion: "0.4.0",
        MatchGaps: [], Findings: [new OciScanMatchFinding("component-1", ["DSA-5000-1"])]);

    private static OciScanMatchRequest MatchBody(OciScanMatchPlatform? platform = null)
        => new([platform ?? MatchPlatform()], [Record()], null);

    private static void AssertInvalid(OciScanResultRequest body, string field, string key)
    {
        var (invalid, _) = OciScanResultWriter.Validate(body);
        Assert.NotNull(invalid);
        Assert.Equal(OciScanResultOutcome.Invalid, invalid.Outcome);
        Assert.Equal(field, invalid.Field);
        Assert.Equal(key, invalid.ErrorKey);
    }

    private static JsonElement Record() => JsonDocument.Parse(DsaRecord).RootElement;

    private static OciScanComponent Component(string reachability = "reachable") => new(
        Purl: "pkg:deb/debian/libssl3@3.0.11-1~deb12u1?distro=debian-12&upstream=openssl",
        Ecosystem: "deb", Name: "libssl3", Version: "3.0.11-1~deb12u1",
        SourceName: "openssl", SourceVersion: "3.0.11-1~deb12u1",
        LayerIndex: 0, LayerDiffId: "sha256:aa", LayerInstruction: "ADD rootfs.tar.xz /",
        FilesPresent: 12, FilesRemoved: 0, InEntrypointClosure: true, OwnedByPurl: null,
        Vulns: [new OciScanComponentVuln("DSA-5000-1", reachability, null, "high")]);

    private static OciScanPlatformResult Platform(IReadOnlyList<string>? gaps = null, string reachability = "reachable") => new(
        Platform: "linux/amd64", ScannerVersion: "0.3.0", ExtractionVersion: "1", OsvSource: "remote",
        Gaps: gaps ?? [], EntrypointKind: "native", ClosureBounded: true,
        Components: [Component(reachability)]);

    private static OciScanResultRequest Body(
        IReadOnlyList<JsonElement>? advisories = null, string reachability = "reachable", IReadOnlyList<string>? gaps = null)
        => new([Platform(gaps, reachability)], advisories ?? [Record()], null);
}
