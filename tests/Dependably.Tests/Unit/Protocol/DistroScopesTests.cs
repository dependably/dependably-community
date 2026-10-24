using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

[Trait("Category", "Unit")]
public sealed class DistroScopesTests
{
    [Theory]
    [InlineData("v3.20", "Alpine:v3.20")]
    [InlineData("3.20", "Alpine:v3.20")]
    [InlineData("Alpine:v3.19", "Alpine:v3.19")]
    [InlineData("alpine-3.18", "Alpine:v3.18")]
    [InlineData(" V3.21 ", "Alpine:v3.21")]
    public void Apk_AcceptsTheCommonSpellingsOfARelease(string raw, string expected)
    {
        Assert.True(DistroScopes.TryParse("apk", raw, out var scope));
        Assert.Equal(expected, scope!.OsvEcosystem);
        Assert.True(scope.IsApk);
    }

    [Theory]
    [InlineData("")]
    [InlineData("edge")]
    [InlineData("3")]
    [InlineData("v3.20.1")]
    [InlineData("Debian:12")]
    [InlineData("v3.20\u0000")]
    public void Apk_RejectsAnythingThatIsNotAReleaseBranch(string raw)
    {
        Assert.False(DistroScopes.TryParse("apk", raw, out _));
    }

    [Theory]
    [InlineData("Rocky Linux:9", "Rocky Linux:9", "Rocky Linux")]
    [InlineData("rocky linux:9", "Rocky Linux:9", "Rocky Linux")]
    [InlineData("rocky:9", "Rocky Linux:9", "Rocky Linux")]
    [InlineData("almalinux:9", "AlmaLinux:9", "AlmaLinux")]
    [InlineData("Red Hat:enterprise_linux:9::appstream", "Red Hat:enterprise_linux:9::appstream", "Red Hat")]
    public void Rpm_NormalisesTheFamily_AndKeepsTheReleaseVerbatim(string raw, string expected, string family)
    {
        Assert.True(DistroScopes.TryParse("rpm", raw, out var scope));
        Assert.Equal(expected, scope!.OsvEcosystem);
        Assert.Equal(family, scope.Family);
        Assert.False(scope.IsApk);
    }

    [Theory]
    [InlineData("Rocky Linux")]
    [InlineData("Rocky Linux:")]
    [InlineData(":9")]
    [InlineData("Debian:12")]
    [InlineData("Ubuntu:22.04")]
    [InlineData("9")]
    [InlineData("Rocky Linux:9\u0000")]
    [InlineData("Rocky Linux:9.4")]
    [InlineData("AlmaLinux:9.4")]
    [InlineData("Red Hat:enterprise_linux:9")]
    [InlineData("Red Hat:enterprise_linux:9::bogus")]
    [InlineData("openSUSE:Leap 15.5")]
    public void Rpm_RejectsUnknownFamiliesAndMissingReleases(string raw)
    {
        Assert.False(DistroScopes.TryParse("rpm", raw, out _));
    }

    [Fact]
    public void Derive_AgreeingUpstreams_YieldTheirSharedRelease()
    {
        var scope = DistroScopes.Derive("apk", [
            "https://dl-cdn.alpinelinux.org/alpine/v3.20/main",
            "https://dl-cdn.alpinelinux.org/alpine/v3.20/community"]);

        Assert.Equal("Alpine:v3.20", scope!.OsvEcosystem);
    }

    [Fact]
    public void Derive_DisagreeingOrOpaqueUpstreams_YieldNothing()
    {
        Assert.Null(DistroScopes.Derive("apk", [
            "https://dl-cdn.alpinelinux.org/alpine/v3.20/main", "https://dl-cdn.alpinelinux.org/alpine/v3.19/main"]));
        Assert.Null(DistroScopes.Derive("apk", [
            "https://dl-cdn.alpinelinux.org/alpine/v3.20/main", "https://mirror.internal/apk"]));
        Assert.Null(DistroScopes.Derive("apk", ["https://dl-cdn.alpinelinux.org/alpine/edge/main"]));
        Assert.Null(DistroScopes.Derive("apk", []));
        Assert.Null(DistroScopes.Derive("rpm", [
            "https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os", "https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os"]));
    }

    [Fact]
    public void Derive_RockyAndAlmaUpstreams_YieldTheirMajorRelease()
    {
        Assert.Equal("Rocky Linux:9", DistroScopes.Derive("rpm", ["https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/"])!.OsvEcosystem);
        Assert.Equal("Rocky Linux:8", DistroScopes.Derive("rpm", ["https://dl.rockylinux.org/vault/rocky/8.9/BaseOS/x86_64/os/"])!.OsvEcosystem);
        Assert.Equal("AlmaLinux:9", DistroScopes.Derive("rpm", ["https://repo.almalinux.org/almalinux/9/AppStream/x86_64/os"])!.OsvEcosystem);
    }

    [Theory]
    [InlineData("apk", "v3.2", true)]
    [InlineData("apk", "v3.24", true)]
    [InlineData("apk", "v3.20", true)]
    [InlineData("apk", "v3.1", false)]
    [InlineData("apk", "v3.99", false)]
    [InlineData("apk", "v4.0", false)]
    [InlineData("rpm", "Rocky Linux:9", true)]
    [InlineData("rpm", "Rocky Linux:10", true)]
    [InlineData("rpm", "Rocky Linux:11", false)]
    [InlineData("rpm", "AlmaLinux:8", true)]
    [InlineData("rpm", "AlmaLinux:99", false)]
    [InlineData("rpm", "Red Hat:enterprise_linux:9::baseos", true)]
    [InlineData("rpm", "Red Hat:enterprise_linux:7::baseos", false)]
    public void IsKnownRelease_OnlyAcceptsReleasesOsvPublishesAFeedFor(string ecosystem, string distro, bool expected)
    {
        Assert.True(DistroScopes.TryParse(ecosystem, distro, out var scope));
        Assert.Equal(expected, DistroScopes.IsKnownRelease(scope!));
    }

    [Theory]
    [InlineData("Alpine:v3.20", "Alpine:v3.20", true)]
    [InlineData("Alpine:v3.20", "alpine:v3.20", true)]
    [InlineData("Alpine:v3.20", "Alpine:v3.2", false)]
    [InlineData("Alpine:v3.2", "Alpine:v3.20", false)]
    [InlineData("Red Hat:enterprise_linux:9", "Red Hat:enterprise_linux:9::baseos", true)]
    [InlineData("Red Hat:enterprise_linux:9", "Red Hat:enterprise_linux:90", false)]
    [InlineData("Rocky Linux:9", "Rocky Linux:8", false)]
    public void Covers_MatchesTheReleaseExactlyOrByQualifierPrefix(string scope, string advisory, bool expected)
    {
        Assert.Equal(expected, DistroScopes.Covers(scope, advisory));
    }

    [Fact]
    public void Covers_NullAdvisoryEcosystemNeverMatches()
    {
        Assert.False(DistroScopes.Covers("Alpine:v3.20", null));
    }

    // ── TryParse: whitespace, casing, aliases, bounds ────────────────────────

    [Theory]
    [InlineData(" rocky : 9 ", "Rocky Linux:9")]
    [InlineData("rocky-linux:8", "Rocky Linux:8")]
    [InlineData("ALMA:9", "AlmaLinux:9")]
    [InlineData("AlmaLinux:10", "AlmaLinux:10")]
    [InlineData("redhat:enterprise_linux:9::baseos", "Red Hat:enterprise_linux:9::baseos")]
    [InlineData("RED HAT:ENTERPRISE_LINUX:8::AppStream", "Red Hat:enterprise_linux:8::appstream")]
    public void Rpm_AcceptsAliasesAndNormalisesCasing(string raw, string expected)
    {
        Assert.True(DistroScopes.TryParse("rpm", raw, out var scope));
        Assert.Equal(expected, scope!.OsvEcosystem);
    }

    [Fact]
    public void TryParse_LeavesScopeNullOnFailure()
    {
        Assert.False(DistroScopes.TryParse("rpm", "Debian:12", out var scope));
        Assert.Null(scope);
    }

    [Fact]
    public void TryParse_RejectsAnOverlongValue_ButAcceptsOneAtTheBound()
    {
        Assert.False(DistroScopes.TryParse("apk", new string('3', 81), out _));
        Assert.False(DistroScopes.TryParse("rpm", "Rocky Linux:" + new string('9', 70), out _));
        Assert.True(DistroScopes.TryParse("apk", "alpine:v3.20", out _));
    }

    [Theory]
    [InlineData("rpm", "Rocky Linux:9\tx")]
    [InlineData("rpm", "Rocky\nLinux:9")]
    [InlineData("apk", "v3.\n20")]
    public void TryParse_RejectsControlCharacters(string ecosystem, string raw)
    {
        Assert.False(DistroScopes.TryParse(ecosystem, raw, out _));
    }

    // ── IsKnownRelease on hand-built scopes ──────────────────────────────────

    [Theory]
    [InlineData("Alpine:v3.20", "Alpine", true)]
    [InlineData("Alpine:edge", "Alpine", false)]
    [InlineData("Alpine:v4.2", "Alpine", false)]
    [InlineData("Alpine:v3.x", "Alpine", false)]
    [InlineData("Debian:12", "Alpine", false)]
    [InlineData("rocky linux:9", "Rocky Linux", true)]
    [InlineData("Red Hat:enterprise_linux:8::appstream", "Red Hat", true)]
    [InlineData("Red Hat:enterprise_linux:10::baseos", "Red Hat", false)]
    [InlineData("Debian:12", "Debian", false)]
    public void IsKnownRelease_HandBuiltScopes(string osvEcosystem, string family, bool expected)
    {
        Assert.Equal(expected, DistroScopes.IsKnownRelease(new DistroScope(osvEcosystem, family)));
    }

    // ── Derive / PurlNamespace / ComparerFor ─────────────────────────────────

    [Fact]
    public void Derive_AgreeingRockyMirrors_YieldTheSharedRelease_EvenAcrossPointReleases()
    {
        var scope = DistroScopes.Derive("rpm", new[]
        {
            "https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/",
            "https://dl.rockylinux.org/pub/rocky/9.4/AppStream/x86_64/os/",
        });

        Assert.Equal("Rocky Linux:9", scope!.OsvEcosystem);
        Assert.Equal("Rocky Linux", scope.Family);
    }

    [Fact]
    public void Derive_RpmUpstreamThatNamesNoKnownDistribution_YieldsNothing()
    {
        Assert.Null(DistroScopes.Derive("rpm", new[] { "https://mirror.example.com/centos/9/BaseOS/x86_64/os/" }));
        Assert.Null(DistroScopes.Derive("rpm", new[]
        {
            "https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/",
            "https://mirror.example.com/opaque",
        }));
    }

    [Fact]
    public void Derive_AlpineBranchWithTrailingSegmentOrBareEnd()
    {
        Assert.Equal(
            "Alpine:v3.19",
            DistroScopes.Derive("apk", new[] { "https://dl-cdn.alpinelinux.org/alpine/v3.19" })!.OsvEcosystem);
        Assert.Equal(
            "Alpine:v3.19",
            DistroScopes.Derive("apk", new[] { "https://dl-cdn.alpinelinux.org/alpine/v3.19/" })!.OsvEcosystem);
    }

    [Theory]
    [InlineData("Rocky Linux:9", "Rocky Linux", "rocky-linux")]
    [InlineData("AlmaLinux:9", "AlmaLinux", "almalinux")]
    [InlineData("Red Hat:enterprise_linux:9::baseos", "Red Hat", "redhat")]
    [InlineData("Alpine:v3.20", "Alpine", null)]
    public void PurlNamespace_IsTheSegmentOsvRegistersForTheFamily(string ecosystem, string family, string? expected)
    {
        Assert.Equal(expected, DistroScopes.PurlNamespace(new DistroScope(ecosystem, family)));
    }

    [Fact]
    public void PurlNamespace_NullScopeHasNone()
    {
        Assert.Null(DistroScopes.PurlNamespace(null));
    }

    [Fact]
    public void ComparerFor_ApkUsesApkOrdering_AndRpmUsesEpochAwareRpmOrdering()
    {
        var apk = DistroScopes.ComparerFor(new DistroScope("Alpine:v3.20", "Alpine"));
        var rpm = DistroScopes.ComparerFor(new DistroScope("Rocky Linux:9", "Rocky Linux"));

        Assert.True(apk("1.2.3-r1", "1.2.3-r0") > 0);
        Assert.True(rpm("1:1.0-1", "2.0-1") > 0);
        Assert.Equal(0, rpm("0:2.0-1", "2.0-1"));
    }

    // ── IsAffected: enumerated package records (no raw JSON) ─────────────────

    private static readonly DistroScope Rocky9 = new("Rocky Linux:9", "Rocky Linux");
    private static readonly DistroScope Alpine320 = new("Alpine:v3.20", "Alpine");

    private static OsvAdvisory Advisory(string? rawJson, params OsvAffectedPackage[] packages) =>
        new("RLSA-2024:0001", Array.Empty<string>(), null, null, null, packages, null, null, true, rawJson);

    [Fact]
    public void IsAffected_WithoutRawJson_MatchesEnumeratedVersionsBySchemeEquality()
    {
        var advisory = Advisory(null, new OsvAffectedPackage(null, "Rocky Linux:9", "openssl", new[] { "0:3.0.7-1", "3.0.8-2" }));

        Assert.True(DistroScopes.IsAffected(advisory, Rocky9, "OpenSSL", "3.0.7-1"));
        Assert.True(DistroScopes.IsAffected(advisory, Rocky9, "openssl", "3.0.8-2"));
        Assert.False(DistroScopes.IsAffected(advisory, Rocky9, "openssl", "3.0.9-1"));
        Assert.False(DistroScopes.IsAffected(advisory, Rocky9, "openssl", "1:3.0.7-1"));
    }

    [Fact]
    public void IsAffected_WithoutRawJson_BarePackageEntryIsReported_ButOtherNamesAndReleasesAreNot()
    {
        var advisory = Advisory(null, new OsvAffectedPackage(null, "Rocky Linux:9", "openssl", Array.Empty<string>()));

        Assert.True(DistroScopes.IsAffected(advisory, Rocky9, "openssl", "9.9.9-9"));
        Assert.False(DistroScopes.IsAffected(advisory, Rocky9, "curl", "9.9.9-9"));
        Assert.False(DistroScopes.IsAffected(advisory, new DistroScope("Rocky Linux:8", "Rocky Linux"), "openssl", "1.0-1"));
    }

    [Fact]
    public void IsAffected_WithoutRawJson_ApkUsesApkEquality()
    {
        var advisory = Advisory(null, new OsvAffectedPackage(null, "Alpine:v3.20", "busybox", new[] { "1.36.1-r5" }));

        Assert.True(DistroScopes.IsAffected(advisory, Alpine320, "busybox", "1.36.1-r5"));
        Assert.False(DistroScopes.IsAffected(advisory, Alpine320, "busybox", "1.36.1-r6"));
    }

    // ── IsAffected: raw OSV record ───────────────────────────────────────────

    private static bool Affected(string rawJson, string name, string version, DistroScope? scope = null) =>
        DistroScopes.IsAffected(Advisory(rawJson), scope ?? Rocky9, name, version);

    private static string Entry(string body, string name = "openssl", string ecosystem = "Rocky Linux:9") =>
        "{\"affected\":[{\"package\":{\"name\":\"" + name + "\",\"ecosystem\":\"" + ecosystem + "\"}," + body + "}]}";

    [Fact]
    public void IsAffected_UnreadableRawJson_IsReportedBecauseItCannotBeShownToExclude()
    {
        Assert.True(Affected("{not json", "openssl", "3.0.7-1"));
    }

    [Theory]
    [InlineData("""{"id":"RLSA-1"}""")]
    [InlineData("""{"affected":"nope"}""")]
    [InlineData("""{"affected":[]}""")]
    [InlineData("""{"affected":[{"versions":["3.0.7-1"]}]}""")]
    [InlineData("""{"affected":[{"package":"openssl","versions":["3.0.7-1"]}]}""")]
    [InlineData("""{"affected":[{"package":{"name":"openssl"},"versions":["3.0.7-1"]}]}""")]
    [InlineData("""{"affected":[{"package":{"name":7,"ecosystem":"Rocky Linux:9"},"versions":["3.0.7-1"]}]}""")]
    public void IsAffected_RecordsWithNoUsableAffectedEntryAreNotReported(string rawJson)
    {
        Assert.False(Affected(rawJson, "openssl", "3.0.7-1"));
    }

    [Fact]
    public void IsAffected_EntryForADifferentPackageOrRelease_IsNotReported()
    {
        Assert.False(Affected(Entry("\"versions\":[\"3.0.7-1\"]", name: "curl"), "openssl", "3.0.7-1"));
        Assert.False(Affected(Entry("\"versions\":[\"3.0.7-1\"]", ecosystem: "Rocky Linux:8"), "openssl", "3.0.7-1"));
    }

    [Fact]
    public void IsAffected_EnumeratedVersions_MatchOnlyTheListedOnes()
    {
        string raw = Entry("\"versions\":[\"3.0.7-1\",42,\"3.0.8-2\"]");

        Assert.True(Affected(raw, "openssl", "3.0.8-2"));
        Assert.False(Affected(raw, "openssl", "3.0.9-1"));
    }

    [Fact]
    public void IsAffected_EntryCarryingNeitherVersionsNorRanges_IsReported()
    {
        Assert.True(Affected(Entry("\"database_specific\":{}"), "openssl", "3.0.7-1"));
    }

    [Fact]
    public void IsAffected_NonEcosystemRangeAlone_IsTreatedAsNoRangeAndReported()
    {
        string raw = Entry("\"ranges\":[{\"type\":\"SEMVER\",\"events\":[{\"introduced\":\"0\"},{\"fixed\":\"1.0.0\"}]}]");

        Assert.True(Affected(raw, "openssl", "9.9.9-1"));
    }

    [Fact]
    public void IsAffected_EcosystemRangeWithoutEvents_ContainsNothing()
    {
        Assert.False(Affected(Entry("\"ranges\":[{\"type\":\"ECOSYSTEM\"}]"), "openssl", "3.0.7-1"));
        Assert.False(Affected(Entry("\"ranges\":[{\"type\":\"ECOSYSTEM\",\"events\":\"x\"}]"), "openssl", "3.0.7-1"));
    }

    [Theory]
    [InlineData("0:3.0.0-1", false)]
    [InlineData("3.0.7-1", true)]
    [InlineData("3.0.9-1", true)]
    [InlineData("3.1.0-1", false)]
    [InlineData("3.2.0-1", false)]
    public void IsAffected_IntroducedAndFixedEvents_BoundTheAffectedWindow(string version, bool expected)
    {
        string raw = Entry("\"ranges\":[{\"type\":\"ECOSYSTEM\",\"events\":[{\"introduced\":\"3.0.5-1\"},{\"fixed\":\"3.1.0-1\"}]}]");

        Assert.Equal(expected, Affected(raw, "openssl", version));
    }

    [Theory]
    [InlineData("2.9.0-1", true)]
    [InlineData("3.0.8-2", true)]
    [InlineData("3.0.8-3", false)]
    public void IsAffected_IntroducedZeroWithLastAffected_ClosesOnlyOncePastIt(string version, bool expected)
    {
        string raw = Entry("\"ranges\":[{\"type\":\"ECOSYSTEM\",\"events\":[{\"introduced\":\"0\"},{\"last_affected\":\"3.0.8-2\"}]}]");

        Assert.Equal(expected, Affected(raw, "openssl", version));
    }

    [Fact]
    public void IsAffected_EventsListedOutOfOrder_AreAppliedInVersionOrder()
    {
        string raw = Entry("\"ranges\":[{\"type\":\"ECOSYSTEM\",\"events\":[{\"fixed\":\"3.1.0-1\"},{\"introduced\":\"3.0.5-1\"}]}]");

        Assert.True(Affected(raw, "openssl", "3.0.9-1"));
        Assert.False(Affected(raw, "openssl", "3.1.0-1"));
        Assert.False(Affected(raw, "openssl", "3.0.1-1"));
    }

    [Fact]
    public void IsAffected_SeveralRanges_AnyContainingTheVersionReports()
    {
        string raw = Entry(
            "\"ranges\":[{\"type\":\"ECOSYSTEM\",\"events\":[{\"introduced\":\"0\"},{\"fixed\":\"1.0-1\"}]}," +
            "{\"type\":\"ECOSYSTEM\",\"events\":[{\"introduced\":\"3.0.0-1\"},{\"fixed\":\"3.0.9-1\"}]}]");

        Assert.True(Affected(raw, "openssl", "3.0.5-1"));
        Assert.True(Affected(raw, "openssl", "0.9-1"));
        Assert.False(Affected(raw, "openssl", "2.0-1"));
    }

    [Fact]
    public void IsAffected_VersionListMissButRangeHits_Reports()
    {
        string raw = Entry(
            "\"versions\":[\"1.0-1\"],\"ranges\":[{\"type\":\"ECOSYSTEM\",\"events\":[{\"introduced\":\"0\"},{\"fixed\":\"5.0-1\"}]}]");

        Assert.True(Affected(raw, "openssl", "4.0-1"));
        Assert.False(Affected(raw, "openssl", "5.0-1"));
    }

    [Fact]
    public void IsAffected_RedHatStreamQualifiedEcosystem_IsCoveredByTheReleaseScope()
    {
        var scope = new DistroScope("Red Hat:enterprise_linux:9", "Red Hat");
        string raw = Entry("\"versions\":[\"3.0.7-1.el9\"]", ecosystem: "Red Hat:enterprise_linux:9::baseos");

        Assert.True(Affected(raw, "openssl", "3.0.7-1.el9", scope));
    }
}
