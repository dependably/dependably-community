using Dependably.Infrastructure;
using Dependably.Infrastructure.Hex;
using Dependably.Protocol;
using Dependably.Protocol.Hex;

namespace Dependably.Tests.Unit.Hex;

/// <summary>
/// The merge rules behind every Hex resource this registry signs: held releases shadow the
/// upstream's, blocked held versions vanish, upstream-only releases are screened on the two
/// facts the upstream index carries, and advisories are indexed once and referenced by position.
/// Each refusal has its permitting twin so the builder is shown to discriminate.
/// </summary>
[Trait("Category", "Unit")]
public sealed class HexIndexBuilderTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 2, 12, 0, 0, TimeSpan.Zero);

    private static OrgSettings Settings(int? minReleaseAgeHours = null, string blockDeprecated = "off") =>
        new() { MinReleaseAgeHours = minReleaseAgeHours, BlockDeprecated = blockDeprecated };

    private static HexIndexedRelease Held(string version, bool hosted = true, string owner = "owner", HexRetirementReason? retired = null) =>
        new(version,
            new HexReleaseFacts("AA".PadRight(64, 'A'), new[] { new HexRequirement("jason", "~> 1.0", false, null, null) },
                null, Array.Empty<string>(), null, retired, null, false, null),
            "bb".PadRight(64, 'b'), Now.AddDays(-30), hosted, owner);

    private static HexRelease Upstream(string version, DateTimeOffset? publishedAt = null, HexRetirementStatus? retired = null) =>
        new(version, new byte[32], Array.Empty<HexDependency>(), retired, new byte[32], null,
            publishedAt is { } p ? HexTimestamp.FromDateTimeOffset(p) : null);

    private static HexPackage UpstreamPackage(params HexRelease[] releases) =>
        new("demo", "hexpm", releases, Array.Empty<HexSecurityAdvisory>());

    [Fact]
    public void HeldShadowsUpstreamOnCollision_AndTheResultIsSortedBySemVer()
    {
        var held = new[] { Held("1.0.0", owner: "held-1") };
        var upstream = UpstreamPackage(Upstream("2.0.0"), Upstream("1.0.0"), Upstream("0.9.0"));

        var package = HexIndexBuilder.BuildPackage("demo", held, upstream, new HashSet<string>(), Array.Empty<HexAdvisoryRow>(),
            HexIndexBuilder.PolicyFrom(Settings()), Now);

        Assert.Equal(HexIndexBuilder.RepositoryName, package.Repository);
        Assert.Equal(new[] { "0.9.0", "1.0.0", "2.0.0" }, package.Releases.Select(r => r.Version));
        // The held 1.0.0 won: it carries the held dependency, the upstream one had none.
        Assert.Single(package.Releases.Single(r => r.Version == "1.0.0").Dependencies);
    }

    [Fact]
    public void BlockedHeldVersion_IsNotAdvertised_AndTheUpstreamTwinDoesNotResurrectIt()
    {
        var held = new[] { Held("1.0.0"), Held("1.1.0") };
        var upstream = UpstreamPackage(Upstream("1.0.0"), Upstream("1.1.0"));

        var package = HexIndexBuilder.BuildPackage("demo", held, upstream,
            new HashSet<string> { "1.0.0" }, Array.Empty<HexAdvisoryRow>(), HexIndexBuilder.PolicyFrom(Settings()), Now);

        Assert.Equal(new[] { "1.1.0" }, package.Releases.Select(r => r.Version));
    }

    [Fact]
    public void UpstreamOnlyRelease_YoungerThanTheCooldown_IsWithheld_OlderOneIsAdvertised()
    {
        var upstream = UpstreamPackage(
            Upstream("1.0.0", publishedAt: Now.AddDays(-10)),
            Upstream("1.1.0", publishedAt: Now.AddHours(-2)));

        var package = HexIndexBuilder.BuildPackage("demo", Array.Empty<HexIndexedRelease>(), upstream,
            new HashSet<string>(), Array.Empty<HexAdvisoryRow>(), HexIndexBuilder.PolicyFrom(Settings(minReleaseAgeHours: 72)), Now);

        Assert.Equal(new[] { "1.0.0" }, package.Releases.Select(r => r.Version));
    }

    [Fact]
    public void UpstreamOnlyRelease_WithNoPublishTime_FailsTheCooldownOpen()
    {
        var upstream = UpstreamPackage(Upstream("1.0.0"));

        var package = HexIndexBuilder.BuildPackage("demo", Array.Empty<HexIndexedRelease>(), upstream,
            new HashSet<string>(), Array.Empty<HexAdvisoryRow>(), HexIndexBuilder.PolicyFrom(Settings(minReleaseAgeHours: 72)), Now);

        Assert.Single(package.Releases);
    }

    [Fact]
    public void RetiredUpstreamRelease_IsWithheldUnderBlockDeprecated_AdvertisedWhenOff()
    {
        var retired = new HexRetirementStatus(HexRetirementReason.Security, "CVE-2026-1");
        var upstream = UpstreamPackage(Upstream("1.0.0"), Upstream("1.1.0", retired: retired));

        var blocking = HexIndexBuilder.BuildPackage("demo", Array.Empty<HexIndexedRelease>(), upstream,
            new HashSet<string>(), Array.Empty<HexAdvisoryRow>(), HexIndexBuilder.PolicyFrom(Settings(blockDeprecated: "block_all")), Now);
        var open = HexIndexBuilder.BuildPackage("demo", Array.Empty<HexIndexedRelease>(), upstream,
            new HashSet<string>(), Array.Empty<HexAdvisoryRow>(), HexIndexBuilder.PolicyFrom(Settings()), Now);

        Assert.Equal(new[] { "1.0.0" }, blocking.Releases.Select(r => r.Version));
        Assert.Equal(new[] { "1.0.0", "1.1.0" }, open.Releases.Select(r => r.Version));
        // The retirement itself is carried through to the client either way it is advertised.
        Assert.Equal(retired, open.Releases[1].Retired);
    }

    [Fact]
    public void Advisories_AreIndexedOncePerPackage_AndReferencedByPositionFromTheReleasesTheyTouch()
    {
        var held = new[] { Held("1.0.0", owner: "pv-1"), Held("1.1.0", owner: "ca-2", hosted: false), Held("1.2.0", owner: "pv-3") };
        var advisories = new[]
        {
            new HexAdvisoryRow("GHSA-aaaa", "first", "HIGH", 7.5, new[] { "CVE-2026-1" }, new[] { "pv-1", "ca-2" }),
            new HexAdvisoryRow("GHSA-bbbb", "second", null, null, Array.Empty<string>(), new[] { "ca-2" }),
            new HexAdvisoryRow("GHSA-cccc", "orphan", "LOW", 2.0, Array.Empty<string>(), new[] { "not-held" }),
        };

        var package = HexIndexBuilder.BuildPackage("demo", held, null, new HashSet<string>(), advisories,
            HexIndexBuilder.PolicyFrom(Settings()), Now);

        Assert.Equal(new[] { "GHSA-aaaa", "GHSA-bbbb", "GHSA-cccc" }, package.Advisories.Select(a => a.Id));
        Assert.Equal(HexAdvisorySeverity.High, package.Advisories[0].Severity);
        Assert.Equal(7.5f, package.Advisories[0].CvssScore);
        Assert.Null(package.Advisories[1].Severity);
        Assert.Equal(new uint[] { 0 }, package.Releases.Single(r => r.Version == "1.0.0").AdvisoryIndexes);
        Assert.Equal(new uint[] { 0, 1 }, package.Releases.Single(r => r.Version == "1.1.0").AdvisoryIndexes);
        Assert.Null(package.Releases.Single(r => r.Version == "1.2.0").AdvisoryIndexes);
        Assert.Contains("osv.dev/vulnerability/GHSA-aaaa", package.Advisories[0].HtmlUrl);
    }

    [Fact]
    public void HeldRelease_CarriesInnerAndOuterChecksumsAndDependencies()
    {
        var release = HexIndexBuilder.ToRelease(Held("1.0.0", retired: HexRetirementReason.Deprecated));

        Assert.Equal(32, release.InnerChecksum.Length);
        Assert.Equal(32, release.OuterChecksum!.Length);
        Assert.Equal(new HexDependency("jason", "~> 1.0"), Assert.Single(release.Dependencies));
        Assert.Equal(HexRetirementReason.Deprecated, release.Retired!.Reason);
        Assert.NotNull(release.PublishedAt);
    }

    [Fact]
    public void Names_ListsEachHeldPackageOnce_Sorted()
    {
        var held = new[] { ("zeta", Held("1.0.0")), ("alpha", Held("1.0.0")), ("alpha", Held("1.1.0")) };

        var names = HexIndexBuilder.BuildNames(held);

        Assert.Equal(new[] { "alpha", "zeta" }, names.Packages.Select(p => p.Name));
        Assert.Equal(HexIndexBuilder.RepositoryName, names.Repository);
    }

    [Fact]
    public void Versions_DropsBlockedVersions_MarksRetiredAndAdvisoryIndexes()
    {
        var held = new[]
        {
            ("alpha", Held("1.0.0", owner: "a1")),
            ("alpha", Held("1.1.0", owner: "a2", retired: HexRetirementReason.Invalid)),
            ("alpha", Held("1.2.0", owner: "a3")),
            ("beta", Held("0.1.0", owner: "b1")),
        };

        var versions = HexIndexBuilder.BuildVersions(held,
            new HashSet<(string, string)> { ("alpha", "1.2.0"), ("beta", "0.1.0") },
            new HashSet<string> { "a1" });

        var alpha = Assert.Single(versions.Packages);
        Assert.Equal(new[] { "1.0.0", "1.1.0" }, alpha.Versions);
        Assert.Equal(new[] { 1 }, alpha.Retired);
        Assert.Equal(new[] { 0 }, alpha.WithAdvisories);
    }

    [Fact]
    public void RetirementAsDeprecation_NamesTheReasonAndMessage()
    {
        Assert.Equal("retired: security — CVE", HexIndexBuilder.RetirementAsDeprecation(new HexRetirementStatus(HexRetirementReason.Security, "CVE")));
        Assert.Equal("retired: renamed", HexIndexBuilder.RetirementAsDeprecation(new HexRetirementStatus(HexRetirementReason.Renamed)));
    }
}
