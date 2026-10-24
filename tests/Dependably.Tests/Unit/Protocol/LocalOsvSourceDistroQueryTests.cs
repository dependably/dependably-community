using Dependably.Protocol;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The offline release-scoped query: ECOSYSTEM ranges are evaluated with the distro's own version
/// ordering, a release the dump carries no feed for is reported as uncovered rather than clean,
/// and an advisory filed under a different release never answers for this one.
/// </summary>
[Trait("Category", "Unit")]
public sealed class LocalOsvSourceDistroQueryTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "osvdistro_" + Guid.NewGuid().ToString("N"));

    public LocalOsvSourceDistroQueryTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    private void Write(string id, string ecosystem, string name, string eventsJson, string versionsJson = "[]")
    {
        string json = $$"""
            {
              "id": "{{id}}",
              "summary": "distro advisory",
              "affected": [{
                "package": { "ecosystem": "{{ecosystem}}", "name": "{{name}}" },
                "ranges": [{ "type": "ECOSYSTEM", "events": {{eventsJson}} }],
                "versions": {{versionsJson}}
              }]
            }
            """;
        File.WriteAllText(Path.Combine(_dir, id.Replace(':', '_') + ".json"), json);
    }

    private LocalOsvSource Build() => new(_dir, NullLogger<LocalOsvSource>.Instance);

    private static DistroScope Alpine(string release) =>
        DistroScopes.TryParse("apk", release, out var scope) ? scope! : throw new InvalidOperationException(release);

    private static DistroScope Rpm(string distro) =>
        DistroScopes.TryParse("rpm", distro, out var scope) ? scope! : throw new InvalidOperationException(distro);

    [Fact]
    public async Task Apk_VersionBelowTheFixedEvent_IsAffected_AtOrAboveIsNot()
    {
        Write("ALPINE-CVE-1", "Alpine:v3.20", "curl", """[{"introduced":"0"},{"fixed":"8.5.0-r2"}]""");
        var src = Build();

        var below = await src.TryQueryDistroPackageAsync(Alpine("v3.20"), "curl", "8.5.0-r1");
        var atFix = await src.TryQueryDistroPackageAsync(Alpine("v3.20"), "curl", "8.5.0-r2");
        var above = await src.TryQueryDistroPackageAsync(Alpine("v3.20"), "curl", "8.5.0-r10");

        Assert.Equal("ALPINE-CVE-1", Assert.Single(below.Advisories).Id);
        Assert.True(below.Reached);
        Assert.Empty(atFix.Advisories);
        Assert.Empty(above.Advisories);
        Assert.True(atFix.Covered);
    }

    [Fact]
    public async Task Apk_AdvisoryFiledUnderAnotherRelease_DoesNotAnswerForThisOne()
    {
        Write("ALPINE-CVE-2", "Alpine:v3.19", "curl", """[{"introduced":"0"},{"fixed":"9.0.0-r0"}]""");
        Write("ALPINE-CVE-3", "Alpine:v3.20", "openssl", """[{"introduced":"0"},{"fixed":"9.0.0-r0"}]""");
        var src = Build();

        var onV320 = await src.TryQueryDistroPackageAsync(Alpine("v3.20"), "curl", "8.5.0-r0");
        var onV319 = await src.TryQueryDistroPackageAsync(Alpine("v3.19"), "curl", "8.5.0-r0");

        Assert.Empty(onV320.Advisories);
        Assert.True(onV320.Covered);
        Assert.Single(onV319.Advisories);
    }

    [Fact]
    public async Task Apk_ReleaseTheDumpHoldsNoFeedFor_IsNotCovered()
    {
        Write("ALPINE-CVE-4", "Alpine:v3.19", "curl", """[{"introduced":"0"},{"fixed":"9.0.0-r0"}]""");

        var result = await Build().TryQueryDistroPackageAsync(Alpine("v3.21"), "curl", "8.5.0-r0");

        Assert.True(result.Reached);
        Assert.False(result.Covered);
        Assert.Empty(result.Advisories);
    }

    [Fact]
    public async Task Apk_MissingDumpDirectory_IsNotReached()
    {
        var src = new LocalOsvSource(Path.Combine(_dir, "absent"), NullLogger<LocalOsvSource>.Instance);

        var result = await src.TryQueryDistroPackageAsync(Alpine("v3.20"), "curl", "8.5.0-r0");

        Assert.False(result.Reached);
    }

    [Fact]
    public async Task Rpm_EpochAwareRange_AffectsOnlyBuildsBelowTheFix()
    {
        Write("RLSA-2024:1", "Rocky Linux:9", "openssl", """[{"introduced":"0"},{"fixed":"1:3.0.7-27.el9"}]""");
        var src = Build();

        var older = await src.TryQueryDistroPackageAsync(Rpm("Rocky Linux:9"), "openssl", "1:3.0.7-24.el9");
        var noEpochIsEpochZero = await src.TryQueryDistroPackageAsync(Rpm("Rocky Linux:9"), "openssl", "3.0.7-99.el9");
        var fixedBuild = await src.TryQueryDistroPackageAsync(Rpm("Rocky Linux:9"), "openssl", "1:3.0.7-27.el9");

        Assert.Single(older.Advisories);
        Assert.Single(noEpochIsEpochZero.Advisories);
        Assert.Empty(fixedBuild.Advisories);
    }

    [Fact]
    public async Task Rpm_RockyReleaseDoesNotAnswerForAlma_AndLastAffectedIsInclusive()
    {
        Write("RLSA-2024:2", "Rocky Linux:9", "bash", """[{"introduced":"0"},{"last_affected":"5.1.8-6.el9"}]""");
        Write("ALSA-2024:9", "AlmaLinux:9", "zsh", """[{"introduced":"0"},{"fixed":"9.9-1.el9"}]""");
        var src = Build();

        var atLast = await src.TryQueryDistroPackageAsync(Rpm("Rocky Linux:9"), "bash", "5.1.8-6.el9");
        var pastLast = await src.TryQueryDistroPackageAsync(Rpm("Rocky Linux:9"), "bash", "5.1.8-7.el9");
        var wrongDistro = await src.TryQueryDistroPackageAsync(Rpm("AlmaLinux:9"), "bash", "5.1.8-6.el9");

        Assert.Single(atLast.Advisories);
        Assert.Empty(pastLast.Advisories);
        Assert.Empty(wrongDistro.Advisories);
    }

    [Fact]
    public async Task Rpm_RedHatProductStream_IsMatched()
    {
        Write("RHSA-2024:3", "Red Hat:enterprise_linux:9::appstream", "nginx", """[{"introduced":"0"},{"fixed":"1:1.22.1-4.el9"}]""");

        var result = await Build().TryQueryDistroPackageAsync(
            Rpm("Red Hat:enterprise_linux:9::appstream"), "nginx", "1:1.22.1-3.el9");

        Assert.True(result.Covered);
        Assert.Single(result.Advisories);
    }

    [Fact]
    public async Task Introduced_AfterTheQueriedVersion_IsNotAffected_AndReintroductionIsHonoured()
    {
        Write(
            "ALPINE-CVE-5", "Alpine:v3.20", "libfoo",
            """[{"introduced":"2.0-r0"},{"fixed":"2.1-r0"},{"introduced":"3.0-r0"},{"fixed":"3.1-r0"}]""");
        var src = Build();

        Assert.Empty((await src.TryQueryDistroPackageAsync(Alpine("v3.20"), "libfoo", "1.9-r0")).Advisories);
        Assert.Single((await src.TryQueryDistroPackageAsync(Alpine("v3.20"), "libfoo", "2.0-r5")).Advisories);
        Assert.Empty((await src.TryQueryDistroPackageAsync(Alpine("v3.20"), "libfoo", "2.5-r0")).Advisories);
        Assert.Single((await src.TryQueryDistroPackageAsync(Alpine("v3.20"), "libfoo", "3.0-r1")).Advisories);
    }

    [Fact]
    public async Task Rpm_BareVersion_NeverReadsAsHavingReachedTheFixedBuild()
    {
        Write("RLSA-2024:5", "Rocky Linux:9", "curl", """[{"introduced":"0"},{"fixed":"7.76.1-26.el9_3.2"}]""");

        var result = await Build().TryQueryDistroPackageAsync(Rpm("Rocky Linux:9"), "curl", "7.76.1");

        Assert.Single(result.Advisories);
    }

    [Fact]
    public async Task Apk_VersionWithoutRevision_NeverReadsAsHavingReachedTheFixedBuild()
    {
        Write("ALPINE-CVE-6", "Alpine:v3.20", "libfoo", """[{"introduced":"0"},{"fixed":"3.3.2-r0"}]""");

        var result = await Build().TryQueryDistroPackageAsync(Alpine("v3.20"), "libfoo", "3.3.2");

        Assert.Single(result.Advisories);
    }

    [Fact]
    public async Task EnumeratedVersions_MatchBySchemeEquality()
    {
        Write("RLSA-2024:4", "Rocky Linux:9", "curl", "[]", """["7.76.1-26.el9"]""");

        var hit = await Build().TryQueryDistroPackageAsync(Rpm("Rocky Linux:9"), "curl", "0:7.76.1-26.el9");

        Assert.Single(hit.Advisories);
    }
}
