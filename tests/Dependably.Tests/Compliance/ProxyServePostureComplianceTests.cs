using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Pins, per ecosystem, which proxy download path an ecosystem uses — and therefore which
/// upstream-facing behaviours it participates in.
///
/// <para>
/// Two ecosystems can both be "gated correctly" and still behave very differently on the way there.
/// Routing through <c>ProxyFetchService</c> brings source pinning (bind the name to its first
/// serving upstream, refuse a later serve from a different one) and the shared record/scan
/// sequence along with it; an ecosystem with its own fetch path gets neither unless it implements
/// them. Neither posture is wrong — RPM's upstreams are distro- and release-specific, so pinning a
/// name to one host is a different proposition than it is for npm — but which posture an ecosystem
/// has must be a decision someone made, not a fact nobody noticed.
/// </para>
///
/// <para>
/// This gate makes the decision visible: adding or removing a <c>ProxyFetchService</c> caller flips
/// an entry here and the build says so. It deliberately asserts the WIRING, not the outcome — the
/// gate symmetry itself is covered by <see cref="BlockGateRequestConstructionComplianceTests"/> and
/// by the behavioural tests, and duplicating that here would only add a second thing to update.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed class ProxyServePostureComplianceTests
{
    private readonly ITestOutputHelper _output;
    public ProxyServePostureComplianceTests(ITestOutputHelper output) => _output = output;

    /// <summary>
    /// The recorded posture. <c>true</c> = the ecosystem's proxy fetch goes through
    /// <c>ProxyFetchService.RecordAndScanAsync</c>, and so participates in source pinning and the
    /// shared post-fetch sequence. <c>false</c> = the ecosystem owns its fetch path.
    /// </summary>
    private static readonly (string Ecosystem, string Handler, bool RoutesThroughProxyFetchService, string Rationale)[] Posture =
    [
        ("npm", "Api/Npm/NpmTarballHandler.cs", true,
            "One well-known upstream per org; a name that starts resolving from a different host is the "
            + "dependency-confusion signal source pinning exists to catch."),
        ("pypi", "Api/PyPi/PyPiProxyFetcher.cs", true, "Same single-upstream shape as npm."),
        ("nuget", "Api/NuGet/NuGetFlatContainerHandler.cs", true, "Same single-upstream shape as npm."),
        ("maven", "Api/MavenController.cs", true,
            "Multiple upstream repositories are normal, but a given coordinate still resolves from one of "
            + "them; pinning catches the same shadowing."),
        ("rpm", "Api/RpmController.cs", false,
            "Distro- and release-specific repositories with no default upstream: the same package name "
            + "legitimately serves from many hosts across releases, so pinning a name to its first host "
            + "would refuse ordinary upgrades. RPM runs the identical record -> scan -> re-read facts -> "
            + "gate sequence in its own handler instead."),
        ("go", "Api/GoController.cs", false, "Proxy-only ecosystem with its own module-proxy fetch path."),
        ("cargo", "Api/CargoController.Serve.cs", false, "Own fetch path; org-scoped blob keys."),
        ("apk", "Api/ApkController.cs", false, "Own fetch path; org-scoped blob keys."),
        ("oci", "Api/OciController.cs", false,
            "Distribution-Spec pull flow with its own upstream resolver and token exchange."),
    ];

    private const string RouteMarker = "RecordAndScanAsync(";

    [Fact]
    public void EachEcosystemsProxyPath_MatchesItsRecordedPosture()
    {
        var files = SourceRoots.AllCSharpFiles().ToList();
        Assert.True(files.Count >= 50, $"only {files.Count} C# files scanned — the source-root walk likely regressed.");

        var drift = new List<string>();
        foreach (var (ecosystem, handler, expected, rationale) in Posture)
        {
            string? path = files.FirstOrDefault(f =>
                f.Replace('\\', '/').EndsWith(handler, StringComparison.Ordinal));
            if (path is null)
            {
                drift.Add($"{ecosystem}: recorded handler '{handler}' no longer exists — the posture entry "
                    + "is pointing at nothing and must be re-pointed or removed.");
                continue;
            }

            bool actual = File.ReadAllText(path).Contains(RouteMarker, StringComparison.Ordinal);
            if (actual != expected)
            {
                drift.Add(
                    $"{ecosystem} ({handler}): recorded as {(expected ? "routing through" : "NOT routing through")} "
                    + $"ProxyFetchService, but the source {(actual ? "does" : "does not")}. If the change is "
                    + $"intended, update the entry and its rationale. Recorded rationale: {rationale}");
            }
        }

        if (drift.Count > 0)
        {
            foreach (string d in drift)
            {
                _output.WriteLine(d);
            }

            Assert.Fail($"{drift.Count} ecosystem(s) drifted from the recorded proxy-serve posture. See test output.");
        }
    }

    /// <summary>
    /// Source pinning must remain a property of the shared path only. If a second file starts
    /// using the pin repository, the "which ecosystems are pinned" answer stops being derivable
    /// from the posture table above, and this test is where that gets noticed.
    /// </summary>
    [Fact]
    public void SourcePinning_IsAppliedOnlyByTheSharedProxyFetchPath()
    {
        var users = SourceRoots.AllCSharpFiles()
            .Where(f => File.ReadAllText(f).Contains("_sourcePins.", StringComparison.Ordinal))
            .Select(Path.GetFileName)
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(["ProxyFetchService.cs"], users);
    }

    /// <summary>Every ecosystem with a proxy path is accounted for — no silent omissions.</summary>
    [Fact]
    public void ThePostureTable_CoversEveryProxyCapableEcosystem()
    {
        foreach (string ecosystem in new[]
                 { "npm", "pypi", "nuget", "maven", "rpm", "go", "cargo", "apk", "oci" })
        {
            Assert.Contains(Posture, p => p.Ecosystem == ecosystem);
        }
    }
}
