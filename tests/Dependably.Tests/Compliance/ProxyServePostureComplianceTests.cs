using System.Text;
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
///
/// <para>
/// Wiring means more than a call site, though, and that is the second thing recorded here. Source
/// pinning keys entirely off the TOP-LEVEL <c>ProxyFetchRequest.UpstreamUrl</c>: with that field
/// left null <c>EvaluateSourcePinAsync</c> returns before it does anything, no pin row is ever
/// written, and no violation can fire — silently, because an omitted optional argument compiles.
/// A gate that greps only for <c>RecordAndScanAsync(</c> reads as comprehensive while the control
/// it implies does not exist, so the pin column is asserted against the argument list itself, with
/// nested constructions (notably the <c>CacheAccess</c> argument, which has an <c>UpstreamUrl</c>
/// of its own for audit) elided so they cannot stand in for the field that matters.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed class ProxyServePostureComplianceTests
{
    private readonly ITestOutputHelper _output;
    public ProxyServePostureComplianceTests(ITestOutputHelper output) => _output = output;

    /// <summary>
    /// The recorded posture.
    ///
    /// <para><c>RoutesThroughProxyFetchService</c>: <c>true</c> = the ecosystem's proxy fetch goes
    /// through <c>ProxyFetchService.RecordAndScanAsync</c>, and so participates in the shared
    /// post-fetch sequence. <c>false</c> = the ecosystem owns its fetch path.</para>
    ///
    /// <para><c>PinsSourceAuthority</c>: <c>true</c> = its <c>ProxyFetchRequest</c> supplies a
    /// top-level <c>UpstreamUrl</c>, which is the only input source pinning reads. Meaningful only
    /// where the ecosystem routes through the shared service.</para>
    ///
    /// <para><c>RequestBuilder</c>: where the <c>ProxyFetchRequest</c> is constructed, when that is
    /// not the handler file itself.</para>
    /// </summary>
    private static readonly PostureEntry[] Posture =
    [
        new("npm", "Api/Npm/NpmTarballHandler.cs", true, true,
            "One well-known upstream per org; a name that starts resolving from a different host is the "
            + "dependency-confusion signal source pinning exists to catch."),
        new("pypi", "Api/PyPi/PyPiProxyFetcher.cs", true, true, "Same single-upstream shape as npm."),
        new("nuget", "Api/NuGet/NuGetFlatContainerHandler.cs", true, true, "Same single-upstream shape as npm.",
            RequestBuilder: "Api/NuGet/NuGetNupkgProxyHelper.cs"),
        new("maven", "Api/MavenController.cs", true, false,
            "Multiple upstream repositories are normal, but a given coordinate still resolves from one of "
            + "them; pinning catches the same shadowing — which is why the false in the pin column is a "
            + "recorded GAP, not a decision: the request omits the top-level UpstreamUrl, so the pin the "
            + "rationale describes does not run. Closing it flips this entry to true."),
        new("rpm", "Api/RpmController.cs", false, false,
            "Distro- and release-specific repositories with no default upstream: the same package name "
            + "legitimately serves from many hosts across releases, so pinning a name to its first host "
            + "would refuse ordinary upgrades. RPM runs the identical record -> scan -> re-read facts -> "
            + "gate sequence in its own handler instead."),
        new("go", "Api/GoController.cs", false, false, "Proxy-only ecosystem with its own module-proxy fetch path."),
        new("cargo", "Api/CargoController.Serve.cs", false, false, "Own fetch path; org-scoped blob keys."),
        new("apk", "Api/ApkController.cs", false, false, "Own fetch path; org-scoped blob keys."),
        new("oci", "Api/OciController.cs", false, false,
            "Distribution-Spec pull flow with its own upstream resolver and token exchange."),
        new("terraform", "Api/TerraformController.cs", true, true,
            "A provider's identity is its full source address, which names exactly one registry "
            + "host, so a provider that starts resolving from a different host is the same "
            + "dependency-confusion signal source pinning exists to catch for npm. Routing through "
            + "the shared service is also what gives the mirror first-fetch gating: the archive is "
            + "hash-and-staged before any byte reaches the client, so a vulnerable or blocked "
            + "provider is refused on the fetch that introduces it, not only on a later download. "
            + "The pinned authority is the resolved REGISTRY base, not the archive's download_url: "
            + "the registry protocol hands out a shared release-CDN URL that names no provider "
            + "identity, so pinning on it would bind every provider to one authority."),
    ];

    private sealed record PostureEntry(
        string Ecosystem,
        string Handler,
        bool RoutesThroughProxyFetchService,
        bool PinsSourceAuthority,
        string Rationale,
        string? RequestBuilder = null);

    private const string RouteMarker = "RecordAndScanAsync(";
    private const string RequestMarker = "new ProxyFetchRequest(";
    private const string PinField = "UpstreamUrl:";

    [Fact]
    public void EachEcosystemsProxyPath_MatchesItsRecordedPosture()
    {
        var files = SourceRoots.AllCSharpFiles().ToList();
        Assert.True(files.Count >= 50, $"only {files.Count} C# files scanned — the source-root walk likely regressed.");

        var drift = new List<string>();
        foreach (var entry in Posture)
        {
            string? path = Locate(files, entry.Handler);
            if (path is null)
            {
                drift.Add($"{entry.Ecosystem}: recorded handler '{entry.Handler}' no longer exists — the posture entry "
                    + "is pointing at nothing and must be re-pointed or removed.");
                continue;
            }

            bool actual = File.ReadAllText(path).Contains(RouteMarker, StringComparison.Ordinal);
            if (actual != entry.RoutesThroughProxyFetchService)
            {
                drift.Add(
                    $"{entry.Ecosystem} ({entry.Handler}): recorded as "
                    + $"{(entry.RoutesThroughProxyFetchService ? "routing through" : "NOT routing through")} "
                    + $"ProxyFetchService, but the source {(actual ? "does" : "does not")}. If the change is "
                    + $"intended, update the entry and its rationale. Recorded rationale: {entry.Rationale}");
            }
        }

        Report(drift, "drifted from the recorded proxy-serve posture");
    }

    /// <summary>
    /// Source pinning reads exactly one input — the top-level <c>ProxyFetchRequest.UpstreamUrl</c> —
    /// and does nothing at all when it is null. Recording per ecosystem whether that field is
    /// supplied is what stops a posture rationale from claiming a control the arguments never
    /// enabled; the nested <c>CacheAccess</c> argument carries an <c>UpstreamUrl</c> of its own for
    /// audit, so the check is made against the top-level argument list with nested constructions
    /// elided rather than against the file text.
    /// </summary>
    [Fact]
    public void EachSharedPathEcosystem_ThreadsTheSourceAuthorityItRecords()
    {
        var files = SourceRoots.AllCSharpFiles().ToList();
        var drift = new List<string>();

        foreach (var entry in Posture.Where(p => p.RoutesThroughProxyFetchService))
        {
            string where = entry.RequestBuilder ?? entry.Handler;
            string? path = Locate(files, where);
            if (path is null)
            {
                drift.Add($"{entry.Ecosystem}: recorded request builder '{where}' no longer exists.");
                continue;
            }

            var requests = TopLevelProxyFetchRequestArguments(File.ReadAllText(path));
            if (requests.Count == 0)
            {
                drift.Add($"{entry.Ecosystem} ({where}): no 'new ProxyFetchRequest(' construction found — "
                    + "the recorded request builder is pointing at the wrong file, or the request is now "
                    + "built somewhere this gate cannot see it.");
                continue;
            }

            foreach (string arguments in requests)
            {
                // A parse that landed somewhere other than a real argument list would silently
                // report "no UpstreamUrl" for every ecosystem, which is the failure mode this gate
                // exists to prevent in the code it inspects.
                Assert.Contains("OrgId:", arguments, StringComparison.Ordinal);
            }

            bool actual = requests.All(a => a.Contains(PinField, StringComparison.Ordinal));
            if (actual != entry.PinsSourceAuthority)
            {
                drift.Add(
                    $"{entry.Ecosystem} ({where}): recorded as "
                    + $"{(entry.PinsSourceAuthority ? "pinning" : "NOT pinning")} its source authority, but the "
                    + $"ProxyFetchRequest {(actual ? "does" : "does not")} supply a top-level {PinField}. "
                    + $"Without it EvaluateSourcePinAsync returns immediately and no pin is ever written. "
                    + $"Recorded rationale: {entry.Rationale}");
            }
        }

        Report(drift, "drifted from the recorded source-pin posture");
    }

    private static string? Locate(IEnumerable<string> files, string suffix) =>
        files.FirstOrDefault(f => f.Replace('\\', '/').EndsWith(suffix, StringComparison.Ordinal));

    private void Report(List<string> drift, string what)
    {
        if (drift.Count == 0)
        {
            return;
        }

        foreach (string d in drift)
        {
            _output.WriteLine(d);
        }

        Assert.Fail($"{drift.Count} ecosystem(s) {what}. See test output.");
    }

    /// <summary>
    /// The top-level argument text of every <c>new ProxyFetchRequest(</c> in a source file, with
    /// nested parenthesised groups, comments and string literals elided. Eliding the nesting is the
    /// point: <c>CacheAccess(… UpstreamUrl: …)</c> is an argument of the request and a plain
    /// substring search over the file would let it stand in for the top-level field that source
    /// pinning actually reads.
    /// </summary>
    internal static IReadOnlyList<string> TopLevelProxyFetchRequestArguments(string source)
    {
        var results = new List<string>();
        int search = 0;

        while (true)
        {
            int start = source.IndexOf(RequestMarker, search, StringComparison.Ordinal);
            if (start < 0)
            {
                return results;
            }

            int i = start + RequestMarker.Length;
            var topLevel = new StringBuilder();
            int depth = 1;

            while (i < source.Length && depth > 0)
            {
                char c = source[i];

                if (c == '/' && i + 1 < source.Length && source[i + 1] == '/')
                {
                    i = source.IndexOf('\n', i);
                    if (i < 0)
                    {
                        break;
                    }

                    continue;
                }

                if (c is '"' or '\'')
                {
                    i = SkipLiteral(source, i, c);
                    continue;
                }

                if (c == '(')
                {
                    depth++;
                }
                else if (c == ')')
                {
                    depth--;
                }

                if (depth == 1 && c != ')')
                {
                    topLevel.Append(c);
                }

                i++;
            }

            results.Add(topLevel.ToString());
            search = i > start ? i : start + RequestMarker.Length;
        }
    }

    // Advances past a string or char literal starting at `open`, honouring backslash escapes.
    private static int SkipLiteral(string source, int open, char quote)
    {
        int i = open + 1;
        while (i < source.Length)
        {
            if (source[i] == '\\')
            {
                i += 2;
                continue;
            }

            if (source[i] == quote)
            {
                return i + 1;
            }

            i++;
        }

        return i;
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
                 { "npm", "pypi", "nuget", "maven", "rpm", "go", "cargo", "apk", "oci", "terraform" })
        {
            Assert.Contains(Posture, p => p.Ecosystem == ecosystem);
        }
    }
}
