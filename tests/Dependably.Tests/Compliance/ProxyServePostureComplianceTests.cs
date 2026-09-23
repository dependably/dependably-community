using System.Reflection;
using System.Text;
using Dependably.Storage;
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
        new("maven", "Api/MavenController.cs", true, true,
            "Multiple upstream repositories are normal, but a given coordinate still resolves from one of "
            + "them; pinning catches the same shadowing. The pinned authority needs no separate "
            + "resolution step: the Maven fetch URL is built as configured-base + repository-path, so its "
            + "authority is already the repository that answered, never a third-party artifact host. "
            + "Authority granularity also absorbs the normal enterprise shape — releases, snapshots and a "
            + "central proxy on one Nexus/Artifactory host are one authority, so a coordinate moving "
            + "between them raises nothing."),
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
        new("hex", "Api/HexController.Serve.cs", true, true,
            "One repository per org's upstream row (repo.hex.pm by default) and a flat package "
            + "namespace, the same single-upstream shape as npm. Routing through the shared service "
            + "is what gives a package tarball its first-fetch gating: the bytes are hash-and-staged "
            + "and verified against the outer checksum the upstream's own signed index vouched for "
            + "before any reach the client. The pinned authority is the repository base URL."),
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

            foreach (var site in requests)
            {
                // A parse that landed somewhere other than a real argument list would silently
                // report "no UpstreamUrl" for every ecosystem, which is the failure mode this gate
                // exists to prevent in the code it inspects.
                Assert.Contains("OrgId:", site.Arguments, StringComparison.Ordinal);
            }

            bool actual = requests.All(s => s.Arguments.Contains(PinField, StringComparison.Ordinal));
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

    /// <summary>
    /// The policy fields <c>BlockGateRequest.ForProxyCacheFacts</c> supplies from
    /// <c>OrgSettings</c> on the cache-hit path — every <c>*Mode</c>/<c>*Tolerance</c> field plus
    /// <c>MinReleaseAgeHours</c>. <c>ProxyFetchRequest</c> carries the identical set of optional
    /// parameters so <c>ForProxyFirstFetch</c> can thread them onto the first-fetch gate request
    /// symmetrically, but "optional" is exactly the trap: a handler that never sets one still
    /// compiles, and the missing field reaches the gate as null — read as "policy off" — for every
    /// first fetch, no matter what the org configured.
    ///
    /// <para>
    /// Derived by reflection over <see cref="ProxyFetchRequest"/>'s constructor rather than
    /// hand-written, so a new defaulted <c>*Mode</c>/<c>*Tolerance</c> parameter is covered the
    /// moment it lands, instead of silently passing every site until someone remembers to add it
    /// here too — the exact hand-maintained-list failure mode <c>SourceRoots</c> and
    /// <c>CardinalityBudgetTests.AllowedAttributeNames</c> exist to avoid elsewhere in this
    /// codebase. <c>MinReleaseAgeHours</c> is the one field the naming convention cannot catch and
    /// is appended by hand. Fact fields (<c>PublishedAt</c>, <c>Deprecated</c>, …) and the
    /// always-required <c>MaxOsvScoreTolerance</c> are excluded: they are either positional-required
    /// (so a missing one fails to compile) or not policy at all — the <c>HasDefaultValue</c> filter
    /// is what keeps them out without naming them.
    /// </para>
    /// </summary>
    private static readonly string[] RequiredPolicyFields = DeriveRequiredPolicyFields();

    private static string[] DeriveRequiredPolicyFields()
    {
        var ctor = typeof(ProxyFetchRequest).GetConstructors().Single();
        var modeOrTolerance = ctor.GetParameters()
            .Where(p => p.HasDefaultValue
                && (p.Name!.EndsWith("Mode", StringComparison.Ordinal)
                    || p.Name!.EndsWith("Tolerance", StringComparison.Ordinal)))
            .Select(p => p.Name!);

        return modeOrTolerance.Append("MinReleaseAgeHours").OrderBy(f => f, StringComparer.Ordinal).ToArray();
    }

    /// <summary>
    /// Pins the reflected set against today's known 13 fields, by name, so a change to
    /// <see cref="ProxyFetchRequest"/>'s naming convention (or an unrelated refactor that happens to
    /// rename a parameter out of the <c>*Mode</c>/<c>*Tolerance</c> pattern) is caught here rather
    /// than silently shrinking what <see cref="EachProxyFetchRequestConstruction_SuppliesEveryPolicyFieldTheCacheHitPathReads"/>
    /// enforces.
    /// </summary>
    [Fact]
    public void DerivedRequiredPolicyFields_MatchesTheKnownFieldSet()
    {
        string[] expected =
        [
            "BlockDeprecatedMode",
            "BlockInstallScriptsMode",
            "BlockKevMode",
            "BlockKevRansomwareMode",
            "BlockMaliciousLiveMode",
            "BlockMaliciousMode",
            "BlockRevokedMode",
            "BlockSsvcExploitationMode",
            "LicenseEnforcementMode",
            "MaxEpssPercentileTolerance",
            "MaxEpssTolerance",
            "MinReleaseAgeHours",
            "VerifyProvenanceMode",
        ];

        Assert.Equal(expected.OrderBy(f => f, StringComparer.Ordinal), RequiredPolicyFields);
    }

    private const string PolicyFieldOptOut = "proxy-request-ok:";
    private const int PolicyFieldOptOutWindow = 5;

    /// <summary>
    /// Every <c>new ProxyFetchRequest(</c> construction anywhere in the source tree must supply
    /// every field in <see cref="RequiredPolicyFields"/>. A field left off compiles fine and defaults
    /// to null — the same silent-hole shape <c>BlockGateRequestConstructionComplianceTests</c>
    /// polices one layer further in, at the <c>BlockGateRequest</c> construction itself; this gate
    /// covers the layer that one cannot see, because a <c>ProxyFetchRequest</c> missing a field is a
    /// well-formed construction, not a factory-bypass violation.
    ///
    /// <para>
    /// Scanned directly against every C# file rather than routed through the <see cref="Posture"/>
    /// table's <c>RequestBuilder</c>/<c>Handler</c> entries: <c>nuget-symbols</c> (debug-symbol
    /// packages, <c>NuGetSymbolProxyFetcher.cs</c>) is a distinct ecosystem discriminator that
    /// constructs its own <c>ProxyFetchRequest</c> but has no <see cref="Posture"/> row of its own —
    /// going through the table would silently skip it, and would skip any future request builder
    /// the same way until someone remembered to add a posture entry too.
    /// </para>
    ///
    /// <para>
    /// A genuine per-ecosystem inapplicability (the ecosystem structurally never computes the fact
    /// that field gates on — an install-script signal, a provenance verdict, a deprecation flag)
    /// opts out with <c>// proxy-request-ok: &lt;FieldName&gt; — &lt;reason&gt;</c> in the 5 lines
    /// above the construction. A marker naming a field but giving no reason is rejected, same as
    /// every other opt-out gate in this codebase.
    /// </para>
    ///
    /// <para>
    /// <b>Blind spots.</b> The scan matches the literal text <c>new ProxyFetchRequest(</c>, so a
    /// target-typed <c>new(...)</c> (legal wherever the assignment target's type is already known,
    /// e.g. a <c>ProxyFetchRequest</c>-typed local or return) or a <c>with { }</c> copy of an
    /// existing request escapes it entirely — every construction site in this codebase today uses
    /// the explicit form, but a future one need not. And the check is presence, not value: a site
    /// that writes <c>BlockKevMode: null</c> explicitly satisfies the gate exactly as a site that
    /// reads the real setting does, because both are indistinguishable from source text alone — the
    /// gate proves a field was threaded, not that it carries the tenant's actual policy.
    /// </para>
    /// </summary>
    [Fact]
    public void EachProxyFetchRequestConstruction_SuppliesEveryPolicyFieldTheCacheHitPathReads()
    {
        var files = SourceRoots.AllCSharpFiles().ToList();
        Assert.True(files.Count >= 50, $"only {files.Count} C# files scanned — the source-root walk likely regressed.");

        var drift = new List<string>();
        int sitesScanned = 0;

        foreach (string path in files)
        {
            string source = File.ReadAllText(path);
            if (!source.Contains(RequestMarker, StringComparison.Ordinal))
            {
                continue;
            }

            string[] lines = source.Split('\n');
            string rel = Path.GetRelativePath(SourceRoots.OwningRoot(path), path);

            foreach (var site in TopLevelProxyFetchRequestArguments(source))
            {
                sitesScanned++;
                // A parse that landed somewhere other than a real argument list would silently
                // report every field missing at a location that is not really a construction site.
                Assert.Contains("OrgId:", site.Arguments, StringComparison.Ordinal);

                foreach (string field in RequiredPolicyFields)
                {
                    if (site.Arguments.Contains(field + ":", StringComparison.Ordinal))
                    {
                        continue;
                    }

                    if (HasReasonedOptOutForField(lines, site.LineIndex, field))
                    {
                        continue;
                    }

                    drift.Add(
                        $"{rel}:{site.LineIndex + 1}: ProxyFetchRequest omits {field} — a proxy first fetch "
                        + "at this site never evaluates that arm, even when the org has it configured. Pass "
                        + $"it, or opt out with `// {PolicyFieldOptOut} {field} — <reason>` in the 5 lines "
                        + "above if this construction site genuinely never carries the signal that field "
                        + "gates on.");
                }
            }
        }

        // Green-but-blind guard: the codebase has 7 known ProxyFetchRequest construction sites today
        // (npm, pypi, nuget nupkg, nuget-symbols, maven, terraform, hex). A regressed scan that found
        // none of them would report zero drift and read as a clean pass.
        Assert.True(sitesScanned >= 7, $"only {sitesScanned} ProxyFetchRequest construction site(s) found — the scan likely regressed.");

        Report(drift, "omit a first-fetch policy field the cache-hit path reads");
    }

    /// <summary>Looks for a reasoned <c>// proxy-request-ok: &lt;fieldName&gt; — …</c> opt-out naming
    /// <paramref name="fieldName"/> exactly, in the <see cref="PolicyFieldOptOutWindow"/> lines above
    /// <paramref name="siteLineIndex"/>.</summary>
    private static bool HasReasonedOptOutForField(string[] lines, int siteLineIndex, string fieldName)
    {
        for (int i = Math.Max(0, siteLineIndex - PolicyFieldOptOutWindow); i < siteLineIndex && i < lines.Length; i++)
        {
            if (TryParsePolicyFieldOptOut(lines[i], out string namedField, out string reason)
                && string.Equals(namedField, fieldName, StringComparison.Ordinal)
                && HasReason(reason))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// True when <paramref name="reason"/> carries actual reason text rather than only the
    /// separator punctuation a marker's author typed and forgot to follow with words — <c>—</c>,
    /// <c>-</c>, <c>:</c>, or a trailing <c>.</c> all trim away to nothing. Matches the precedent at
    /// <c>AlertSettingsRetiredSmtpTransportComplianceTests.HasReason</c>.
    /// </summary>
    private static bool HasReason(string reason) => reason.Trim(' ', '—', '-', ':', '.').Length > 0;

    /// <summary>
    /// Parses a <c>// proxy-request-ok: &lt;FieldName&gt; [reason text]</c> line. The first
    /// whitespace-delimited token after the marker is the field name; everything after that is the
    /// reason, trimmed. A marker with no field name, or no reason, still parses (returns
    /// <see langword="true"/>) — an empty reason is what makes the marker unreasoned, not a parse
    /// failure, so the caller can reject it explicitly rather than silently ignoring it.
    /// </summary>
    private static bool TryParsePolicyFieldOptOut(string line, out string field, out string reason)
    {
        field = "";
        reason = "";
        int idx = line.IndexOf(PolicyFieldOptOut, StringComparison.Ordinal);
        if (idx < 0)
        {
            return false;
        }

        string rest = line[(idx + PolicyFieldOptOut.Length)..].Trim();
        int spaceIdx = rest.IndexOfAny([' ', '\t']);
        field = spaceIdx >= 0 ? rest[..spaceIdx] : rest;
        reason = spaceIdx >= 0 ? rest[(spaceIdx + 1)..].Trim() : "";
        return true;
    }

    /// <summary>
    /// Scanner self-test: a marker must name the field it opts out AND carry a reason, or it does
    /// not count. Mirrors the shape of every other opt-out gate's own self-test in this codebase.
    /// </summary>
    [Theory]
    [InlineData("// proxy-request-ok: BlockInstallScriptsMode — Terraform carries no install-script concept.", "BlockInstallScriptsMode", true)]
    [InlineData("// proxy-request-ok: BlockInstallScriptsMode", "BlockInstallScriptsMode", false)]
    [InlineData("// proxy-request-ok: BlockInstallScriptsMode   ", "BlockInstallScriptsMode", false)]
    [InlineData("// proxy-request-ok: BlockInstallScriptsMode —", "BlockInstallScriptsMode", false)]
    [InlineData("// proxy-request-ok: BlockInstallScriptsMode .", "BlockInstallScriptsMode", false)]
    [InlineData("// proxy-request-ok: VerifyProvenanceMode — some other field's reason", "BlockInstallScriptsMode", false)]
    [InlineData("var x = 1;", "BlockInstallScriptsMode", false)]
    public void PolicyFieldOptOutParser_RequiresTheNamedFieldAndAReason(string line, string field, bool expected) =>
        Assert.Equal(expected, HasReasonedOptOutForField([line], 1, field));

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
    /// One <c>new ProxyFetchRequest(</c> construction: its top-level argument text (see
    /// <see cref="TopLevelProxyFetchRequestArguments"/>) and the zero-based line index the
    /// construction starts on, so a caller can look for an opt-out marker in the lines above it.
    /// </summary>
    internal readonly record struct ProxyFetchRequestSite(string Arguments, int LineIndex);

    /// <summary>
    /// The top-level argument text of every <c>new ProxyFetchRequest(</c> in a source file, with
    /// nested parenthesised groups, comments and string literals elided. Eliding the nesting is the
    /// point: <c>CacheAccess(… UpstreamUrl: …)</c> is an argument of the request and a plain
    /// substring search over the file would let it stand in for the top-level field that source
    /// pinning actually reads.
    /// </summary>
    internal static IReadOnlyList<ProxyFetchRequestSite> TopLevelProxyFetchRequestArguments(string source)
    {
        var results = new List<ProxyFetchRequestSite>();
        int search = 0;

        while (true)
        {
            int start = source.IndexOf(RequestMarker, search, StringComparison.Ordinal);
            if (start < 0)
            {
                return results;
            }

            int lineIndex = CountNewlines(source, start);
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

            results.Add(new ProxyFetchRequestSite(topLevel.ToString(), lineIndex));
            search = i > start ? i : start + RequestMarker.Length;
        }
    }

    private static int CountNewlines(string source, int upto)
    {
        int count = 0;
        for (int k = 0; k < upto && k < source.Length; k++)
        {
            if (source[k] == '\n')
            {
                count++;
            }
        }

        return count;
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
                 { "npm", "pypi", "nuget", "maven", "rpm", "go", "cargo", "apk", "oci", "terraform", "hex" })
        {
            Assert.Contains(Posture, p => p.Ecosystem == ecosystem);
        }
    }
}
