using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Fail-closed gate for the protocol read plane: a serve path that decides whether an
/// <em>anonymous</em> caller may read must also decide what an <em>authenticated</em> one may read.
///
/// <para>
/// The invariant exists because the two decisions are routinely conflated. Every protocol read gate
/// in this codebase is built from the same idiom — resolve a token, then refuse only when the org
/// has <c>AnonymousPull</c> off and no token was presented:
/// </para>
/// <code>
/// var token = await Request.ResolveTokenAsync(_tokens, orgId, ct);
/// if (settings is not null &amp;&amp; !settings.AnonymousPull &amp;&amp; token is null) { return Unauthorized(); }
/// </code>
/// <para>
/// Stopping there means <em>any</em> live token in the tenant reads everything the org hosts and
/// proxies, whatever it was scoped for — an audit-only token, a publish-only CI credential, a token
/// deliberately minted narrow. <c>ResolveTokenAsync</c> proves only that the token is active and
/// belongs to the tenant; it says nothing about what the token is allowed to do. The capability
/// column is the ceiling, and on these paths nothing reads it.
/// </para>
///
/// <para>
/// <b>What this gate requires:</b> a method that consults <c>AnonymousPull</c> in a gate position
/// must also name a capability — a <c>HasCapability(…)</c> call or a <c>[RequireCapability]</c>
/// attribute in the same member — or carry an explicit <c>// <see cref="Marker"/> &lt;reason&gt;</c>
/// justification, matching the <c>xtenant:</c> / <c>rawsql:</c> / <c>authz-ok:</c> convention. A bare
/// marker with no reason is malformed and is never honoured.
/// </para>
///
/// <para>
/// <b>Why a baseline rather than a fix:</b> most protocol read paths do not check a capability today,
/// and making them do so is a behaviour change that would start refusing tokens which read
/// successfully right now — it needs its own rollout, and a decision about how a capability check
/// composes with <c>AnonymousPull</c>. Turning that inventory into a hard failure would force either
/// a rushed behaviour change or a wall of rubber-stamp markers, and the second is how a gate becomes
/// decoration. So the known sites are enumerated in <see cref="KnownUncheckedReadGates"/> as recorded
/// debt, distinct from <see cref="Marker"/>, which means "deliberately exempt". The distinction is
/// the whole point: a marker says this is fine, the baseline says this is not fine yet.
/// </para>
///
/// <para>
/// The baseline only shrinks. <see cref="EveryBaselinedReadGateIsStillUnchecked"/> fails when an entry
/// stops being a real unchecked gate, so fixing one forces its removal and it can never be re-added
/// quietly. A <em>new</em> read gate is not in the baseline and fails immediately, which is the
/// property that matters: this gate exists to stop the nineteenth unchecked serve path, not to
/// re-litigate the first eighteen.
/// </para>
///
/// <para>
/// <b>Known limitations, stated plainly.</b> This proves a capability check is <em>present</em> in the
/// member, never that it is the right capability, that it guards every branch, or that it runs before
/// the bytes are served. It anchors on the <c>AnonymousPull</c> idiom, so a read gate written some
/// other way is invisible to it — the anchor is what makes the gate precise, and it is also its
/// ceiling. And it says nothing about the write plane, which is covered by
/// <see cref="AuthorizationDecisionComplianceTests"/> and the per-controller publish checks.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class CapabilityEnforcementComplianceTests
{
    internal const string Marker = "cap-ok:";

    private const int MarkerWindow = 5;

    private readonly ITestOutputHelper _output;

    public CapabilityEnforcementComplianceTests(ITestOutputHelper output) => _output = output;

    /// <summary>
    /// Protocol read gates that resolve a token and then never consult its capabilities. Each entry is
    /// <c>&lt;file&gt;::&lt;member&gt;</c>. These are recorded gaps, not exemptions — see the class
    /// remarks for why they are baselined rather than fixed here.
    /// </summary>
    private static readonly IReadOnlySet<string> KnownUncheckedReadGates = new HashSet<string>(StringComparer.Ordinal)
    {
        // Apk — TOFU trust model; the serve path has no capability arm at all.
        "src/Dependably.Core/Api/ApkController.cs::HandleApkRequest",

        // cargo — config/search/index/crate reads gate on AnonymousPull only.
        "src/Dependably.Core/Api/CargoController.cs::GetConfig",
        "src/Dependably.Core/Api/CargoController.cs::Search",
        "src/Dependably.Core/Api/CargoController.Serve.cs::GetCrateAsync",
        "src/Dependably.Core/Api/CargoController.Serve.cs::GetIndexAsync",

        // go — proxy-only ecosystem; the whole module surface is one unchecked read.
        "src/Dependably.Core/Api/GoController.cs::HandleGoRequest",

        // maven — hosted download and the global-plane serve; the publish path does check.
        "src/Dependably.Core/Api/MavenController.cs::Download",
        "src/Dependably.Core/Api/MavenController.cs::ServeGlobalPlaneArtifactAsync",

        // npm — packument, dist-tags, audit and the proxy-cache tarball arms; the hosted tarball arms do check read:artifact.
        "src/Dependably.Core/Api/Npm/NpmAuditHandler.cs::BulkAdvisoriesAsync",
        "src/Dependably.Core/Api/Npm/NpmDistTagsHandler.cs::GetDistTagsImplAsync",
        "src/Dependably.Core/Api/Npm/NpmDistTagsHandler.cs::SearchAsync",
        "src/Dependably.Core/Api/Npm/NpmPackumentHandler.cs::ServeLocalPackumentAsync",
        "src/Dependably.Core/Api/Npm/NpmPackumentHandler.cs::ServePassthroughPackumentAsync",
        "src/Dependably.Core/Api/Npm/NpmTarballHandler.cs::CheckProxyGatesAsync",
        "src/Dependably.Core/Api/Npm/NpmTarballHandler.cs::HeadProxyCachedTarballAsync",
        "src/Dependably.Core/Api/Npm/NpmTarballHandler.cs::TryServeCacheHitTarballAsync",

        // nuget — every read routes through AuthorizeNuGetReadAsync, which resolves a token and never consults it; symbols and search included.
        "src/Dependably.Core/Api/NuGet/NuGetFlatContainerHandler.cs::AuthorizeNuGetReadAsync",
        "src/Dependably.Core/Api/NuGet/NuGetFlatContainerHandler.cs::FetchFromUpstreamAsync",
        "src/Dependably.Core/Api/NuGet/NuGetFlatContainerHandler.cs::HeadProxyCachedVersionAsync",
        "src/Dependably.Core/Api/NuGet/NuGetFlatContainerHandler.cs::HeadUploadedVersionAsync",
        "src/Dependably.Core/Api/NuGet/NuGetFlatContainerHandler.cs::ServeHostedVersionAsync",
        "src/Dependably.Core/Api/NuGet/NuGetFlatContainerHandler.cs::TryServeProxyCacheHitAsync",
        "src/Dependably.Core/Api/NuGet/NuGetPublishHandler.cs::GetSymbolFileAsync",
        "src/Dependably.Core/Api/NuGet/NuGetPublishHandler.cs::GetSymbolsAsync",
        "src/Dependably.Core/Api/NuGet/NuGetRegistrationHandler.cs::AuthorizeNuGetReadAsync",
        "src/Dependably.Core/Api/NuGet/NuGetSearchHandler.cs::AutocompleteAsync",
        "src/Dependably.Core/Api/NuGet/NuGetSearchHandler.cs::SearchAsync",

        // pypi — simple index, JSON API and the proxy-cache download arms; the hosted download arm does check.
        "src/Dependably.Core/Api/PyPi/PyPiDownloadHandler.cs::HeadProxyCachedPackageAsync",
        "src/Dependably.Core/Api/PyPi/PyPiDownloadHandler.cs::TryServeProxyCacheHitAsync",
        "src/Dependably.Core/Api/PyPi/PyPiJsonApiHandler.cs::PackageJsonCoreAsync",
        "src/Dependably.Core/Api/PyPi/PyPiSimpleIndexHandler.cs::PackageIndexAsync",
        "src/Dependably.Core/Api/PyPi/PyPiSimpleIndexHandler.cs::ProxyUpstreamSimpleIndexAsync",
        "src/Dependably.Core/Api/PyPi/PyPiSimpleIndexHandler.cs::SimpleIndexAsync",

        // rpm — repodata and package download on the proxy path.
        "src/Dependably.Core/Api/RpmController.Proxy.cs::Download",
        "src/Dependably.Core/Api/RpmController.Proxy.cs::Repodata",

        // terraform — provider-mirror reads.
        "src/Dependably.Core/Api/TerraformController.cs::HandleMirrorRequest",
    };

    [Fact]
    public void EveryAnonymousPullGateAlsoDecidesWhatATokenMayRead()
    {
        var unchecked_ = FindUncheckedReadGates();
        var violations = unchecked_
            .Where(site => !KnownUncheckedReadGates.Contains(site.Key))
            .Select(site => $"{site.Key} — consults AnonymousPull but never checks a capability; "
                          + $"add a HasCapability check, or an explicit '// {Marker} <reason>' if this "
                          + "path genuinely must serve any live token in the tenant")
            .ToList();

        Report(violations, "protocol read gate(s) with no capability decision");
    }

    /// <summary>
    /// The ratchet. A baseline entry that is no longer an unchecked gate — because it was fixed, moved,
    /// or renamed — is stale, and a stale baseline silently re-opens the hole it was hiding.
    /// </summary>
    [Fact]
    public void EveryBaselinedReadGateIsStillUnchecked()
    {
        var live = FindUncheckedReadGates().Select(s => s.Key).ToHashSet(StringComparer.Ordinal);
        var stale = KnownUncheckedReadGates
            .Where(entry => !live.Contains(entry))
            .Select(entry => $"{entry} — baselined as an unchecked read gate, but it no longer is. "
                           + "Delete the entry: the baseline only shrinks.")
            .ToList();

        Report(stale, "stale capability-enforcement baseline entry(ies)");
    }

    [Fact]
    public void EveryCapOkMarkerCarriesAStatedReason()
    {
        var violations = new List<string>();

        foreach (string file in ApiSourceFiles())
        {
            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                if (lines[i].Contains(Marker, StringComparison.Ordinal)
                    && !MarkerReasonRegex().IsMatch(lines[i]))
                {
                    violations.Add($"{Relative(file)}:{i + 1} — bare '{Marker}' with no reason; "
                                 + "a marker that states nothing is not a decision and is not honoured");
                }
            }
        }

        Report(violations, "malformed cap-ok marker(s)");
    }

    // ── Scan ───────────────────────────────────────────────────────────────────

    private static List<(string Key, string File)> FindUncheckedReadGates()
    {
        var found = new List<(string, string)>();

        foreach (string file in ApiSourceFiles())
        {
            string[] lines = File.ReadAllLines(file);

            for (int i = 0; i < lines.Length; i++)
            {
                if (!AnonymousPullGateRegex().IsMatch(lines[i]))
                {
                    continue;
                }

                var member = EnclosingMember(lines, i);
                if (member is null)
                {
                    // Extraction failing is a gate defect, not a pass: surface it as a violation
                    // rather than silently skipping the site.
                    found.Add(($"{Relative(file)}::<unresolved member at line {i + 1}>", file));
                    continue;
                }

                var (Name, Body, DeclarationLine) = member.Value;

                if (CapabilityDecisionRegex().IsMatch(Body) || HasMarkerAbove(lines, DeclarationLine)
                    || HasMarkerAbove(lines, i))
                {
                    continue;
                }

                found.Add(($"{Relative(file)}::{Name}", file));
            }
        }

        return found.DistinctBy(f => f.Item1, StringComparer.Ordinal)
            .OrderBy(f => f.Item1, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>
    /// The member enclosing <paramref name="lineIndex"/>: the nearest declaration above it, and that
    /// declaration's brace-matched body. Returns null when no declaration is found or the braces do
    /// not balance — the caller treats that as a violation rather than a pass.
    /// </summary>
    private static (string Name, string Body, int DeclarationLine)? EnclosingMember(string[] lines, int lineIndex)
    {
        for (int i = lineIndex; i >= 0; i--)
        {
            string name;
            int declarationStart = i;

            var decl = MemberDeclarationRegex().Match(lines[i]);
            if (decl.Success)
            {
                name = decl.Groups["name"].Value;
            }
            else
            {
                // A signature wrapped across two lines — the return type on one, the name and
                // parameter list on the next. Common where a tuple return type is long enough to
                // push past the line limit, which is exactly where the shared read-authorization
                // helpers live, so failing to recognise it would leave the real gate unresolved.
                var wrapped = WrappedDeclarationNameRegex().Match(lines[i]);
                int previous = i - 1;
                while (previous >= 0 && lines[previous].Trim().Length == 0)
                {
                    previous--;
                }

                if (!wrapped.Success || previous < 0
                    || !WrappedDeclarationPrefixRegex().IsMatch(lines[previous]))
                {
                    continue;
                }

                name = wrapped.Groups["name"].Value;
                declarationStart = previous;
            }

            int depth = 0;
            bool opened = false;
            var body = new System.Text.StringBuilder();

            for (int j = declarationStart; j < lines.Length; j++)
            {
                body.AppendLine(lines[j]);
                foreach (char c in lines[j])
                {
                    if (c == '{')
                    {
                        depth++;
                        opened = true;
                    }
                    else if (c == '}')
                    {
                        depth--;
                    }
                }

                if (opened && depth <= 0)
                {
                    return j >= lineIndex ? (name, body.ToString(), declarationStart) : null;
                }
            }

            return null;
        }

        return null;
    }

    private static bool HasMarkerAbove(string[] lines, int lineIndex)
    {
        for (int probe = Math.Max(0, lineIndex - MarkerWindow); probe <= lineIndex && probe < lines.Length; probe++)
        {
            // The reason is what makes the opt-out reviewable, so a bare marker suppresses
            // nothing here rather than merely being reported by the companion test. Otherwise a
            // marker with no argument would silently satisfy the gate for one run.
            if (MarkerReasonRegex().IsMatch(lines[probe]))
            {
                return true;
            }
        }

        return false;
    }

    private static IEnumerable<string> ApiSourceFiles() =>
        SourceRoots.AllCSharpFiles()
            .Where(f => f.Replace('\\', '/').Contains("/Api/", StringComparison.Ordinal));

    private static string Relative(string file) =>
        Path.GetRelativePath(SourceRoots.RepoRoot(), file).Replace('\\', '/');

    private void Report(List<string> violations, string what)
    {
        if (violations.Count == 0)
        {
            return;
        }

        violations.Sort(StringComparer.Ordinal);
        violations.ForEach(_output.WriteLine);
        Assert.Fail($"{violations.Count} {what}. See test output for the full list.");
    }

    // A gate position, not a mention: AnonymousPull participating in a conditional. Excludes the
    // prose occurrences in doc comments, which name the field while deciding nothing.
    [GeneratedRegex(@"^(?![^""]*//).*\bAnonymousPull\b\s*(?:&&|\|\||\)|$)")]
    private static partial Regex AnonymousPullGateRegex();

    // Either enforcement mechanism counts, exactly as AuthorizationDecisionComplianceTests treats a
    // hand-rolled check as equal to [Authorize]: the gate requires a decision, never a mechanism.
    [GeneratedRegex(@"HasCapability\s*\(|\[RequireCapability")]
    private static partial Regex CapabilityDecisionRegex();

    [GeneratedRegex(@"\bcap-ok:\s*\S+")]
    private static partial Regex MarkerReasonRegex();

    [GeneratedRegex(@"^\s*(?:\[[^\]]*\]\s*)*(?:public|private|protected|internal)\s[^;=]*?\b(?<name>\w+)\s*\(")]
    private static partial Regex MemberDeclarationRegex();

    [GeneratedRegex(@"^\s+(?<name>\w+)\s*\(")]
    private static partial Regex WrappedDeclarationNameRegex();

    // Deliberately permits '(' — the wrapped declarations this exists for are the ones whose
    // return type is a tuple, which is why the signature was too long for one line to begin with.
    // Excluding ';' and '{' is what keeps it from matching a field or a property's opening line.
    [GeneratedRegex(@"^\s*(?:\[[^\]]*\]\s*)*(?:public|private|protected|internal)\s[^;{]*$")]
    private static partial Regex WrappedDeclarationPrefixRegex();
}
