using System.Text.RegularExpressions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check for the recurring "new ecosystem missed a hardcoded list" defect class: a new
/// entry in the shared <c>ECOSYSTEMS</c> vocabulary (<c>web/src/lib/ecosystems.js</c>) compiles
/// and passes every other gate while two unrelated hand-maintained lists silently fall behind —
/// <see cref="Dependably.Program"/>'s SPA-fallback <c>NonSpaPathPrefixes</c> array (a protocol
/// GET that matches no route 200s the SPA shell instead of 404ing) and the Dashboard donut's
/// per-ecosystem <c>.slice-{eco}</c> fill rule (an unmatched slice renders the SVG default fill —
/// opaque black — instead of its <c>--eco-{name}</c> color). Terraform shipped missing both.
///
/// Both lists are read and regexed as text rather than via reflection: <c>NonSpaPathPrefixes</c>
/// is <c>private</c> in a composition-root <c>Program</c> class, and the CSS rule has no runtime
/// representation to reflect over at all — text is the only surface either exposes, and it is the
/// same technique <see cref="UpstreamEcosystemVocabularyComplianceTests"/> already uses for the
/// analogous upstream-registry vocabulary.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class EcosystemHardcodedListComplianceTests
{
    // export const ECOSYSTEMS = ['pypi', 'npm', …]
    [GeneratedRegex(@"export\s+const\s+ECOSYSTEMS\s*=\s*\[(?<body>[^\]]*)\]", RegexOptions.Singleline)]
    private static partial Regex EcosystemVocabularyRegex();

    [GeneratedRegex(@"'(?<eco>[a-z0-9]+)'", RegexOptions.Singleline)]
    private static partial Regex QuotedKeyRegex();

    // private static readonly string[] NonSpaPathPrefixes = [ "/api/", "/simple/", … ];
    [GeneratedRegex(@"NonSpaPathPrefixes\s*=\s*\[(?<body>[^\]]*)\]", RegexOptions.Singleline)]
    private static partial Regex NonSpaPathPrefixesRegex();

    [GeneratedRegex(@"""(?<prefix>/[^""]*)""")]
    private static partial Regex QuotedStringRegex();

    // .slice-terraform { fill: var(--eco-terraform); }
    [GeneratedRegex(@"\.slice-(?<eco>[a-z0-9]+)\s*\{", RegexOptions.Singleline)]
    private static partial Regex SliceRuleRegex();

    // The ECOSYSTEMS key does not always equal its protocol route segment (oci serves the OCI
    // Distribution Spec surface at /v2/, golang at /go/) — this map is the one hand-maintained
    // translation the gate needs; every other lookup is a direct key match. Adding an ecosystem
    // to ecosystems.js without a matching entry here fails with a message naming both files.
    private static readonly Dictionary<string, string> EcosystemToRoutePrefix = new(StringComparer.Ordinal)
    {
        ["pypi"] = "/pypi/",
        ["npm"] = "/npm/",
        ["nuget"] = "/nuget/",
        ["maven"] = "/maven/",
        ["rpm"] = "/rpm/",
        ["oci"] = "/v2/",
        ["golang"] = "/go/",
        ["cargo"] = "/cargo/",
        ["apk"] = "/apk/",
        ["terraform"] = "/terraform/",
    };

    [Fact]
    public void EveryEcosystemHasANonSpaFallbackPrefix()
    {
        var ecosystems = ParseEcosystemVocabulary();

        var unmapped = ecosystems.Where(e => !EcosystemToRoutePrefix.ContainsKey(e))
            .OrderBy(e => e, StringComparer.Ordinal)
            .ToList();
        Assert.True(unmapped.Count == 0,
            $"{unmapped.Count} ecosystem(s) in web/src/lib/ecosystems.js have no route-prefix " +
            $"mapping in this test: [{string.Join(", ", unmapped)}]. Add an entry to " +
            $"{nameof(EcosystemToRoutePrefix)} naming the protocol prefix that ecosystem serves.");

        var prefixes = ParseNonSpaPathPrefixes();
        var missing = ecosystems
            .Select(e => EcosystemToRoutePrefix[e])
            .Where(p => !prefixes.Contains(p))
            .OrderBy(p => p, StringComparer.Ordinal)
            .ToList();

        Assert.True(missing.Count == 0,
            $"{missing.Count} protocol prefix(es) missing from NonSpaPathPrefixes in " +
            $"src/Dependably/Program.cs: [{string.Join(", ", missing)}]. A GET under that prefix " +
            "that matches no protocol route falls through to the SPA fallback and returns 200 " +
            "index.html instead of 404.");
    }

    [Fact]
    public void EveryEcosystemHasADonutSliceFillRule()
    {
        var ecosystems = ParseEcosystemVocabulary();
        var sliceRules = ParseSliceRules();

        var missing = ecosystems
            .Where(e => !sliceRules.Contains(e))
            .OrderBy(e => e, StringComparer.Ordinal)
            .ToList();

        Assert.True(missing.Count == 0,
            $"{missing.Count} ecosystem(s) in web/src/lib/ecosystems.js have no " +
            $".slice-{{eco}} rule in Dashboard.svelte's scoped styles: [{string.Join(", ", missing)}]. " +
            "The donut's <path class=\"slice slice-{eco}\"> falls back to the SVG default fill — " +
            "opaque black — instead of var(--eco-{eco}). Add \".slice-{eco} { fill: var(--eco-{eco}); }\".");
    }

    private static HashSet<string> ParseEcosystemVocabulary()
    {
        string source = ReadWebFile(Path.Combine("lib", "ecosystems.js"));
        var match = EcosystemVocabularyRegex().Match(source);
        Assert.True(match.Success,
            "Could not locate the ECOSYSTEMS list in web/src/lib/ecosystems.js — did its " +
            "declaration shape change? This gate parses it textually.");

        var keys = QuotedKeyRegex().Matches(match.Groups["body"].Value)
            .Select(m => m.Groups["eco"].Value)
            .ToHashSet(StringComparer.Ordinal);

        Assert.True(keys.Count >= 8, $"Parsed only [{string.Join(", ", keys)}] from ECOSYSTEMS.");
        return keys;
    }

    private static HashSet<string> ParseNonSpaPathPrefixes()
    {
        string source = ReadServerFile(Path.Combine("Dependably", "Program.cs"));
        var match = NonSpaPathPrefixesRegex().Match(source);
        Assert.True(match.Success,
            "Could not locate NonSpaPathPrefixes in src/Dependably/Program.cs — did its " +
            "declaration shape change? This gate parses it textually.");

        var prefixes = QuotedStringRegex().Matches(match.Groups["body"].Value)
            .Select(m => m.Groups["prefix"].Value)
            .ToHashSet(StringComparer.Ordinal);

        Assert.True(prefixes.Count >= 8, $"Parsed only [{string.Join(", ", prefixes)}] from NonSpaPathPrefixes.");
        return prefixes;
    }

    private static HashSet<string> ParseSliceRules()
    {
        string source = ReadWebFile(Path.Combine("pages", "Dashboard.svelte"));
        var rules = SliceRuleRegex().Matches(source)
            .Select(m => m.Groups["eco"].Value)
            .ToHashSet(StringComparer.Ordinal);

        Assert.True(rules.Count >= 8, $"Parsed only [{string.Join(", ", rules)}] slice rules from Dashboard.svelte.");
        return rules;
    }

    private static string ReadWebFile(string relativePath)
    {
        string path = Path.Combine(SourceRoots.RepoRoot(), "web", "src", relativePath);
        Assert.True(File.Exists(path), $"Expected frontend source at {path}.");
        return File.ReadAllText(path);
    }

    private static string ReadServerFile(string relativePath)
    {
        string path = Path.Combine(SourceRoots.RepoRoot(), "src", relativePath);
        Assert.True(File.Exists(path), $"Expected server source at {path}.");
        return File.ReadAllText(path);
    }
}
