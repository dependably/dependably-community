using System.Text.Json;
using System.Text.RegularExpressions;
using Dependably.Infrastructure.Sbom;
using Dependably.Tests.Compliance;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// Cross-layer parity for the CycloneDX analysis vocabulary: the server's one set, the Svelte
/// editor's select options, and the two locale catalogues that label them.
///
/// <para>The drift this pins is silent in both directions and costs an operator a decision.
/// A justification only the write path admits is stored, exported as CycloneDX no consumer
/// validates, and then dropped by <see cref="VexVocabulary.NormalizeJustification"/> when that
/// export is uploaded back — a triage that reads as saved and is not. A justification only the
/// read path knows renders as a raw key, or, when a vendor VEX supplies it, ingests fine and
/// then 422s the moment the operator edits the row through the UI.</para>
///
/// <para>The frontend halves are read as text rather than mirrored into a C# constant, because a
/// mirrored copy is exactly the second spelling this test exists to forbid.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class VexVocabularyParityTests
{
    /// <summary>
    /// The CycloneDX 1.6 <c>analysis.justification</c> enumeration, written out so a change to
    /// the server's set has to be a deliberate edit against the specification rather than a
    /// rename that quietly carries every other layer along with it.
    /// </summary>
    private static readonly string[] CycloneDxJustifications =
    [
        "code_not_present",
        "code_not_reachable",
        "requires_configuration",
        "requires_dependency",
        "requires_environment",
        "protected_by_compiler",
        "protected_at_runtime",
        "protected_at_perimeter",
        "protected_by_mitigating_control",
    ];

    [Fact]
    public void Justifications_AreExactlyTheCycloneDxEnumeration()
    {
        Assert.Equal(
            CycloneDxJustifications.OrderBy(v => v, StringComparer.Ordinal),
            VexVocabulary.Justifications.OrderBy(v => v, StringComparer.Ordinal));
    }

    [Fact]
    public void EveryVocabularySet_MatchesTheEditorsSelectOptions()
    {
        string source = File.ReadAllText(
            Path.Combine(SourceRoots.RepoRoot(), "web", "src", "lib", "sbom", "analysis.js"));

        AssertSameSet(VexVocabulary.States, JsArray(source, "VEX_STATES"), "VEX_STATES");
        AssertSameSet(VexVocabulary.Justifications, JsArray(source, "VEX_JUSTIFICATIONS"), "VEX_JUSTIFICATIONS");
        AssertSameSet(VexVocabulary.Responses, JsArray(source, "VEX_RESPONSES"), "VEX_RESPONSES");
    }

    [Theory]
    [InlineData("en")]
    [InlineData("fr")]
    public void EveryVocabularySet_HasALabelInEveryLocale(string locale)
    {
        using var catalogue = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(SourceRoots.RepoRoot(), "web", "src", "locales", $"{locale}.json")));
        var vex = catalogue.RootElement.GetProperty("sbomAnalysis").GetProperty("vex");

        // The state group also carries the select's own "label" string, so it is compared
        // against the vocabulary with that one non-value key removed rather than wholesale.
        AssertSameSet(
            VexVocabulary.States,
            LabelKeys(vex, "state").Where(k => k != "label").ToList(),
            $"{locale}.state");
        AssertSameSet(VexVocabulary.Justifications, LabelKeys(vex, "justificationValue"), $"{locale}.justificationValue");
        AssertSameSet(VexVocabulary.Responses, LabelKeys(vex, "responseValue"), $"{locale}.responseValue");
    }

    private static void AssertSameSet(
        IReadOnlySet<string> server, IReadOnlyCollection<string> frontend, string what)
    {
        var missing = server.Except(frontend, StringComparer.Ordinal).OrderBy(v => v, StringComparer.Ordinal).ToList();
        var extra = frontend.Except(server, StringComparer.Ordinal).OrderBy(v => v, StringComparer.Ordinal).ToList();

        Assert.True(
            missing.Count == 0 && extra.Count == 0,
            $"{what} has drifted from VexVocabulary. Absent from the frontend: "
            + $"[{string.Join(", ", missing)}]. Unknown to the server: [{string.Join(", ", extra)}].");
    }

    /// <summary>The string literals of one exported array in <c>analysis.js</c>.</summary>
    private static IReadOnlyCollection<string> JsArray(string source, string name)
    {
        var declaration = Regex.Match(
            source,
            $@"export const {Regex.Escape(name)}\s*=\s*\[(?<body>[^\]]*)\]",
            RegexOptions.None,
            TimeSpan.FromSeconds(5));
        Assert.True(declaration.Success, $"analysis.js declares no exported array named {name}.");

        return Regex.Matches(declaration.Groups["body"].Value, @"'(?<value>[^']+)'", RegexOptions.None, TimeSpan.FromSeconds(5))
            .Select(m => m.Groups["value"].Value)
            .ToList();
    }

    private static IReadOnlyCollection<string> LabelKeys(JsonElement vex, string group) =>
        vex.GetProperty(group).EnumerateObject().Select(p => p.Name).ToList();
}
