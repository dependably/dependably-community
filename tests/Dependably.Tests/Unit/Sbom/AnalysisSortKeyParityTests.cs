using System.Text.RegularExpressions;
using Dependably.Api;
using Dependably.Tests.Compliance;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// Cross-layer parity for the component table's sort keys: the DataTable column key a header
/// click emits is sent verbatim as the API's <c>sort</c> parameter, and the endpoint rejects an
/// unrecognised value rather than defaulting it.
///
/// <para>The drift this pins is worse than a wrong order. A column key outside the server's set
/// 422s the whole request, so the table renders its validation detail instead of any rows — and
/// because the table state is persisted to the query string, the bad key survives the reload,
/// leaving the page stuck until the operator hand-edits the URL. Nothing in the frontend
/// validates the key it emits, so only this comparison catches a header that was made sortable
/// without a matching server arm.</para>
///
/// <para>The frontend halves are read as text rather than mirrored into a C# constant, because a
/// mirrored copy is exactly the second spelling this test exists to forbid.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed partial class AnalysisSortKeyParityTests
{
    [Fact]
    public void EverySortableColumnKey_IsASortKeyTheEndpointAccepts()
    {
        var sortable = SortableColumnKeys();

        // A parity test over an empty set passes while proving nothing — the extraction breaking
        // (a reformatted columns array) must fail here rather than read as clean.
        Assert.True(sortable.Count > 0, "no sortable columns were extracted from ProjectVersionDetail.svelte");

        var unknown = sortable
            .Where(k => !SbomAnalysisProjection.SortKeys.Contains(k))
            .OrderBy(k => k, StringComparer.Ordinal)
            .ToList();
        Assert.True(
            unknown.Count == 0,
            $"sortable column keys the analysis endpoint rejects: {string.Join(", ", unknown)}");
    }

    [Fact]
    public void TheDefaultSort_IsASortKeyTheEndpointAccepts()
    {
        string source = File.ReadAllText(Path.Combine(
            SourceRoots.RepoRoot(), "web", "src", "lib", "sbom", "analysis.js"));

        var match = DefaultTableStateRegex().Match(source);
        Assert.True(match.Success, "DEFAULT_TABLE_STATE not found in web/src/lib/sbom/analysis.js.");

        var sort = SortDefaultRegex().Match(match.Groups["body"].Value);
        Assert.True(sort.Success, "DEFAULT_TABLE_STATE has no literal sort default.");
        Assert.Contains(sort.Groups["key"].Value, SbomAnalysisProjection.SortKeys);
    }

    /// <summary>
    /// The keys of the component table's columns declared <c>sortable: true</c>. Scoped to the
    /// reactive <c>columns</c> array so the page's other keyed literals cannot leak in.
    /// </summary>
    private static List<string> SortableColumnKeys()
    {
        string source = File.ReadAllText(Path.Combine(
            SourceRoots.RepoRoot(), "web", "src", "pages", "ProjectVersionDetail.svelte"));

        var block = ColumnsArrayRegex().Match(source);
        Assert.True(block.Success, "The reactive columns array was not found in ProjectVersionDetail.svelte.");

        return SortableColumnKeyRegex().Matches(block.Groups["body"].Value)
            .Select(m => m.Groups["key"].Value)
            .ToList();
    }

    [GeneratedRegex(@"DEFAULT_TABLE_STATE\s*=\s*\{(?<body>[^}]*)\}", RegexOptions.Singleline)]
    private static partial Regex DefaultTableStateRegex();

    [GeneratedRegex(@"sort:\s*'(?<key>[^']+)'")]
    private static partial Regex SortDefaultRegex();

    [GeneratedRegex(@"\$:\s*columns\s*=\s*\[(?<body>.*?)\n\s*\]", RegexOptions.Singleline)]
    private static partial Regex ColumnsArrayRegex();

    [GeneratedRegex(@"key:\s*'(?<key>[^']+)'[^}]*?sortable:\s*true")]
    private static partial Regex SortableColumnKeyRegex();
}
