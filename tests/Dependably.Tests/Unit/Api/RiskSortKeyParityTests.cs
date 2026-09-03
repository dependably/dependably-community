using System.Text.RegularExpressions;
using Dependably.Infrastructure;
using Dependably.Tests.Compliance;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Cross-layer parity for the Risk page's two sortable tables: the <c>DataTable</c> column key a
/// header click emits is sent verbatim as <c>RiskController.Operational</c>/<c>.License</c>'s
/// <c>sort</c> parameter, and each endpoint's own allowlist
/// (<see cref="PackageAnalyticsRepository.OperationalRiskSortKeys"/> /
/// <see cref="PackageAnalyticsRepository.LicenseRiskSortKeys"/>) is what makes an unrecognised
/// value fall back to the default rather than reaching the SQL.
///
/// <para>The drift this pins is worse than a wrong order: a header made sortable in Risk.svelte
/// with no matching server-side column silently orders by the endpoint's default instead — the
/// header renders an indicator that lies about which column actually drove the order, and nothing
/// short of this comparison would catch a column added to one side and not the other.</para>
///
/// <para>The frontend halves are read as text rather than mirrored into a C# constant, because a
/// mirrored copy is exactly the second spelling this test exists to forbid — the same approach
/// <c>AnalysisSortKeyParityTests</c> takes for the SBOM analysis table.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed partial class RiskSortKeyParityTests
{
    [Fact]
    public void EverySortableOperationalColumnKey_IsASortKeyTheEndpointAccepts()
    {
        var sortable = SortableColumnKeys("operationalColumns");

        // A parity test over an empty set passes while proving nothing — the extraction breaking
        // (a reformatted columns array) must fail here rather than read as clean.
        Assert.True(sortable.Count > 0, "no sortable columns were extracted from Risk.svelte's operationalColumns");

        var unknown = sortable
            .Where(k => !PackageAnalyticsRepository.OperationalRiskSortKeys.Contains(k))
            .OrderBy(k => k, StringComparer.Ordinal)
            .ToList();
        Assert.True(
            unknown.Count == 0,
            $"sortable operational column keys the endpoint rejects: {string.Join(", ", unknown)}");
    }

    [Fact]
    public void EverySortableLicenseColumnKey_IsASortKeyTheEndpointAccepts()
    {
        var sortable = SortableColumnKeys("licenseColumns");

        Assert.True(sortable.Count > 0, "no sortable columns were extracted from Risk.svelte's licenseColumns");

        var unknown = sortable
            .Where(k => !PackageAnalyticsRepository.LicenseRiskSortKeys.Contains(k))
            .OrderBy(k => k, StringComparer.Ordinal)
            .ToList();
        Assert.True(
            unknown.Count == 0,
            $"sortable license column keys the endpoint rejects: {string.Join(", ", unknown)}");
    }

    // "licenses" is the one license-table column deliberately left unsortable — the SPDX
    // identifiers are stitched onto the page's rows after paging (RiskController.License), so
    // there is no server-side column for a sort key to name. This pins the omission is
    // deliberate, not a column that was simply forgotten by both sides at once.
    [Fact]
    public void The_licenses_column_is_declared_unsortable_in_Risk_svelte()
    {
        string source = File.ReadAllText(RiskSveltePath());
        string block = ColumnsBlock(source, "licenseColumns");

        var match = LicensesColumnSortableRegex().Match(block);
        Assert.True(match.Success, "licenses column not found in Risk.svelte's licenseColumns.");
        Assert.Equal("false", match.Groups["val"].Value);
    }

    [Fact]
    public void TheDefaultSortForEachTab_IsASortKeyTheEndpointAccepts()
    {
        string source = File.ReadAllText(RiskSveltePath());

        var match = TabDefaultSortRegex().Match(source);
        Assert.True(match.Success, "tabDefaultSort() not found (or reshaped) in Risk.svelte.");

        Assert.Contains(match.Groups["op"].Value, PackageAnalyticsRepository.OperationalRiskSortKeys);
        Assert.Contains(match.Groups["lic"].Value, PackageAnalyticsRepository.LicenseRiskSortKeys);
        Assert.Equal(PackageAnalyticsRepository.DefaultOperationalRiskSort, match.Groups["op"].Value);
        Assert.Equal(PackageAnalyticsRepository.DefaultLicenseRiskSort, match.Groups["lic"].Value);
    }

    private static string RiskSveltePath() =>
        Path.Combine(SourceRoots.RepoRoot(), "web", "src", "pages", "Risk.svelte");

    /// <summary>
    /// The keys of the named reactive columns array's entries declared <c>sortable: true</c>.
    /// </summary>
    private static List<string> SortableColumnKeys(string variableName)
    {
        string source = File.ReadAllText(RiskSveltePath());
        string block = ColumnsBlock(source, variableName);

        return SortableColumnKeyRegex().Matches(block)
            .Select(m => m.Groups["key"].Value)
            .ToList();
    }

    private static string ColumnsBlock(string source, string variableName)
    {
        var block = Regex.Match(source, $@"\$:\s*{variableName}\s*=\s*\[(?<body>.*?)\n\s*\]", RegexOptions.Singleline);
        Assert.True(block.Success, $"The reactive {variableName} array was not found in Risk.svelte.");
        return block.Groups["body"].Value;
    }

    [GeneratedRegex(@"key:\s*'licenses'[^}]*?sortable:\s*(?<val>true|false)")]
    private static partial Regex LicensesColumnSortableRegex();

    [GeneratedRegex(
        @"function\s+tabDefaultSort\(tab\)\s*\{.*?return\s+tab\s*===\s*'license'\s*\?\s*\{\s*sort:\s*'(?<lic>[^']+)',\s*dir:\s*'(?<licDir>[^']+)'\s*\}\s*:\s*\{\s*sort:\s*'(?<op>[^']+)',\s*dir:\s*'(?<opDir>[^']+)'\s*\}",
        RegexOptions.Singleline)]
    private static partial Regex TabDefaultSortRegex();

    [GeneratedRegex(@"key:\s*'(?<key>[^']+)'[^}]*?sortable:\s*true")]
    private static partial Regex SortableColumnKeyRegex();
}
