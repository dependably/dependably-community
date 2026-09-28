using System.Text.RegularExpressions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// <c>IMetadataStore.OpenCrossTenantAsync</c> and <c>DbScope.CrossTenant</c> are the row-level
/// security bypass. Two rules keep it
/// from becoming the path of least resistance when the backstop raises:
/// <list type="number">
///   <item>Every call carries an <c>// xtenant: &lt;reason&gt;</c> marker in the five lines above
///         it, the same reviewable signal the <c>org_id</c> filter gate asks for.</item>
///   <item>The number of calls is pinned. A new bypass changes <see cref="ExpectedCrossTenantOpens"/>
///         in the same diff, so it cannot slip in beside an unrelated change.</item>
/// </list>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class CrossTenantOpenComplianceTests
{
    /// <summary>
    /// Pinned count of <c>OpenCrossTenantAsync</c> call sites under <c>src/</c>. Raise it only
    /// together with the new call and its <c>xtenant:</c> reason.
    /// </summary>
    private const int ExpectedCrossTenantOpens = 45;

    private const int MarkerWindow = 5;

    [GeneratedRegex(@"(?:\.OpenCrossTenantAsync|\bDbScope\.CrossTenant)\s*\(")]
    private static partial Regex CallRegex();

    [GeneratedRegex(@"//\s*xtenant:\s*\S")]
    private static partial Regex MarkerRegex();

    private static List<(string File, int Line, bool Marked)> CallSites()
    {
        var sites = new List<(string, int, bool)>();
        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                if (!CallRegex().IsMatch(lines[i]))
                {
                    continue;
                }

                bool marked = Enumerable.Range(Math.Max(0, i - MarkerWindow), Math.Min(i, MarkerWindow) + 1)
                    .Any(j => MarkerRegex().IsMatch(lines[j]));
                string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
                sites.Add((rel, i + 1, marked));
            }
        }

        return sites;
    }

    [Fact]
    public void EveryCrossTenantOpen_CarriesAnXtenantReason()
    {
        var unmarked = CallSites().Where(s => !s.Marked).Select(s => $"{s.File}:{s.Line}").ToList();

        Assert.True(
            unmarked.Count == 0,
            "OpenCrossTenantAsync bypasses Postgres row-level security. Put `// xtenant: <reason>` within " +
            $"{MarkerWindow} lines above each call:\n  " + string.Join("\n  ", unmarked));
    }

    [Fact]
    public void CrossTenantOpenCount_IsPinned()
    {
        var sites = CallSites();

        Assert.True(
            sites.Count == ExpectedCrossTenantOpens,
            $"Expected {ExpectedCrossTenantOpens} OpenCrossTenantAsync call site(s), found {sites.Count}. A new " +
            "row-level security bypass must update ExpectedCrossTenantOpens in the same change so the review " +
            "sees it; a removed one should lower it:\n  " + string.Join("\n  ", sites.Select(s => $"{s.File}:{s.Line}")));
    }
}
