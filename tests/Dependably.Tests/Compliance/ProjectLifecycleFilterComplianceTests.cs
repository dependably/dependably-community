using System.Text.RegularExpressions;
using Dependably.Infrastructure;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check that every surface deciding "is this project version still something the tenant
/// ships" agrees on one predicate — <see cref="ProjectLifecycle.InServiceFilter"/>.
///
/// <para><b>Why a gate and not a shared constant.</b> The predicate is written inline in each SQL
/// literal rather than concatenated in, because these are raw string literals a reader greps and
/// reads whole, and splicing a constant through a <c>"""…""" + Const + """…"""</c> seam makes six
/// queries materially harder to read to save one line each. Inline text is the readable choice and
/// a drifting copy is its cost; this test is what pays that cost.</para>
///
/// <para><b>Why the drift matters more than a normal duplication.</b> The three consumer classes
/// are not peers rendering the same number — they form a chain, and each disagreement is its own
/// silent failure:</para>
/// <list type="bullet">
///   <item><description><c>SbomBlastRadiusRepository</c> counts a version, so an operator sees it
///   in "N applications ship this".</description></item>
///   <item><description><c>VulnerabilityScanService</c> re-evaluates it nightly. Narrower here
///   than in the blast radius means a counted version whose advisory links are frozen at whenever
///   it was last latest — a stale number presented beside current ones, with nothing on the
///   surface saying which is which.</description></item>
///   <item><description><c>RetentionService</c> spares it from the version cap. Narrower here
///   means a counted version silently deleted, so the affected-application number simply drops
///   with no event and no alert.</description></item>
/// </list>
///
/// <para><c>SbomExportService.Vex</c> is in scope too: it publishes the same count inside a VEX
/// document handed to a customer, so disagreeing with the UI is a published contradiction of the
/// tenant's own dashboard.</para>
///
/// <para><b>What this gate cannot see.</b> It proves the predicate text appears in each file, not
/// that it governs the right query — a file could carry it on one statement and leave a second
/// one unfiltered, and the count assertion below is the only thing standing against that. It also
/// cannot tell whether <c>p</c> and <c>pv</c> are bound to the tables the predicate assumes. Those
/// remain reviewer-enforced; the behavioural tests in
/// <c>Unit/Sbom/SbomBlastRadiusTests.cs</c> are what pin the semantics.</para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class ProjectLifecycleFilterComplianceTests
{
    /// <summary>
    /// Each file that must apply the in-service predicate, and how many SQL statements in it must
    /// carry one. The counts are asserted exactly, not as a floor: a floor would let a new query
    /// land in one of these files with no filter at all and still pass, which is precisely the
    /// hole the gate exists to close.
    /// </summary>
    private static readonly (string RelativePath, int Occurrences)[] RequiredSites =
    [
        (Path.Combine("Dependably.Management", "Infrastructure", "SbomBlastRadiusRepository.cs"), 6),
        (Path.Combine("Dependably.Management", "Infrastructure", "SbomExportService.Vex.cs"), 1),
        (Path.Combine("Dependably.Core", "Infrastructure", "VulnerabilityScanService.cs"), 1),
    ];

    private readonly ITestOutputHelper _output;
    public ProjectLifecycleFilterComplianceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void EveryInServiceSurfaceUsesTheCanonicalPredicate()
    {
        string src = Path.Combine(SourceRoots.RepoRoot(), "src");
        var violations = new List<string>();

        foreach ((string rel, int expected) in RequiredSites)
        {
            string path = Path.Combine(src, rel);
            if (!File.Exists(path))
            {
                violations.Add($"{rel}: file not found — did it move? The gate must move with it.");
                continue;
            }

            // Whitespace-insensitive: the predicate is wrapped across two lines in some queries
            // and sits on one in others, and a gate that failed over a line break would be
            // rewriting the SQL's formatting rather than protecting its meaning.
            int found = CountNormalized(StripDocComments(path), ProjectLifecycle.InServiceFilter);
            if (found != expected)
            {
                violations.Add(
                    $"{rel}: found {found} occurrence(s) of the in-service predicate, expected {expected}. "
                    + "A query added here needs the filter; a query removed needs this count updated.");
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations) { _output.WriteLine(v); }
        }

        Assert.True(
            violations.Count == 0,
            $"""
             {violations.Count} in-service filter violation(s).

             Every surface that decides what the tenant still ships must filter on:
                 {ProjectLifecycle.InServiceFilter}

             {string.Join(Environment.NewLine, violations)}
             """);
    }

    /// <summary>
    /// The retention cap is the inverse surface — it selects what to DELETE, so it must spare
    /// exactly what the others count. Its predicate is the complement (<c>is_latest = 0 AND
    /// is_active = 0</c>) rather than the filter above, which is why it gets its own assertion
    /// instead of being folded into the table.
    ///
    /// <para>Both statements matter and are checked. The SELECT chooses the rows; the DELETE
    /// re-asserts the predicate because a promotion or a reinstatement can land between them on
    /// the same unwrapped connection, and a DELETE that trusted the SELECT's id would act on a
    /// row that had just become in-service.</para>
    /// </summary>
    [Fact]
    public void RetentionSparesEveryInServiceVersion()
    {
        string path = Path.Combine(
            SourceRoots.RepoRoot(), "src", "Dependably.Management", "Infrastructure", "RetentionService.cs");
        Assert.True(File.Exists(path), $"RetentionService.cs not found at {path}.");

        string text = StripDocComments(path);

        // The two statements alias the table differently — the SELECT qualifies both columns with
        // `pv.`, the DELETE (a single-table statement) qualifies neither — so they are counted as
        // two distinct needles rather than one being assumed a substring of the other.
        int selectGuards = CountNormalized(text, "pv.is_latest = 0 AND pv.is_active = 0");
        int deleteGuards = CountNormalized(text, "WHERE org_id = @orgId AND id = @versionId "
            + "AND is_latest = 0 AND is_active = 0");

        Assert.True(
            selectGuards >= 1,
            "EnforceProjectVersionLimitAsync's SELECT must exclude in-service versions with "
            + "`pv.is_latest = 0 AND pv.is_active = 0`. Without the is_active half, a retention cap "
            + "deletes a release an operator marked as still running, and the blast-radius count "
            + "shrinks with no event to explain it.");

        Assert.True(
            deleteGuards >= 1,
            "The DELETE in EnforceProjectVersionLimitAsync must re-assert both flags rather than "
            + "trusting the id its SELECT chose: a promotion or a reinstatement can land between "
            + "the two statements, which run on one connection with no transaction around them.");
    }

    /// <summary>
    /// The C# mirror and the SQL predicate must state the same rule. Nothing forces them to agree
    /// — one is a string, the other a method — so the truth table is asserted directly.
    /// </summary>
    [Theory]
    // project active, version latest, version active  => in service
    [InlineData(true, true, true, true)]
    [InlineData(true, true, false, true)]    // latest is a floor: retiring it changes nothing
    [InlineData(true, false, true, true)]    // superseded but still deployed
    [InlineData(true, false, false, false)]  // superseded and retired
    [InlineData(false, true, true, false)]   // retired project overrides both version flags
    [InlineData(false, true, false, false)]
    [InlineData(false, false, true, false)]
    [InlineData(false, false, false, false)]
    public void CSharpMirrorMatchesTheSqlPredicate(
        bool projectActive, bool isLatest, bool versionActive, bool expected)
        => Assert.Equal(expected, ProjectLifecycle.IsInService(projectActive, isLatest, versionActive));

    /// <summary>
    /// The file with its <c>///</c> documentation lines removed, so the gate counts SQL and not
    /// the prose describing it. Without this, documenting the predicate in a class comment — which
    /// these files rightly do — inflates the count and fails the gate for writing it down.
    /// </summary>
    private static string StripDocComments(string path) =>
        string.Join(
            Environment.NewLine,
            File.ReadAllLines(path).Where(line => !line.TrimStart().StartsWith("///", StringComparison.Ordinal)));

    /// <summary>
    /// Collapses runs of whitespace so a predicate wrapped across lines counts the same as one
    /// written inline.
    /// </summary>
    [GeneratedRegex(@"\s+")]
    private static partial Regex WhitespaceRun();

    private static int CountNormalized(string haystack, string needle)
    {
        string flatHaystack = WhitespaceRun().Replace(haystack, " ");
        string flatNeedle = WhitespaceRun().Replace(needle, " ");

        int count = 0;
        int index = 0;
        while ((index = flatHaystack.IndexOf(flatNeedle, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += flatNeedle.Length;
        }

        return count;
    }
}
