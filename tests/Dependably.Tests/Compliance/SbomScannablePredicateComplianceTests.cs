using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check that the SBOM scan work queue has exactly one predicate.
///
/// <para>Two writers stamp <c>sbom_components.vuln_checked_at</c> — the upload/rescan-triggered
/// <c>SbomScanWorker</c>'s reader and the nightly pass in <c>VulnerabilityScanService</c> — and a
/// third in-memory reader (<c>SbomPolicyEvaluationService</c>) decides what a NULL stamp means. A
/// disagreement between them is invisible at compile time and invisible in a passing test suite:
/// each path works perfectly on its own, and the terminal state of a component becomes a function
/// of which one happened to run. So the condition lives in
/// <c>SbomScannableComponents.BuildPredicate</c> / <c>IsScannable</c>, and this gate fails any
/// source file that spells it out inline instead.</para>
///
/// <para>The rule is scoped, not global: only a file whose SQL touches <c>sbom_components</c> is
/// judged, and only for the three fragments that constitute the predicate. A file spliced from the
/// shared constant satisfies the gate by referencing it.</para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed class SbomScannablePredicateComplianceTests
{
    private const string SharedPredicateReference = "SbomScannableComponents.BuildPredicate";
    private const string SharedPredicateFile = "SbomScannableComponents.cs";

    // The fragments that, together, are the scannable condition. Any one of them appearing beside
    // sbom_components SQL means the file is re-deriving the predicate rather than splicing it.
    private static readonly string[] InlinePredicateFragments =
    [
        "ecosystem IS NOT NULL",
        "purl IS NOT NULL",
        "noFeedEcosystems",
    ];

    private readonly ITestOutputHelper _output;
    public SbomScannablePredicateComplianceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void EverySbomComponentScanQuery_SplicesTheSharedPredicate()
    {
        var violations = new List<string>();
        int scanned = 0;

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            if (Path.GetFileName(file).Equals(SharedPredicateFile, StringComparison.Ordinal))
            {
                continue;
            }

            // Comments are stripped first: a doc comment naming the shared constant would
            // otherwise satisfy the gate while the code beside it re-derived the predicate, which
            // is exactly the green-but-blind failure the gate exists to prevent.
            string text = StripComments(File.ReadAllText(file));
            if (!text.Contains("sbom_components", StringComparison.Ordinal))
            {
                continue;
            }

            scanned++;
            if (text.Contains(SharedPredicateReference, StringComparison.Ordinal))
            {
                continue;
            }

            foreach (string fragment in InlinePredicateFragments)
            {
                if (text.Contains(fragment, StringComparison.Ordinal))
                {
                    violations.Add(
                        $"{Path.GetFileName(file)}: spells the scannable condition inline ('{fragment}') " +
                        $"instead of splicing {SharedPredicateReference}.");
                }
            }
        }

        _output.WriteLine($"Scanned {scanned} source file(s) touching sbom_components.");
        Assert.True(scanned > 0, "No source file touching sbom_components was found — the gate is blind.");
        Assert.True(violations.Count == 0, string.Join(Environment.NewLine, violations));
    }

    /// <summary>
    /// Adversarial twin for the scan above: the gate only proves the fragments are absent, which a
    /// file that stopped querying the scan queue at all would also satisfy. This asserts the two
    /// SQL readers of the queue are still present and still splice the shared constant, so the
    /// gate cannot go green because its subjects disappeared.
    /// </summary>
    [Theory]
    [InlineData("SbomComponentVulnRepository.cs")]
    [InlineData("VulnerabilityScanService.cs")]
    public void TheKnownScanQueueReaders_ReferenceTheSharedPredicate(string fileName)
    {
        string? file = SourceRoots.AllCSharpFiles()
            .FirstOrDefault(f => Path.GetFileName(f).Equals(fileName, StringComparison.Ordinal));

        Assert.True(file is not null, $"{fileName} was not found under any source root.");
        Assert.Contains(SharedPredicateReference, StripComments(File.ReadAllText(file!)), StringComparison.Ordinal);
    }

    /// <summary>
    /// Removes <c>//</c> line comments (doc comments included) and <c>/* … */</c> blocks. Crude by
    /// design — it does not track string literals — but the fragments and the constant reference
    /// this gate looks for never contain a comment opener, so the only effect of over-stripping
    /// would be to hide a violation inside a string containing <c>//</c>, which none of the SQL
    /// here does.
    /// </summary>
    private static string StripComments(string source)
    {
        string withoutBlocks = System.Text.RegularExpressions.Regex.Replace(
            source, @"/\*.*?\*/", " ",
            System.Text.RegularExpressions.RegexOptions.Singleline,
            TimeSpan.FromSeconds(5));

        return string.Join(
            "\n",
            withoutBlocks.Split('\n').Select(line =>
            {
                int marker = line.IndexOf("//", StringComparison.Ordinal);
                return marker >= 0 ? line[..marker] : line;
            }));
    }
}
