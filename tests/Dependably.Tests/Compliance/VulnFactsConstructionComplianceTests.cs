using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check enforcing that <c>VersionFacts</c> — the unified vulnerability-facts vocabulary
/// threaded through the whole block gate — is built through the record's own factory
/// (<c>VersionFacts.ForUpstreamOnly</c>) or one of the reviewed, marker-carrying construction
/// sites in <c>BlockGateService.cs</c>, never silently field-by-field at an arbitrary call site.
///
/// <para>
/// <c>VersionFacts</c> has the same omission-risk shape <c>BlockGateRequestConstructionComplianceTests</c>
/// already guards against on <c>BlockGateRequest</c>: it carries a <see cref="Dependably.Infrastructure.VulnFacts"/>
/// alongside a dozen other fields, and a field left off a call site does not fail to compile — it
/// silently reads as "no signal", which every arm interprets as "nothing to block on". By contrast,
/// <see cref="Dependably.Infrastructure.VulnFacts"/> itself is a plain leaf value record built fresh
/// at each of its own handful of call sites from a different source each time (a SQL aggregate row,
/// an ad hoc <c>AdvisoryAnalysis</c>, a per-vuln SBOM row) — it has no single owning file to route
/// through and no comparable "which factory forgets a field" failure mode, so this gate does not
/// cover it.
/// </para>
///
/// <para>
/// Opt-out: <c>// vuln-facts-ok: &lt;reason&gt;</c> in the 5 lines above the construction. The
/// marker is what makes the exception reviewable; a bare inline construction fails. Two production
/// sites outside <c>BlockGateService.cs</c> carry the marker today — <c>PackageLookupService.cs</c>'s
/// pre-fetch policy preview (no <c>BlockGateRequest</c>-shaped call site exists for a candidate
/// nobody has fetched yet) and <c>RpmRepodataService.cs</c>'s <c>FactsOf</c> row projector (RPM runs
/// its own record → scan → re-read facts → gate sequence rather than the shared request/index
/// paths, per <c>ProxyServePostureComplianceTests</c>).
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed class VulnFactsConstructionComplianceTests
{
    private readonly ITestOutputHelper _output;
    public VulnFactsConstructionComplianceTests(ITestOutputHelper output) => _output = output;

    private const string Construction = "new VersionFacts(";
    private const string OptOut = "vuln-facts-ok:";

    /// <summary>The file where the gate's arm ladder lives and constructs the record directly.</summary>
    private const string OwningFile = "BlockGateService.cs";

    [Fact]
    public void VersionFactsAreBuiltThroughTheFactoryOrAReviewedSite_NotBareFieldByFieldAtCallSites()
    {
        var violations = new List<string>();
        int scanned = 0;

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            if (Path.GetFileName(file).Equals(OwningFile, StringComparison.Ordinal))
            {
                continue;
            }

            string[] lines = File.ReadAllLines(file);
            scanned++;
            for (int i = 0; i < lines.Length; i++)
            {
                if (!lines[i].Contains(Construction, StringComparison.Ordinal)
                    || HasOptOut(lines, i))
                {
                    continue;
                }

                string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
                violations.Add(
                    $"{rel}:{i + 1}: VersionFacts constructed inline outside {OwningFile}. Use "
                    + "VersionFacts.ForUpstreamOnly(...) when it fits, or add a "
                    + "`// vuln-facts-ok: <reason>` marker in the 5 lines above a deliberate exception "
                    + "so a fact silently defaulting to \"no signal\" here stays reviewable.");
            }
        }

        // Green-but-blind guard: a moved/renamed source root would make this scan vacuous.
        Assert.True(scanned >= 50, $"only {scanned} C# files scanned — the source-root walk likely regressed.");

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} inline VersionFacts construction site(s). See test output.");
        }
    }

    /// <summary>
    /// The owning file must actually contain the one factory this gate names. Without this, a
    /// rename would leave the gate's guidance pointing at nothing while still passing.
    /// </summary>
    [Fact]
    public void TheOwningFile_DeclaresTheFactoryThisGateNames()
    {
        string? ownerPath = SourceRoots.AllCSharpFiles()
            .FirstOrDefault(f => Path.GetFileName(f).Equals(OwningFile, StringComparison.Ordinal));
        Assert.NotNull(ownerPath);

        string source = File.ReadAllText(ownerPath!);
        Assert.Contains("VersionFacts ForUpstreamOnly(", source, StringComparison.Ordinal);
    }

    /// <summary>
    /// Scanner self-test: the detector must fire on a bare construction and stand down for an
    /// annotated one, so the gate cannot go green-but-blind after a refactor of either half.
    /// </summary>
    [Theory]
    [InlineData(new[] { "var f = new VersionFacts(null, null, null, false, VulnFacts.None);" }, true)]
    [InlineData(new[] { "// vuln-facts-ok: reason", "var f = new VersionFacts(null, null, null, false, VulnFacts.None);" }, false)]
    [InlineData(new[] { "var f = VersionFacts.ForUpstreamOnly(deprecated, publishedAt);" }, false)]
    public void Scanner_FiresOnBareConstructionsOnly(string[] lines, bool expectViolation)
    {
        bool found = false;
        for (int i = 0; i < lines.Length; i++)
        {
            if (lines[i].Contains(Construction, StringComparison.Ordinal) && !HasOptOut(lines, i))
            {
                found = true;
            }
        }

        Assert.Equal(expectViolation, found);
    }

    private static bool HasOptOut(string[] lines, int lineIndex)
    {
        for (int probe = Math.Max(0, lineIndex - 5); probe <= lineIndex && probe < lines.Length; probe++)
        {
            if (lines[probe].Contains(OptOut, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
