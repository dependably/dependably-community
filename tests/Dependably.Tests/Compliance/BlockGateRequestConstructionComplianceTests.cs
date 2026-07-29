using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check enforcing that a <c>BlockGateRequest</c> is built by one of the factories in
/// <c>BlockGateService.cs</c>, never field-by-field at a call site.
///
/// <para>
/// The gate reads a dozen policy modes and as many facts. Every one of them has to be threaded from
/// somewhere to the arm that reads it, and a field left off a call site does not fail to compile —
/// it defaults to null, which every arm reads as "policy off". So the failure mode is silent, and
/// it is always the same shape: a security control that looks configured, is displayed as
/// configured, and quietly never fires on one path.
/// </para>
///
/// <para>
/// This has already happened twice in this codebase. <c>VerifyProvenanceMode</c> was omitted from
/// both request factories, leaving the provenance arm inert on every serve path for every
/// ecosystem. The proxy first-fetch path built its request inline against a tenant-blind projection
/// and so dropped <c>manual_block_state</c> and <c>revoked_at</c>, serving artifacts the cache-hit
/// path would have refused. Both were found by reading, not by a test. Routing every construction
/// through the factories turns the next one into a compile-time question — "which factory?" — and
/// makes a new signal reach every path the moment it is added to the factory.
/// </para>
///
/// <para>
/// Opt-out: <c>// gate-request-ok: &lt;reason&gt;</c> in the 5 lines above the construction. The
/// marker is what makes the exception reviewable; a bare inline construction fails.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed class BlockGateRequestConstructionComplianceTests
{
    private readonly ITestOutputHelper _output;
    public BlockGateRequestConstructionComplianceTests(ITestOutputHelper output) => _output = output;

    private const string Construction = "new BlockGateRequest(";
    private const string OptOut = "gate-request-ok:";

    /// <summary>The one file where the factories live and may construct the record directly.</summary>
    private const string FactoryFile = "BlockGateService.cs";

    [Fact]
    public void BlockGateRequestsAreBuiltByAFactory_NotFieldByFieldAtCallSites()
    {
        var violations = new List<string>();
        int scanned = 0;

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            if (Path.GetFileName(file).Equals(FactoryFile, StringComparison.Ordinal))
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
                    $"{rel}:{i + 1}: BlockGateRequest constructed inline. Build it through a factory on "
                    + "the record (For / ForProxyCacheFacts / ForProxyFirstFetch / ForFirstFetch…) so a "
                    + "newly added gate signal reaches this path too. A deliberate exception needs "
                    + "`// gate-request-ok: <reason>` above it.");
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

            Assert.Fail($"{violations.Count} inline BlockGateRequest construction site(s). See test output.");
        }
    }

    /// <summary>
    /// The factory file must actually contain the factories this gate redirects people to. Without
    /// this, renaming them away would leave the gate pointing at nothing while still passing.
    /// </summary>
    [Fact]
    public void TheFactoryFile_DeclaresEveryFactoryThisGateNames()
    {
        string? factoryPath = SourceRoots.AllCSharpFiles()
            .FirstOrDefault(f => Path.GetFileName(f).Equals(FactoryFile, StringComparison.Ordinal));
        Assert.NotNull(factoryPath);

        string source = File.ReadAllText(factoryPath!);
        foreach (string factory in new[]
                 {
                     "BlockGateRequest For(",
                     "BlockGateRequest ForProxyCacheFacts(",
                     "BlockGateRequest ForProxyFirstFetch(",
                     "BlockGateRequest ForFirstFetchDeprecation(",
                     "BlockGateRequest ForFirstFetchProvenance(",
                 })
        {
            Assert.Contains(factory, source, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// Both proxy factories must read the SAME facts type. That is the structural half of the
    /// first-fetch/cache-hit symmetry: if one took a narrower projection, a fact could exist on one
    /// path and not the other, which is exactly how the first-fetch path came to ignore a tenant's
    /// manual block.
    /// </summary>
    [Fact]
    public void BothProxyFactories_ReadTheSameCacheArtifactFactsType()
    {
        string factoryPath = SourceRoots.AllCSharpFiles()
            .First(f => Path.GetFileName(f).Equals(FactoryFile, StringComparison.Ordinal));
        string source = File.ReadAllText(factoryPath);

        foreach (string factory in new[] { "ForProxyCacheFacts(", "ForProxyFirstFetch(" })
        {
            int start = source.IndexOf(factory, StringComparison.Ordinal);
            Assert.True(start >= 0, $"{factory} not found in {FactoryFile}");

            int bodyStart = source.IndexOf("=>", start, StringComparison.Ordinal);
            Assert.True(bodyStart > start, $"{factory} has no expression body to inspect");

            string signature = source[start..bodyStart];
            Assert.Contains("CacheArtifactServeFacts", signature, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// Scanner self-test: the detector must fire on a bare construction and stand down for an
    /// annotated one, so the gate cannot go green-but-blind after a refactor of either half.
    /// </summary>
    [Theory]
    [InlineData(new[] { "var r = new BlockGateRequest(orgId, eco);" }, true)]
    [InlineData(new[] { "// gate-request-ok: reason", "var r = new BlockGateRequest(orgId, eco);" }, false)]
    [InlineData(new[] { "var r = BlockGateRequest.For(orgId, eco, v, t, s, ip);" }, false)]
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
