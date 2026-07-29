using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check enforcing "the rendered-metadata cache key is built in exactly one place".
///
/// <para><c>MetadataCacheKeys</c> owns every rendered-cache key string. A second, hand-rolled
/// spelling of one of those keys at a call site is the specific defect that produces a
/// <em>partial</em> invalidation — a key that is right for one ecosystem and subtly wrong for
/// another, leaving a stale surface that now looks solved. A hand-rolled
/// <c>$"metadata:{orgId}:npm:{name}"</c> removed straight from the shared <c>IMemoryCache</c>
/// misses npm's <c>:proxy</c> variant, PyPI's <c>:json</c> representation, and both of NuGet's
/// proxy variants, and addresses no Maven or RPM document at all — while reading, at the call
/// site, exactly like a complete eviction.</para>
///
/// <para>Detection is a source scan for a string literal that <em>starts with</em> one of the
/// key namespaces the formatters own (<c>metadata:</c>, <c>rpm:merged-repodata:</c>,
/// <c>rpm:local-repodata:</c>) anywhere outside <c>MetadataCacheKeys.cs</c>. A call site that
/// needs an entry gone routes coordinates through <c>MetadataInvalidationCoordinator</c>, which
/// expands the ecosystem's full variant matrix through those same formatters.</para>
///
/// <para>Opt-out: <c>// cachekey-ok: &lt;reason&gt;</c> on the line or in the 5 lines above.</para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class RenderedCacheKeyComplianceTests
{
    private readonly ITestOutputHelper _output;
    public RenderedCacheKeyComplianceTests(ITestOutputHelper output) => _output = output;

    // A string literal (plain, verbatim, or interpolated) opening with one of the rendered-cache
    // key namespaces. Anchored on the literal's opening quote so a substring inside a longer
    // sentence (a log message, a doc comment) does not match.
    [GeneratedRegex(@"\$?@?""(?:metadata:|rpm:merged-repodata:|rpm:local-repodata:)")]
    private static partial Regex RenderedKeyLiteralRegex();

    [Fact]
    public void RenderedMetadataCacheKeysAreOnlyBuiltByTheirFormatters()
    {
        var violations = new List<string>();

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            // The one place these keys are legitimately built.
            if (Path.GetFileName(file).Equals("MetadataCacheKeys.cs", StringComparison.Ordinal))
            {
                continue;
            }

            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                if (!RenderedKeyLiteralRegex().IsMatch(lines[i]) || HasOptOut(lines, i))
                {
                    continue;
                }

                violations.Add($"{Path.GetRelativePath(SourceRoots.RepoRoot(), file)}:{i + 1}  {lines[i].Trim()}");
            }
        }

        foreach (string violation in violations)
        {
            _output.WriteLine(violation);
        }

        Assert.True(
            violations.Count == 0,
            "Rendered-metadata cache keys must come from MetadataCacheKeys, and evictions must go "
            + "through MetadataInvalidationCoordinator so every ecosystem's key variants are covered. "
            + "A hand-rolled key is how a partial invalidation ships.\n  "
            + string.Join("\n  ", violations));
    }

    private static bool HasOptOut(string[] lines, int index)
    {
        int start = Math.Max(0, index - 5);
        for (int i = start; i <= index; i++)
        {
            if (lines[i].Contains("cachekey-ok:", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
