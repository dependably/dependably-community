using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check enforcing the architectural rule "PURLs are the canonical package identity;
/// <c>PurlNormalizer</c> is the single source of truth" (see CLAUDE.md → Key architectural
/// rules). A PURL is built by calling <c>PurlNormalizer.…</c>, never by interpolating or
/// concatenating <c>"pkg:&lt;type&gt;/…"</c> at the call site.
///
/// <para>The rule had no gate, and thirteen OCI call sites drifted off it: the controllers
/// interpolated <c>pkg:oci/{repository}@{digest}</c> while every catalogue writer went through
/// <see cref="Dependably.Protocol.PurlNormalizer"/>, so one image was recorded under two
/// spellings — one of which folds the namespace into the name and leaves the digest's colon
/// unencoded, and is therefore not a valid PURL at all. Nothing failed; the rows simply
/// disagreed. A regex is what makes the fourteenth site a red build instead.</para>
///
/// <para>Scope: interpolated or concatenated <c>pkg:</c> literals in <c>src/**</c>.
/// A plain literal with no interpolation hole and no concatenation is left alone — a fixed
/// string such as a test fixture's constant or a prefix used for a <c>LIKE</c> predicate names
/// no package and cannot drift per call site. <c>PurlNormalizer.cs</c> is excluded: it is the
/// one place PURLs are legitimately assembled.</para>
///
/// <para>Opt-out: annotate the line (or the five lines above it) with
/// <c>// purl-ok: &lt;reason&gt;</c>.</para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class PurlConstructionComplianceTests
{
    private readonly ITestOutputHelper _output;
    public PurlConstructionComplianceTests(ITestOutputHelper output) => _output = output;

    // An interpolated PURL literal: $"pkg:npm/{name}@{version}" and friends. Requires an
    // interpolation hole somewhere in the literal, so a fixed prefix constant does not match.
    [GeneratedRegex(@"\$@?""pkg:[a-z]+/[^""]*\{", RegexOptions.None)]
    private static partial Regex InterpolatedPurlRegex();

    // A concatenated PURL literal: "pkg:oci/" + repository + "@" + digest.
    [GeneratedRegex(@"@?""pkg:[a-z]+/[^""]*""\s*\+", RegexOptions.None)]
    private static partial Regex ConcatenatedPurlRegex();

    [Fact]
    public void PurlsAreOnlyBuiltByPurlNormalizer()
    {
        var violations = new List<string>();
        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            // PurlNormalizer is the one place PURLs are legitimately assembled.
            if (Path.GetFileName(file).Equals("PurlNormalizer.cs", StringComparison.Ordinal))
            {
                continue;
            }

            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                if (!InterpolatedPurlRegex().IsMatch(lines[i]) && !ConcatenatedPurlRegex().IsMatch(lines[i]))
                {
                    continue;
                }

                if (HasOptOutComment(lines, i))
                {
                    continue;
                }

                string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
                violations.Add(
                    $"{rel}:{i + 1}: PURL built inline. Construct it via PurlNormalizer.… instead, so " +
                    $"every plane records the same identity for the same artefact. If this string is " +
                    $"deliberately not a package identity (e.g. a prefix for a LIKE predicate), " +
                    $"annotate with `// purl-ok: <reason>`. Line: {Truncate(lines[i].Trim(), 120)}");
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} inline PURL construction site(s) found. " +
                        $"See test output for the full list and remediation hint.");
        }
    }

    private static bool HasOptOutComment(string[] lines, int lineIndex)
    {
        for (int probe = Math.Max(0, lineIndex - 5); probe <= lineIndex && probe < lines.Length; probe++)
        {
            if (lines[probe].Contains("purl-ok:", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}
