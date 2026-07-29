using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: no source formats a timestamp with an inline pattern. Every timestamp
/// written to the database or emitted on the wire goes through
/// <c>UtcTimestamp.ToUtcIso()</c> / <c>UtcTimestamp.Now()</c> (or the millisecond/microsecond
/// siblings documented on <see cref="Dependably.Infrastructure.UtcTimestamp"/>).
///
/// The inline form is not a style question. In a .NET custom format string the trailing
/// <c>Z</c> is a literal, not a conversion, so formatting a non-UTC
/// <see cref="DateTimeOffset"/> against <c>yyyy-MM-ddTHH:mm:ssZ</c> emits that value's
/// wall-clock time and stamps <c>Z</c> on it — a timestamp wrong by the offset, in a column
/// whose lexicographic comparisons then silently misorder. Instants reaching these call
/// sites from upstream registry metadata, X.509 certificates, SAML assertions, and request
/// bodies all carry the offset they arrived with. The extension method converts to UTC
/// first, so routing every site through it is what makes "the database stores UTC" an
/// invariant rather than a convention.
///
/// Three patterns are banned over <c>src/**</c>:
/// <list type="bullet">
/// <item>the literal canonical/millisecond pattern as an inline <c>ToString(…)</c> argument
/// (<see cref="InlineTimestampFormatRegex"/>) — including a line-wrapped
/// <c>ToString(</c>-then-newline-then-format-string split across lines;</item>
/// <item><c>ToString("o")</c> / <c>ToString("O")</c> (<see cref="RoundtripFormatRegex"/>) —
/// the round-trip specifier emits 7 fractional digits and a <c>+00:00</c>/other offset suffix
/// rather than the canonical <c>Z</c> form. The pre-fix global <c>DateTimeOffsetHandler</c>
/// (<c>SchemaInitializer.OwnerPlane.cs</c>) itself called this exact specifier in its
/// <c>SetValue</c> — but that line never actually ran: Dapper's built-in type map claims
/// <see cref="DateTimeOffset"/> for parameter binding ahead of a registered
/// <c>ITypeHandler</c> unless the type is first removed from the map, so every raw-bound
/// <see cref="DateTimeOffset"/> parameter fell through to the ADO.NET provider's own
/// serialization instead — space-separated, offset preserved, never the "o" shape the dead
/// code would have produced. This pattern is banned regardless, since a call site that does
/// reach it directly has the same wrong-shape hazard; legitimate WIRE-format uses (an
/// external API field, not a DB write) opt out with <c>// utcformat-ok:</c>, same as any
/// other flagged line;</item>
/// <item>a C# interpolated string embedding the canonical format specifier
/// (<c>$"{x:yyyy-MM-dd…}"</c>, <see cref="InterpolatedTimestampFormatRegex"/>) — the same
/// literal-<c>Z</c> hazard as the plain <c>ToString(…)</c> form, just spelled as string
/// interpolation instead of a method call.</item>
/// </list>
///
/// The scan joins each file's lines into one text blob (blanking whole-line comments first, so
/// a marker or a discussion of the pattern in prose doesn't self-trigger) before matching, so a
/// wrapped <c>ToString(\n "yyyy-MM-dd…</c> spanning two lines is caught exactly like the
/// single-line form — a per-line regex misses it.
///
/// Opt-out: a deliberate non-canonical format annotates with
/// <c>// utcformat-ok: &lt;reason&gt;</c> on the same line or within the 5 lines above
/// (the same window as <c>// now-ok:</c> / <c>// rawsql:</c> / <c>// xtenant:</c>).
///
/// The <c>ToString("o"/"O")</c> and interpolated-specifier checks run over <c>src/**</c> only.
/// Tests seed a large number of rows directly with <c>.ToString("o")</c> as a raw-SQL TEXT
/// parameter (not through the Dapper <see cref="DateTimeOffset"/> handler this gate's sibling
/// fix hardens) to construct fixture timestamps at an exact instant; that is a test-authoring
/// convention distinct from a production write path and out of scope here.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class UtcTimestampFormatComplianceTests
{
    private readonly ITestOutputHelper _output;
    public UtcTimestampFormatComplianceTests(ITestOutputHelper output) => _output = output;

    // The canonical pattern used as an inline format-string argument. Split so this file's
    // own source text does not match the pattern it bans.
    [GeneratedRegex("""ToString\(\s*"yyyy-MM-dd[T ]HH:mm:ss""", RegexOptions.Singleline)]
    private static partial Regex InlineTimestampFormatRegex();

    // ToString("o") / ToString("O") — the round-trip specifier. Banned for storage writes;
    // legitimate wire-format uses opt out with `// utcformat-ok:`. A plain escaped literal
    // (not a raw string) because the pattern ends in a quote character, which would collide
    // with a raw string's closing delimiter.
    [GeneratedRegex("ToString\\(\\s*\"[oO]\"", RegexOptions.Singleline)]
    private static partial Regex RoundtripFormatRegex();

    // A C# interpolated string embedding the canonical format specifier, e.g.
    // $"{last.CreatedAt:yyyy-MM-ddTHH:mm:ssZ}|{last.Id}". Deliberately requires the `$"` marker
    // immediately preceding the interpolation hole (not just any `{…:yyyy-MM-dd…}`), so a
    // Serilog output-template string literal — which uses the identical `{Timestamp:…}` syntax
    // but is never prefixed with `$` — does not false-positive.
    [GeneratedRegex("\\$\"(?:[^\"\\\\]|\\\\.)*?\\{[^{}]*:yyyy-MM-dd[^{}]*\\}", RegexOptions.Singleline)]
    private static partial Regex InterpolatedTimestampFormatRegex();

    [Fact]
    public void SrcFormatsTimestampsThroughUtcTimestamp()
    {
        AssertNoInlineFormats(SourceRoots.All().ToArray(), "src", includeStorageOnlyPatterns: true);
    }

    [Fact]
    public void TestsFormatTimestampsThroughUtcTimestamp()
    {
        // Tests seed rows the production readers parse back, so a test that hand-formats a
        // timestamp can assert a shape the writer never actually produces. The storage-only
        // patterns (ToString("o"/"O"), interpolated specifier) are NOT scanned here — see the
        // class summary for why test fixture seeding is out of scope for those two.
        AssertNoInlineFormats([Path.Combine(SourceRoots.RepoRoot(), "tests")], "tests", includeStorageOnlyPatterns: false);
    }

    private void AssertNoInlineFormats(string[] roots, string label, bool includeStorageOnlyPatterns)
    {
        string repoRoot = SourceRoots.RepoRoot();
        var violations = new List<string>();

        foreach (string root in roots)
        {
            foreach (string file in EnumerateSource(root))
            {
                // This scanner and the helper it enforces both name the banned pattern.
                string name = Path.GetFileName(file);
                if (name is nameof(UtcTimestampFormatComplianceTests) + ".cs" or "UtcTimestamp.cs")
                {
                    continue;
                }

                string[] lines = File.ReadAllLines(file);
                string joined = JoinNonCommentLines(lines);

                CollectViolations(InlineTimestampFormatRegex(), joined, lines, file, repoRoot,
                    "inline timestamp format", violations);

                if (includeStorageOnlyPatterns)
                {
                    CollectViolations(RoundtripFormatRegex(), joined, lines, file, repoRoot,
                        "ToString(\"o\"/\"O\") round-trip format", violations);
                    CollectViolations(InterpolatedTimestampFormatRegex(), joined, lines, file, repoRoot,
                        "interpolated timestamp format specifier", violations);
                }
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} inline timestamp format(s) in {label}. The trailing `Z` in a " +
                        "custom format string is a literal, not a UTC conversion, so a non-UTC instant is " +
                        "stored wrong by its offset; the round-trip \"o\"/\"O\" specifier emits an offset " +
                        "suffix instead of `Z` and extra fractional digits most columns don't carry. Format " +
                        "through UtcTimestamp, or annotate a deliberate exception with " +
                        "`// utcformat-ok: <reason>`. See test output.");
        }
    }

    private static void CollectViolations(
        Regex pattern, string joined, string[] lines, string file, string repoRoot,
        string label, List<string> violations)
    {
        foreach (Match m in pattern.Matches(joined))
        {
            int lineIndex = joined[..m.Index].Count(c => c == '\n');
            if (HasOptOut(lines, lineIndex))
            {
                continue;
            }

            string snippet = lines[Math.Min(lineIndex, lines.Length - 1)].Trim();
            violations.Add(
                $"{Path.GetRelativePath(repoRoot, file)}:{lineIndex + 1}: {label} — " +
                $"use UtcTimestamp.ToUtcIso()/ToUtcIsoMillis()/ToUtcIsoPrecise(), or annotate " +
                $"`// utcformat-ok: <reason>`. {snippet}");
        }
    }

    /// <summary>
    /// Joins every line with <c>\n</c> after blanking whole-line comments (preserving line
    /// count and each surviving line's column offsets, so a match's line number is exact) —
    /// this is what lets a construct split across lines (e.g. <c>ToString(\n "yyyy-MM-dd…</c>)
    /// match as one occurrence instead of being missed by a per-line scan, while a comment that
    /// merely discusses the banned pattern never contributes text to match against.
    /// </summary>
    private static string JoinNonCommentLines(string[] lines)
    {
        string[] kept = new string[lines.Length];
        for (int i = 0; i < lines.Length; i++)
        {
            kept[i] = lines[i].TrimStart().StartsWith("//") ? "" : lines[i];
        }

        return string.Join('\n', kept);
    }

    private static bool HasOptOut(string[] lines, int lineIndex)
    {
        for (int probe = Math.Max(0, lineIndex - 5); probe <= lineIndex && probe < lines.Length; probe++)
        {
            if (lines[probe].Contains("utcformat-ok:", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static IEnumerable<string> EnumerateSource(string root)
    {
        foreach (string file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
        {
            string p = file.Replace('\\', '/');
            if (p.Contains("/obj/") || p.Contains("/bin/"))
            {
                continue;
            }

            yield return file;
        }
    }
}
