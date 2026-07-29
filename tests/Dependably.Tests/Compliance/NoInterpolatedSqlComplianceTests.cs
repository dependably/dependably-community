using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: no SQL string in the codebase is built by string interpolation
/// (<c>$"…"</c>, <c>$@"…"</c>, or <c>$"""…"""</c>) or by concatenating a SQL-keyword-headed
/// literal onto a non-literal operand (<c>"SELECT … " + ident</c>). Interpolating or splicing
/// runtime values into a SQL command is the classic injection vector; the project rule is
/// parameterized Dapper only (<c>@name</c> placeholders). A literal-to-literal splice
/// (<c>"SELECT … " + "FROM …"</c>) is compiler-folded and safe, so the concatenation arm
/// deliberately does not match it. This is the interpolation companion to
/// <see cref="OrgIdFilteringComplianceTests"/> — same crude static-scan style, runs in the
/// test suite so violations surface locally and on every PR, not only under an analyzer
/// warning nobody reads.
///
/// A handful of legitimate sites interpolate a <b>compile-time-constant</b> SQL fragment
/// (e.g. a whitelisted ORDER BY column, or a <c>const string</c> WHERE clause that itself
/// contains only <c>@param</c> placeholders). Those carry an <c>S2077</c> SuppressMessage
/// and a justification already; mark the opening line with <c>// rawsql: &lt;reason&gt;</c>
/// so this test treats them as reviewed.
///
/// Opt-out: put <c>// rawsql:</c> on the line that opens the interpolated SQL string, or in
/// the small window above it. Example:
/// <code>
///   // rawsql: countWhereClause is a const containing only @param placeholders
///   var n = await conn.ExecuteScalarAsync&lt;int&gt;(
///       $"SELECT COUNT(*) FROM audit_log WHERE {countWhereClause}", args);
/// </code>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class NoInterpolatedSqlComplianceTests
{
    private readonly ITestOutputHelper _output;
    public NoInterpolatedSqlComplianceTests(ITestOutputHelper output) => _output = output;

    // Interpolated raw string: $"""  …  """  (Singleline so multi-line SQL is captured).
    [GeneratedRegex(@"\$""""""\s*(?<sql>.*?)\s*""""""", RegexOptions.Singleline)]
    private static partial Regex InterpolatedRawRegex();

    // Interpolated verbatim string: $@"…" or @$"…" (doubled "" is an escaped quote).
    [GeneratedRegex(@"(?:\$@|@\$)""(?<sql>(?:[^""]|"""")*)""", RegexOptions.Singleline)]
    private static partial Regex InterpolatedVerbatimRegex();

    // Interpolated regular string: $"…" on a single logical line (\\ is a literal backslash).
    [GeneratedRegex(@"\$""(?<sql>(?:[^""\\]|\\.)*)""")]
    private static partial Regex InterpolatedRegularRegex();

    // Concatenated SQL: a plain string literal spliced onto a NON-literal operand — "…" + ident,
    // "…" + (expr), "…" + method(...). The trailing [A-Za-z_(] excludes a following quote, so a
    // safe literal-to-literal fold ("…" + "…") is not matched. LooksLikeSql then narrows to
    // operands whose captured literal actually opens with a SQL keyword.
    [GeneratedRegex(@"""(?<sql>(?:[^""\\]|\\.)*)""\s*\+\s*[A-Za-z_(]", RegexOptions.Singleline)]
    private static partial Regex ConcatenatedSqlRegex();

    [Fact]
    public void NoSqlIsBuiltByStringInterpolation()
    {
        var violations = new List<string>();
        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string[] lines = File.ReadAllLines(file);
            string source = string.Join('\n', lines);

            foreach (var match in EnumerateInterpolatedLiterals(source))
            {
                if (!LooksLikeSql(match.Sql))
                {
                    continue;
                }

                int lineNumber = CountLinesUpTo(source, match.StartIndex);
                if (HasOptOutComment(lines, lineNumber))
                {
                    continue;
                }

                string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
                violations.Add(
                    $"{rel}:{lineNumber + 1}: SQL built by string interpolation. Use a parameterized " +
                    $"Dapper query (@name placeholders). If the interpolated fragment is a compile-time " +
                    $"constant (e.g. whitelisted ORDER BY), annotate the opening line with " +
                    $"`// rawsql: <reason>`. SQL: {Truncate(match.Sql, 120)}");
            }

            foreach (var match in EnumerateConcatenatedSqlLiterals(source))
            {
                if (!LooksLikeSql(match.Sql))
                {
                    continue;
                }

                int lineNumber = CountLinesUpTo(source, match.StartIndex);
                if (HasOptOutComment(lines, lineNumber))
                {
                    continue;
                }

                string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
                violations.Add(
                    $"{rel}:{lineNumber + 1}: SQL built by string concatenation onto a non-literal " +
                    $"operand. Use a parameterized Dapper query (@name placeholders). If every spliced " +
                    $"operand is itself a compile-time constant (a body `const`, a DapperInClause IN list), " +
                    $"annotate the opening line with `// rawsql: <reason>`. SQL: {Truncate(match.Sql, 120)}");
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} interpolated SQL literal(s) found. " +
                        $"See test output for the full list and remediation hint.");
        }
    }

    private record struct SqlMatch(string Sql, int StartIndex);

    private static IEnumerable<SqlMatch> EnumerateInterpolatedLiterals(string source)
    {
        foreach (Match m in InterpolatedRawRegex().Matches(source))
        {
            yield return new SqlMatch(m.Groups["sql"].Value, m.Index);
        }

        foreach (Match m in InterpolatedVerbatimRegex().Matches(source))
        {
            yield return new SqlMatch(m.Groups["sql"].Value, m.Index);
        }

        foreach (Match m in InterpolatedRegularRegex().Matches(source))
        {
            yield return new SqlMatch(m.Groups["sql"].Value, m.Index);
        }
    }

    private static IEnumerable<SqlMatch> EnumerateConcatenatedSqlLiterals(string source)
    {
        foreach (Match m in ConcatenatedSqlRegex().Matches(source))
        {
            yield return new SqlMatch(m.Groups["sql"].Value, m.Index);
        }
    }

    // ── Self-tests: the concatenation arm sees a runtime splice and ignores the safe forms. ──

    [Fact]
    public void ConcatScanner_FlagsSqlLiteralSplicedOntoIdentifier()
    {
        const string bad = "\"DELETE FROM quarantine WHERE id IN \" + idsClause";
        var hits = EnumerateConcatenatedSqlLiterals(bad).Where(m => LooksLikeSql(m.Sql)).ToList();
        Assert.Single(hits);
    }

    [Fact]
    public void ConcatScanner_IgnoresLiteralToLiteralFold()
    {
        // "SELECT … " + "FROM …" is compiler-folded; no runtime value enters, so it is not a hit.
        const string good = "\"SELECT id \" + \"FROM instance_lock WHERE id = @id\"";
        var hits = EnumerateConcatenatedSqlLiterals(good).Where(m => LooksLikeSql(m.Sql)).ToList();
        Assert.Empty(hits);
    }

    [Fact]
    public void ConcatScanner_IgnoresNonSqlConcatenation()
    {
        // A non-SQL literal spliced onto an identifier (paths, log messages) is not SQL.
        const string good = "\"artifacts/\" + orgId + \"/blob\"";
        var hits = EnumerateConcatenatedSqlLiterals(good).Where(m => LooksLikeSql(m.Sql)).ToList();
        Assert.Empty(hits);
    }

    private static bool LooksLikeSql(string s)
    {
        // A SQL command string starts with one of these top-level keywords. Capitalized so
        // an interpolated English/log/URL string ("Transition '{x}' …", "https://…") never
        // matches — only deliberate SQL does.
        var head = s.TrimStart().AsSpan();
        return StartsWithKeyword(head, "SELECT")
            || StartsWithKeyword(head, "INSERT")
            || StartsWithKeyword(head, "UPDATE")
            || StartsWithKeyword(head, "DELETE")
            || StartsWithKeyword(head, "WITH")
            || StartsWithKeyword(head, "CREATE");
    }

    private static bool StartsWithKeyword(ReadOnlySpan<char> s, string keyword)
        => s.Length >= keyword.Length
            && s[..keyword.Length].SequenceEqual(keyword.AsSpan())
            && (s.Length == keyword.Length || char.IsWhiteSpace(s[keyword.Length]));

    private static int CountLinesUpTo(string source, int index)
    {
        int count = 0;
        for (int i = 0; i < index && i < source.Length; i++)
        {
            if (source[i] == '\n')
            {
                count++;
            }
        }

        return count;
    }

    private static bool HasOptOutComment(string[] lines, int lineIndex)
    {
        // The marker may sit on the opening line or a few lines above it (the call often
        // spans `await conn.ExecuteAsync(\n    $"…"`). Five lines mirrors the xtenant window.
        for (int probe = Math.Max(0, lineIndex - 5); probe <= lineIndex && probe < lines.Length; probe++)
        {
            if (lines[probe].Contains("rawsql:", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string Truncate(string s, int max)
    {
        s = s.Replace('\n', ' ').Replace('\r', ' ').Trim();
        return s.Length <= max ? s : s[..max] + "...";
    }
}
