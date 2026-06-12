using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: no SQL string in the codebase is built by string interpolation
/// (<c>$"…"</c>, <c>$@"…"</c>, or <c>$"""…"""</c>). Interpolating runtime values into a
/// SQL command is the classic injection vector; the project rule is parameterized Dapper
/// only (<c>@name</c> placeholders). This is the interpolation companion to
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

    [Fact]
    public void NoSqlIsBuiltByStringInterpolation()
    {
        string srcRoot = LocateSourceRoot();
        Assert.True(Directory.Exists(srcRoot), $"src root not found at {srcRoot}");

        var violations = new List<string>();
        foreach (string file in Directory.EnumerateFiles(srcRoot, "*.cs", SearchOption.AllDirectories))
        {
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                || file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
            {
                continue;
            }

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

                string rel = Path.GetRelativePath(srcRoot, file);
                violations.Add(
                    $"{rel}:{lineNumber + 1}: SQL built by string interpolation. Use a parameterized " +
                    $"Dapper query (@name placeholders). If the interpolated fragment is a compile-time " +
                    $"constant (e.g. whitelisted ORDER BY), annotate the opening line with " +
                    $"`// rawsql: <reason>`. SQL: {Truncate(match.Sql, 120)}");
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

    private static string LocateSourceRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string candidate = Path.Combine(dir.FullName, "src", "Dependably");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            dir = dir.Parent;
        }
        return string.Empty;
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
