using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: a positional record used as a Dapper query type argument and declaring a
/// non-string member carries <c>[method: ExplicitConstructor]</c>.
///
/// Dapper's default binding for a positional record demands that the constructor signature match
/// the reader's CLR column types <em>exactly</em> — and the two supported providers report
/// different CLR types for the same declared column. SQLite reports every <c>INTEGER</c> as
/// <c>Int64</c>; Postgres reports <c>INTEGER</c> (int4) as <c>Int32</c>. One fixed signature
/// therefore cannot satisfy both: whichever provider it was written against works, and the other
/// throws <c>InvalidOperationException ("A parameterless default constructor or one matching
/// signature … is required for … materialization")</c> at runtime, on the first read.
///
/// <c>[ExplicitConstructor]</c> names the constructor for Dapper instead of matching it, which
/// moves binding onto Dapper's converting path — the same path property-mapped classes already
/// use. That path widens either provider's integer into the declared member type and throws on an
/// out-of-range value rather than truncating, so the resulting projection is provider-portable by
/// construction, with no per-provider SQL and no cast in the SELECT list.
///
/// This gate exists because the failure is invisible to the rest of the suite: every test but the
/// <c>Category=SchemaPostgres</c> family runs on SQLite, where a SQLite-shaped signature is
/// correct by definition. <see cref="Dependably.Tests.Integration"/>'s
/// <c>PostgresRecordMaterializationTests</c> is the runtime counterpart, exercising the reachable
/// read paths against a live server; this scan covers the ones a test cannot reach — private
/// records inside controllers — and every projection added later.
///
/// Scope note: only positional records are affected. A class or a body-form record binds through
/// Dapper's property setters, which already convert, so those need nothing. Members typed
/// <c>string</c> are provider-identical (<c>TEXT</c> is <c>string</c> on both), which is why the
/// rule keys on a record having at least one non-string member.
///
/// Trade accepted: on the converting path a constructor parameter with no matching column binds
/// to <c>default</c> instead of throwing. That is why the live-Postgres counterpart asserts the
/// seeded values rather than merely that the read did not throw.
///
/// Opt-out: <c>// dapper-record-ok: &lt;reason&gt;</c> within the 5 lines above the declaration.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class DapperPositionalRecordComplianceTests
{
    private readonly ITestOutputHelper _output;
    public DapperPositionalRecordComplianceTests(ITestOutputHelper output) => _output = output;

    // Dapper's generic read entry points. ExecuteScalarAsync<T> is deliberately absent: it goes
    // through Dapper's Parse<T>/ChangeType conversion, not the constructor matcher.
    [GeneratedRegex(@"Query(?:Single|First)?(?:OrDefault)?Async<([A-Za-z_][A-Za-z0-9_.]*)\??>")]
    private static partial Regex DapperTypeArgRegex();

    // A positional record declaration: `record Name(` / `record struct Name(`, capturing the name.
    [GeneratedRegex(@"\brecord\s+(?:struct\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(")]
    private static partial Regex PositionalRecordRegex();

    [GeneratedRegex(@"\b(?:long|int|short|byte|sbyte|uint|ulong|ushort|double|float|decimal|bool)\b\??\s+[A-Za-z_]")]
    private static partial Regex NonStringMemberRegex();

    [Fact]
    public void PositionalRecordsBoundByDapperDeclareAnExplicitConstructor()
    {
        string repoRoot = SourceRoots.RepoRoot();
        var files = SourceRoots.AllCSharpFiles().ToList();

        var boundTypeNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (string file in files)
        {
            foreach (Match m in DapperTypeArgRegex().Matches(File.ReadAllText(file)))
            {
                // Strip any namespace/containing-type qualifier: declarations are matched by
                // simple name.
                string name = m.Groups[1].Value;
                boundTypeNames.Add(name[(name.LastIndexOf('.') + 1)..]);
            }
        }

        Assert.NotEmpty(boundTypeNames);

        var violations = new List<string>();
        foreach (string file in files)
        {
            string text = File.ReadAllText(file);
            string[] lines = File.ReadAllLines(file);

            foreach (Match m in PositionalRecordRegex().Matches(text))
            {
                string name = m.Groups[1].Value;
                if (!boundTypeNames.Contains(name))
                {
                    continue;
                }

                string? parameters = ReadBalancedParameterList(text, m.Index + m.Length - 1);
                if (parameters is null || !NonStringMemberRegex().IsMatch(parameters))
                {
                    continue;
                }

                int line = text.Take(m.Index).Count(c => c == '\n');
                if (HasExplicitConstructor(lines, line) || HasOptOut(lines, line))
                {
                    continue;
                }

                violations.Add(
                    $"{Path.GetRelativePath(repoRoot, file)}:{line + 1}: positional record `{name}` is bound " +
                    "by Dapper and declares a non-string member, but carries no " +
                    "`[method: ExplicitConstructor]`.");
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail(
                $"{violations.Count} Dapper-bound positional record(s) without [method: ExplicitConstructor]. " +
                "Without it Dapper matches the constructor against the reader's CLR column types, which " +
                "differ per provider (SQLite reports INTEGER as Int64, Postgres as Int32), so the " +
                "projection throws at runtime on whichever provider it was not written against — " +
                "invisibly, because the suite runs on SQLite. Add `[method: ExplicitConstructor]` above " +
                "the declaration, or annotate `// dapper-record-ok: <reason>`. See test output.");
        }
    }

    /// <summary>
    /// Returns the text between the parameter list's parentheses, given the index of its opening
    /// parenthesis, or null when the list is unbalanced. Counting depth (rather than matching to
    /// the first <c>)</c>) is what keeps a parameter carrying a default or an attribute from
    /// truncating the list.
    /// </summary>
    private static string? ReadBalancedParameterList(string text, int openParenIndex)
    {
        int depth = 0;
        for (int i = openParenIndex; i < text.Length; i++)
        {
            if (text[i] == '(')
            {
                depth++;
            }
            else if (text[i] == ')')
            {
                depth--;
                if (depth == 0)
                {
                    return text[(openParenIndex + 1)..i];
                }
            }
        }

        return null;
    }

    private static bool HasExplicitConstructor(string[] lines, int declarationLine)
    {
        for (int probe = Math.Max(0, declarationLine - 5); probe <= declarationLine && probe < lines.Length; probe++)
        {
            if (lines[probe].Contains("method: ExplicitConstructor", StringComparison.Ordinal)
                || lines[probe].Contains("method: Dapper.ExplicitConstructor", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasOptOut(string[] lines, int declarationLine)
    {
        for (int probe = Math.Max(0, declarationLine - 5); probe <= declarationLine && probe < lines.Length; probe++)
        {
            if (lines[probe].Contains("dapper-record-ok:", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
