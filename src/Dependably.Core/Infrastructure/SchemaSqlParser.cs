using System.Text;
using System.Text.RegularExpressions;

namespace Dependably.Infrastructure;

/// <summary>
/// Minimal, dependency-free parser for the hand-maintained Schema.sql / Schema.pg.sql DDL files.
/// Extracts, per <c>CREATE TABLE</c>, the column names declared in its body — ignoring table-level
/// constraint clauses (<c>PRIMARY KEY (...)</c>, <c>UNIQUE (...)</c>, <c>CHECK (...)</c>, …).
///
/// The scan is comment-, paren-depth- and string-literal-aware, so that <c>DEFAULT (strftime(...))</c>
/// and <c>CHECK (status IN ('a','b'))</c> expressions — which carry commas, parens, and apostrophes —
/// don't confuse the column/constraint split. It is NOT a general SQL parser; it only needs to cope
/// with the shapes these two files actually use.
///
/// Pure text processing over the embedded DDL — no I/O, no database, no dependency beyond
/// <see cref="Regex"/>. That is what lets the same parser serve both the static schema-compliance
/// gates (which read the files off disk) and <see cref="SchemaInitializer"/>'s Postgres
/// canonical-timestamp CHECK retrofit (which parses the embedded resource the apply already read),
/// so the retrofit's column set is derived from the very text a fresh install is created from
/// rather than from a hand-copied list that can drift from it.
/// </summary>
internal static partial class SchemaSqlParser
{
    [GeneratedRegex(@"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?<name>""?\w+""?)\s*\(", RegexOptions.IgnoreCase)]
    private static partial Regex CreateTableHeaderRegex();

    [GeneratedRegex(@"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?<name>""?\w+""?)", RegexOptions.IgnoreCase)]
    private static partial Regex CreateTableNameRegex();

    [GeneratedRegex(@"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?(?<name>""?\w+""?)", RegexOptions.IgnoreCase)]
    private static partial Regex CreateIndexNameRegex();

    [GeneratedRegex(@"\bCHECK\s*\(", RegexOptions.IgnoreCase)]
    private static partial Regex CheckKeywordRegex();

    private static readonly string[] ConstraintLeaders = ["PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"];

    /// <summary>Maps table name → ordered column names declared in its CREATE TABLE body (comments stripped).</summary>
    public static Dictionary<string, List<string>> ParseTables(string sql) =>
        ParseTableDefinitions(sql).ToDictionary(
            kv => kv.Key,
            kv => kv.Value.Columns.Select(c => c.Name).ToList(),
            StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Maps table name → its full <c>CREATE TABLE</c> shape: every column with the raw text of its
    /// declaration, plus the table-level constraint items. The raw text is what the nullability /
    /// DEFAULT / inline-CHECK inspections read — the backward-compatibility gate's, and
    /// <see cref="SchemaInitializer"/>'s search for the canonical-timestamp CHECK text; the column
    /// split itself is shared with <see cref="ParseTables"/> so both views agree on what a column is.
    /// </summary>
    public static Dictionary<string, SchemaTable> ParseTableDefinitions(string sql)
    {
        string clean = StripComments(sql);
        var tables = new Dictionary<string, SchemaTable>(StringComparer.OrdinalIgnoreCase);
        foreach (Match header in CreateTableHeaderRegex().Matches(clean))
        {
            // The header regex ends at the opening '('. Bracket-match to find the table body.
            int openParen = header.Index + header.Length - 1;
            int closeParen = MatchingParen(clean, openParen);
            if (closeParen < 0)
            {
                continue;
            }

            var (columns, constraints) = ParseTableBody(clean[(openParen + 1)..closeParen]);
            string table = Unquote(header.Groups["name"].Value);
            tables[table] = new SchemaTable(table, columns, constraints);
        }
        return tables;
    }

    /// <summary>
    /// Splits one <c>CREATE TABLE</c> body (already bracket-matched to its opening/closing parens)
    /// into its column declarations and its table-level constraint items.
    /// </summary>
    private static (List<SchemaColumn> Columns, List<string> Constraints) ParseTableBody(string body)
    {
        var columns = new List<SchemaColumn>();
        var constraints = new List<string>();
        foreach (string item in SplitTopLevel(body))
        {
            string trimmed = item.Trim();
            if (trimmed.Length == 0)
            {
                continue;
            }

            if (IsConstraint(trimmed))
            {
                constraints.Add(trimmed);
                continue;
            }

            string name = Unquote(FirstToken(trimmed));
            if (name.Length > 0)
            {
                columns.Add(new SchemaColumn(name, trimmed));
            }
        }
        return (columns, constraints);
    }

    /// <summary>
    /// The <c>CHECK (...)</c> expression bodies inside a single table-body item — the parenthesised
    /// text after each <c>CHECK</c> keyword, bracket-matched so a nested expression survives whole.
    /// </summary>
    public static List<string> CheckExpressions(string item)
    {
        var found = new List<string>();
        foreach (Match m in CheckKeywordRegex().Matches(item))
        {
            int open = m.Index + m.Length - 1;
            int close = MatchingParen(item, open);
            if (close > open)
            {
                found.Add(item[(open + 1)..close]);
            }
        }
        return found;
    }

    /// <summary>The item text with every <c>CHECK (...)</c> expression removed, so keyword scans for
    /// <c>NOT NULL</c> / <c>DEFAULT</c> can't be fooled by an <c>IS NOT NULL</c> inside a constraint.</summary>
    public static string WithoutCheckExpressions(string item)
    {
        string result = item;
        foreach (var m in CheckKeywordRegex().Matches(item).OrderByDescending(m => m.Index))
        {
            int open = m.Index + m.Length - 1;
            int close = MatchingParen(result, open);
            if (close > open)
            {
                result = result.Remove(m.Index, close - m.Index + 1);
            }
        }
        return result;
    }

    public static List<string> CreatedTableNames(string sql) =>
        CreateTableNameRegex().Matches(StripComments(sql)).Select(m => Unquote(m.Groups["name"].Value)).ToList();

    public static List<string> CreatedIndexNames(string sql) =>
        CreateIndexNameRegex().Matches(StripComments(sql)).Select(m => Unquote(m.Groups["name"].Value)).ToList();

    /// <summary>Removes <c>-- line</c> and <c>/* block */</c> comments, leaving string literals intact.</summary>
    public static string StripComments(string sql)
    {
        var sb = new StringBuilder(sql.Length);
        for (int i = 0; i < sql.Length; i++)
        {
            char c = sql[i];
            if (c is '\'' or '"')
            {
                int end = SkipStringLiteral(sql, i);
                sb.Append(sql, i, end - i + 1);
                i = end;
                continue;
            }

            if (c == '-' && i + 1 < sql.Length && sql[i + 1] == '-')
            {
                i = SkipLineComment(sql, i);
                if (i < sql.Length)
                {
                    sb.Append('\n');
                }

                continue;
            }

            if (c == '/' && i + 1 < sql.Length && sql[i + 1] == '*')
            {
                i = SkipBlockComment(sql, i);
                continue;
            }

            sb.Append(c);
        }
        return sb.ToString();
    }

    // Index of the '\n' ending a "-- ..." line comment starting at commentStart (s[commentStart]
    // is the first '-'), or s.Length when the comment runs to end of file.
    private static int SkipLineComment(string s, int commentStart)
    {
        int i = commentStart;
        while (i < s.Length && s[i] != '\n')
        {
            i++;
        }

        return i;
    }

    // Index of the '/' closing a "/* ... */" comment starting at commentStart (s[commentStart] is
    // '/', s[commentStart + 1] is '*'), or s.Length - 1 when the comment runs to end of file.
    private static int SkipBlockComment(string s, int commentStart)
    {
        int i = commentStart + 2;
        while (i + 1 < s.Length && !(s[i] == '*' && s[i + 1] == '/'))
        {
            i++;
        }

        return i + 1;
    }

    // Index of the closing quote matching the opening quote at s[openIndex] (handling the
    // doubled-quote '' / "" escape), or s.Length - 1 when the literal is unterminated. Shared by
    // every scan below so "is this character inside a string literal" is answered in one place.
    private static int SkipStringLiteral(string s, int openIndex)
    {
        char quote = s[openIndex];
        for (int i = openIndex + 1; i < s.Length; i++)
        {
            if (s[i] != quote)
            {
                continue;
            }

            if (i + 1 < s.Length && s[i + 1] == quote)
            {
                i++; // escaped '' / ""
                continue;
            }

            return i;
        }

        return s.Length - 1;
    }

    // Index of the ')' closing the '(' at openIndex, or -1. String-literal aware.
    private static int MatchingParen(string s, int openIndex)
    {
        int depth = 0;
        for (int i = openIndex; i < s.Length; i++)
        {
            char c = s[i];
            if (c is '\'' or '"')
            {
                i = SkipStringLiteral(s, i);
                continue;
            }

            switch (c)
            {
                case '(': depth++; break;
                case ')':
                    if (--depth == 0)
                    {
                        return i;
                    }

                    break;
            }
        }
        return -1;
    }

    // Splits a table body into top-level items on commas at paren depth 0 (string-aware).
    private static IEnumerable<string> SplitTopLevel(string body)
    {
        int depth = 0, start = 0;
        for (int i = 0; i < body.Length; i++)
        {
            char c = body[i];
            if (c is '\'' or '"')
            {
                i = SkipStringLiteral(body, i);
                continue;
            }

            switch (c)
            {
                case '(': depth++; break;
                case ')': depth--; break;
                case ',' when depth == 0:
                    yield return body[start..i];
                    start = i + 1;
                    break;
            }
        }
        if (start < body.Length)
        {
            yield return body[start..];
        }
    }

    private static bool IsConstraint(string item)
    {
        foreach (string leader in ConstraintLeaders)
        {
            if (item.StartsWith(leader, StringComparison.OrdinalIgnoreCase)
                && (item.Length == leader.Length || !(char.IsLetterOrDigit(item[leader.Length]) || item[leader.Length] == '_')))
            {
                return true;
            }
        }

        return false;
    }

    private static string FirstToken(string item)
    {
        int i = 0;
        while (i < item.Length && !char.IsWhiteSpace(item[i]) && item[i] != '(')
        {
            i++;
        }

        return item[..i];
    }

    private static string Unquote(string s) => s.Trim('"', '`', '[', ']');
}

/// <summary>One column of a <c>CREATE TABLE</c> body: its name and the raw text of its declaration
/// (type, <c>NOT NULL</c>, <c>DEFAULT</c>, inline <c>CHECK</c>, …), comments already stripped.</summary>
internal sealed record SchemaColumn(string Name, string Declaration);

/// <summary>A parsed <c>CREATE TABLE</c>: its columns in declaration order plus the table-level
/// constraint items (<c>PRIMARY KEY (...)</c>, <c>CHECK (...)</c>, …) that are not columns.</summary>
internal sealed record SchemaTable(
    string Name,
    IReadOnlyList<SchemaColumn> Columns,
    IReadOnlyList<string> TableConstraints);
