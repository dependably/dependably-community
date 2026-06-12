using System.Text;
using System.Text.RegularExpressions;

namespace Dependably.Tests.Compliance;

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
/// Shared by <see cref="SchemaSyncComplianceTests"/> and <see cref="SchemaParityComplianceTests"/>.
/// </summary>
internal static partial class SchemaSqlParser
{
    [GeneratedRegex(@"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?<name>""?\w+""?)\s*\(", RegexOptions.IgnoreCase)]
    private static partial Regex CreateTableHeaderRegex();

    [GeneratedRegex(@"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?<name>""?\w+""?)", RegexOptions.IgnoreCase)]
    private static partial Regex CreateTableNameRegex();

    [GeneratedRegex(@"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?(?<name>""?\w+""?)", RegexOptions.IgnoreCase)]
    private static partial Regex CreateIndexNameRegex();

    private static readonly string[] ConstraintLeaders = ["PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"];

    /// <summary>Maps table name → ordered column names declared in its CREATE TABLE body (comments stripped).</summary>
    public static Dictionary<string, List<string>> ParseTables(string sql)
    {
        string clean = StripComments(sql);
        var tables = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (Match header in CreateTableHeaderRegex().Matches(clean))
        {
            // The header regex ends at the opening '('. Bracket-match to find the table body.
            int openParen = header.Index + header.Length - 1;
            int closeParen = MatchingParen(clean, openParen);
            if (closeParen < 0)
            {
                continue;
            }

            var columns = new List<string>();
            foreach (string item in SplitTopLevel(clean[(openParen + 1)..closeParen]))
            {
                string trimmed = item.Trim();
                if (trimmed.Length == 0 || IsConstraint(trimmed))
                {
                    continue;
                }

                string name = Unquote(FirstToken(trimmed));
                if (name.Length > 0)
                {
                    columns.Add(name);
                }
            }
            tables[Unquote(header.Groups["name"].Value)] = columns;
        }
        return tables;
    }

    public static List<string> CreatedTableNames(string sql) =>
        CreateTableNameRegex().Matches(StripComments(sql)).Select(m => Unquote(m.Groups["name"].Value)).ToList();

    public static List<string> CreatedIndexNames(string sql) =>
        CreateIndexNameRegex().Matches(StripComments(sql)).Select(m => Unquote(m.Groups["name"].Value)).ToList();

    /// <summary>Removes <c>-- line</c> and <c>/* block */</c> comments, leaving string literals intact.</summary>
    public static string StripComments(string sql)
    {
        var sb = new StringBuilder(sql.Length);
        bool inStr = false;
        char quote = '\0';
        for (int i = 0; i < sql.Length; i++)
        {
            char c = sql[i];
            if (inStr)
            {
                sb.Append(c);
                if (c == quote)
                {
                    if (i + 1 < sql.Length && sql[i + 1] == quote)
                    {
                        sb.Append(sql[++i]); // escaped '' / ""
                    }
                    else
                    {
                        inStr = false;
                    }
                }
                continue;
            }
            if (c is '\'' or '"') { inStr = true; quote = c; sb.Append(c); continue; }
            if (c == '-' && i + 1 < sql.Length && sql[i + 1] == '-')
            {
                while (i < sql.Length && sql[i] != '\n')
                {
                    i++;
                }

                if (i < sql.Length)
                {
                    sb.Append('\n');
                }

                continue;
            }
            if (c == '/' && i + 1 < sql.Length && sql[i + 1] == '*')
            {
                i += 2;
                while (i + 1 < sql.Length && !(sql[i] == '*' && sql[i + 1] == '/'))
                {
                    i++;
                }

                i++; // skip the closing '/', the for-loop ++ skips the '*'
                continue;
            }
            sb.Append(c);
        }
        return sb.ToString();
    }

    // Index of the ')' closing the '(' at openIndex, or -1. String-literal aware.
    private static int MatchingParen(string s, int openIndex)
    {
        int depth = 0;
        bool inStr = false;
        char quote = '\0';
        for (int i = openIndex; i < s.Length; i++)
        {
            char c = s[i];
            if (inStr)
            {
                if (c == quote)
                {
                    if (i + 1 < s.Length && s[i + 1] == quote)
                    {
                        i++;
                    }
                    else
                    {
                        inStr = false;
                    }
                }
                continue;
            }
            switch (c)
            {
                case '\'' or '"': inStr = true; quote = c; break;
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
        bool inStr = false;
        char quote = '\0';
        for (int i = 0; i < body.Length; i++)
        {
            char c = body[i];
            if (inStr)
            {
                if (c == quote)
                {
                    if (i + 1 < body.Length && body[i + 1] == quote)
                    {
                        i++;
                    }
                    else
                    {
                        inStr = false;
                    }
                }
                continue;
            }
            switch (c)
            {
                case '\'' or '"': inStr = true; quote = c; break;
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

/// <summary>Locates the live source tree (not embedded resources) so the static schema checks can
/// read both provider files regardless of which one the running provider would load.</summary>
internal static class SchemaTestPaths
{
    public static string SourceRoot()
    {
        // Tests run from the test bin/ directory; walk up to the repo root and into src/Dependably.
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
        throw new DirectoryNotFoundException($"Could not locate src/Dependably from {AppContext.BaseDirectory}");
    }

    public static string SchemaInitializer(string srcRoot) => Path.Combine(srcRoot, "Infrastructure", "SchemaInitializer.cs");
    public static string SqliteSchema(string srcRoot) => Path.Combine(srcRoot, "Infrastructure", "schema", "Schema.sql");
    public static string PostgresSchema(string srcRoot) => Path.Combine(srcRoot, "Infrastructure", "schema", "Schema.pg.sql");
}
