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
    /// DEFAULT / CHECK inspections in <see cref="SchemaBackwardCompatibility"/> read; the column
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

            var columns = new List<SchemaColumn>();
            var constraints = new List<string>();
            foreach (string item in SplitTopLevel(clean[(openParen + 1)..closeParen]))
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
            string table = Unquote(header.Groups["name"].Value);
            tables[table] = new SchemaTable(table, columns, constraints);
        }
        return tables;
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

/// <summary>One column of a <c>CREATE TABLE</c> body: its name and the raw text of its declaration
/// (type, <c>NOT NULL</c>, <c>DEFAULT</c>, inline <c>CHECK</c>, …), comments already stripped.</summary>
internal sealed record SchemaColumn(string Name, string Declaration);

/// <summary>A parsed <c>CREATE TABLE</c>: its columns in declaration order plus the table-level
/// constraint items (<c>PRIMARY KEY (...)</c>, <c>CHECK (...)</c>, …) that are not columns.</summary>
internal sealed record SchemaTable(
    string Name,
    IReadOnlyList<SchemaColumn> Columns,
    IReadOnlyList<string> TableConstraints);

/// <summary>Locates the live source tree (not embedded resources) so the static schema checks can
/// read both provider files regardless of which one the running provider would load. The one
/// shared <c>Infrastructure/schema/</c> directory and the <c>SchemaInitializer.cs</c> migration
/// source live in exactly one source root; each is discovered across <see cref="SourceRoots.All"/>
/// so the schema gates survive the assembly split, and an accidental second copy fails loudly.</summary>
internal static class SchemaTestPaths
{
    /// <summary>
    /// The source root owning the schema DDL. <see cref="SourceRoot"/> preserves the historical
    /// call shape (the gates combine it with the relative schema/initializer paths below), while
    /// resolving to whichever root actually holds <c>Infrastructure/schema/</c>.
    /// </summary>
    public static string SourceRoot() => SchemaDirOwningRoot();

    // The single root that contains Infrastructure/schema/. Exactly one must — a future duplicate
    // schema directory across roots is a correctness hazard and fails here rather than silently.
    private static string SchemaDirOwningRoot() => SingleOwningRoot(
        root => Directory.Exists(Path.Combine(root, "Infrastructure", "schema")),
        "Infrastructure/schema/");

    // The single root that contains the SchemaInitializer migration source.
    private static string SchemaInitializerOwningRoot() => SingleOwningRoot(
        root => File.Exists(Path.Combine(root, "Infrastructure", "SchemaInitializer.cs")),
        "Infrastructure/SchemaInitializer.cs");

    private static string SingleOwningRoot(Func<string, bool> predicate, string what)
    {
        var matches = SourceRoots.All().Where(predicate).ToList();
        return matches.Count switch
        {
            1 => matches[0],
            0 => throw new DirectoryNotFoundException(
                $"No source root under src/ contains {what}."),
            _ => throw new InvalidOperationException(
                $"{matches.Count} source roots contain {what} (expected exactly one): "
                + string.Join(", ", matches)),
        };
    }

    // SchemaInitializer is a partial class split across SchemaInitializer.cs and its
    // SchemaInitializer.*.cs companions (e.g. .ColumnMigrations.cs, .OwnerPlane.cs, .Reshapes.cs)
    // — the additive-migration array can live in any of them, so callers must scan every file.
    public static IReadOnlyList<string> SchemaInitializerFiles() =>
        Directory.GetFiles(
            Path.Combine(SchemaInitializerOwningRoot(), "Infrastructure"),
            "SchemaInitializer*.cs");

    public static string SqliteSchema(string srcRoot) => Path.Combine(srcRoot, "Infrastructure", "schema", "Schema.sql");
    public static string PostgresSchema(string srcRoot) => Path.Combine(srcRoot, "Infrastructure", "schema", "Schema.pg.sql");
}
