using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: every SQL string in the codebase that references a tenant-scoped table
/// must also filter on <c>org_id</c> or <c>tenant_id</c>, OR carry an explicit opt-out
/// comment on the line that opens the string.
///
/// All three C# string forms are scanned — raw (<c>"""…"""</c>), verbatim (<c>@"…"</c>), and
/// plain (<c>"…"</c>). The plain form matters: a one-line <c>"DELETE FROM … WHERE id = @id"</c>
/// is exactly where a missing tenant filter hides, and scanning only the multi-line forms left
/// that class of query invisible to this gate.
///
/// This is the org_id companion to <see cref="NoInterpolatedSqlComplianceTests"/> — same crude
/// static-scan style. It runs in the test suite so violations show up locally and on every PR,
/// not just in CI. Catches the class of bug the BOLA review turned up: a query touching tenant
/// data that forgot the org filter.
///
/// Opt-out: prefix the line that opens the SQL string with the marker
/// <c>// xtenant:</c> followed by a short reason. Example:
/// <code>
///   // xtenant: system-admin view counts admins across all tenants
///   var n = await conn.ExecuteScalarAsync&lt;int&gt;("SELECT COUNT(*) FROM users");
/// </code>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class OrgIdFilteringComplianceTests
{
    private readonly ITestOutputHelper _output;
    public OrgIdFilteringComplianceTests(ITestOutputHelper output) => _output = output;

    /// <summary>
    /// Relations whose rows belong to a tenant but that carry no <c>org_id</c>/<c>tenant_id</c>
    /// column of their own in <c>Schema.sql</c>, so the schema derivation below cannot see them.
    /// This is the ONLY hand-maintained part of the table set, and every entry is asserted to
    /// exist by <see cref="NonSchemaTenantScopedRelations_AllExistInTheSchemaSources"/>.
    /// </summary>
    private static readonly string[] NonSchemaTenantScopedRelations =
    [
        // The canonical read-model views. Defined in SchemaInitializer.Views.cs rather than the
        // schema file, they carry org_id and span every tenant — a query selecting from one
        // without filtering is exactly as dangerous as one against the underlying tables.
        "artifact_inventory",
        "artifact_license",
        "org_storage_bytes",

        // Version-scoped child tables: no org_id column of their own, reached via an org-scoped
        // package_versions / packages FK. Listed so unfiltered raw SQL against them must justify
        // the cross-tenant reach with `// xtenant:`.
        "package_versions",
        "package_version_vulns",
        "package_version_licenses",
        "maven_version_files",
    ];

    /// <summary>
    /// Tables whose rows belong to a tenant. Any SQL touching one of these MUST filter on
    /// <c>org_id</c> (or <c>tenant_id</c> for tables that use that name).
    ///
    /// <para>
    /// Derived from <c>Schema.sql</c> at test time — every <c>CREATE TABLE</c> that declares an
    /// <c>org_id</c> or <c>tenant_id</c> column is tenant-scoped by construction, so a new
    /// tenant-scoped table is covered by this gate the moment it lands in the schema. A
    /// hand-maintained list is exactly what rotted here before: nine tenant-scoped tables
    /// (including the <c>signature_trust_anchor</c> and <c>install_script_allowlist</c>
    /// supply-chain trust material) were never inspected by the gate at all.
    /// </para>
    ///
    /// <para>
    /// Tables that sit at the data plane but carry no tenant column on purpose —
    /// <c>cache_artifact</c>, <c>vulnerabilities</c> (OSV), <c>spdx_license</c> — are excluded
    /// automatically by the same construction.
    /// </para>
    /// </summary>
    internal static readonly HashSet<string> TenantScopedTables = BuildTenantScopedTables();

    private static HashSet<string> BuildTenantScopedTables()
    {
        var set = new HashSet<string>(SchemaDeclaredTenantScopedTables(), StringComparer.OrdinalIgnoreCase);
        foreach (string relation in NonSchemaTenantScopedRelations)
        {
            set.Add(relation);
        }

        return set;
    }

    /// <summary>Every <c>CREATE TABLE</c> in <c>Schema.sql</c> that declares org_id / tenant_id.</summary>
    internal static IEnumerable<string> SchemaDeclaredTenantScopedTables()
    {
        string sql = File.ReadAllText(SchemaTestPaths.SqliteSchema(SchemaTestPaths.SourceRoot()));
        return SchemaSqlParser.ParseTables(sql)
            .Where(t => t.Value.Any(c =>
                c.Equals("org_id", StringComparison.OrdinalIgnoreCase)
                || c.Equals("tenant_id", StringComparison.OrdinalIgnoreCase)))
            .Select(t => t.Key);
    }

    [GeneratedRegex(@"""""""\s*(?<sql>.*?)\s*""""""", RegexOptions.Singleline)]
    private static partial Regex RawStringRegex();

    [GeneratedRegex(@"@""(?<sql>(?:[^""]|"""")*)""", RegexOptions.Singleline)]
    private static partial Regex VerbatimStringRegex();

    /// <summary>
    /// Plain (non-raw, non-verbatim) single-line string literals: <c>"SELECT … "</c>. Short SQL
    /// written as an ordinary quoted string is the gate's historic blind spot — a BOLA-class
    /// cross-tenant DELETE can hide in one and the raw/verbatim scan never sees it. Escape
    /// sequences are consumed so an embedded <c>\"</c> doesn't terminate the match early.
    /// Applied to source whose raw/verbatim literals have already been blanked, so the quote
    /// characters inside those literals cannot mis-pair here.
    /// </summary>
    [GeneratedRegex(@"""(?<sql>(?:[^""\\\r\n]|\\.)+)""")]
    private static partial Regex PlainStringRegex();

    [GeneratedRegex(@"\b(FROM|JOIN|INTO|UPDATE)\s+(?<table>[a-z_][a-z0-9_]*)", RegexOptions.IgnoreCase)]
    private static partial Regex TableRefRegex();

    [Fact]
    public void EverySqlAgainstTenantScopedTable_FiltersOnOrgId_OrIsExplicitlyOptedOut()
    {
        var violations = new List<string>();
        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string[] lines = File.ReadAllLines(file);
            string source = string.Join('\n', lines);

            foreach (var match in EnumerateSqlLiterals(source))
            {
                if (!LooksLikeSql(match.Sql))
                {
                    continue;
                }

                var touchedTenantTables = TenantScopedTablesIn(match.Sql);
                if (touchedTenantTables.Count == 0)
                {
                    continue;
                }

                if (HasOrgFilter(match.Sql))
                {
                    continue;
                }

                // Find the line where this literal opens; check for an opt-out comment.
                int lineNumber = CountLinesUpTo(source, match.StartIndex);
                if (HasOptOutComment(lines, lineNumber))
                {
                    continue;
                }

                string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
                violations.Add(
                    $"{rel}:{lineNumber + 1}: SQL touches tenant-scoped table(s) " +
                    $"[{string.Join(", ", touchedTenantTables)}] without org_id / tenant_id filter. " +
                    $"Either add the filter or annotate the opening line with " +
                    $"`// xtenant: <reason>`. SQL: {Truncate(match.Sql, 120)}");
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} SQL literal(s) touch tenant-scoped tables without org_id/tenant_id filtering. " +
                        $"See test output for the full list and remediation hint.");
        }
    }

    /// <summary>
    /// Self-test for the scanner itself. The gate went green-but-blind for as long as it read only
    /// raw and verbatim literals: a one-line <c>"DELETE FROM &lt;tenant table&gt; WHERE id = @id"</c>
    /// was invisible to it, which is precisely the shape a cross-tenant write takes. These cases
    /// pin the three properties the scan depends on, so a future refactor of the regexes cannot
    /// quietly reopen the hole or start flagging split-literal queries that are in fact filtered.
    /// </summary>
    [Theory]
    // Plain quoted SQL against a tenant-scoped table, unfiltered → must be seen.
    [InlineData("""await conn.ExecuteAsync("DELETE FROM package_version_files WHERE id = @id");""", true)]
    [InlineData("""await conn.ExecuteAsync("UPDATE maven_version_files SET blob_key = @k WHERE id = @id");""", true)]
    // Plain quoted SQL that DOES filter → must not be seen as a violation.
    [InlineData("""await conn.QueryAsync("SELECT id FROM package_version_files WHERE org_id = @orgId");""", false)]
    // A query split across concatenated literals is one logical statement: the filter lives in the
    // tail, so judging the head alone would be a false positive.
    [InlineData("""
        await conn.QueryAsync("SELECT id FROM package_version_files " +
            "WHERE org_id = @orgId AND filename = @f");
        """, false)]
    public void Scanner_SeesPlainQuotedSql_AndJudgesConcatenatedLiteralsWhole(string source, bool expectViolation)
    {
        bool flagged = EnumerateSqlLiterals(source)
            .Where(m => LooksLikeSql(m.Sql))
            .Where(m => TenantScopedTablesIn(m.Sql).Count > 0)
            .Any(m => !HasOrgFilter(m.Sql));

        Assert.Equal(expectViolation, flagged);
    }

    /// <summary>
    /// Self-test for the filter check. Mentioning the tenant column is not filtering on it: a
    /// projection, an alias, or an inverted predicate all span every tenant while carrying the
    /// column name. These cases pin "the column appears in a filtering position", which is the
    /// property the gate actually claims to enforce.
    /// </summary>
    [Theory]
    // --- Mentions the column, does not filter on it: must be a violation. ---
    [InlineData("SELECT org_id, name FROM packages", true)]
    [InlineData("SELECT id, org_id AS tenant FROM packages ORDER BY name", true)]
    [InlineData("SELECT id FROM packages WHERE org_id != @orgId", true)]
    [InlineData("SELECT id FROM packages WHERE org_id <> @orgId", true)]
    [InlineData("SELECT id FROM packages WHERE id NOT IN (SELECT org_id FROM users)", true)]
    [InlineData("DELETE FROM signature_trust_anchor WHERE id = @id", true)]
    [InlineData("UPDATE install_script_allowlist SET enabled = 1 WHERE id = @id", true)]
    // --- Genuinely filtering: must pass. ---
    [InlineData("SELECT id FROM packages WHERE org_id = @orgId", false)]
    [InlineData("SELECT id FROM packages p WHERE p.org_id=@orgId AND p.name = @n", false)]
    [InlineData("SELECT id FROM banners WHERE id = @id AND (scope = 'system' OR org_id = @orgId)", false)]
    [InlineData("SELECT id FROM packages WHERE org_id IN (SELECT id FROM orgs)", false)]
    [InlineData("SELECT id FROM mfa_trusted_devices WHERE tenant_id IS NULL", false)]
    [InlineData("SELECT p.id FROM packages p JOIN users u ON u.org_id = p.org_id WHERE u.id = @id", false)]
    [InlineData("UPDATE quarantine SET state = @s WHERE org_id = @orgId AND id = @id", false)]
    // An INSERT binds its row to a tenant through the column list; there is no predicate to find.
    [InlineData("INSERT INTO packages (org_id, name) VALUES (@orgId, @name)", false)]
    // …but an INSERT … SELECT reads across tenants unless the SELECT itself is filtered.
    [InlineData("INSERT INTO packages (org_id, name) SELECT org_id, name FROM packages", true)]
    [InlineData("INSERT INTO packages (org_id, name) SELECT org_id, name FROM packages WHERE org_id = @o", false)]
    public void FilterCheck_RequiresTheTenantColumnInAFilteringPosition(string sql, bool expectViolation)
    {
        Assert.True(TenantScopedTablesIn(sql).Count > 0, "fixture must touch a tenant-scoped table");
        Assert.Equal(expectViolation, !HasOrgFilter(sql));
    }

    /// <summary>
    /// The table set is derived from <c>Schema.sql</c>, not hand-maintained. This pins the
    /// derivation: every <c>CREATE TABLE</c> declaring org_id/tenant_id is covered, including the
    /// supply-chain trust tables a hand-maintained list had silently omitted.
    /// </summary>
    [Fact]
    public void TenantScopedTables_CoverEverySchemaTableDeclaringATenantColumn()
    {
        var declared = SchemaDeclaredTenantScopedTables().ToList();

        // A parser regression that returned nothing would make the gate green-but-blind, so pin a
        // floor well below the real count rather than trusting the set difference alone.
        Assert.True(declared.Count >= 30, $"schema derivation found only {declared.Count} tenant-scoped tables");

        var missing = declared.Where(t => !TenantScopedTables.Contains(t)).OrderBy(t => t, StringComparer.Ordinal).ToList();
        Assert.True(missing.Count == 0, $"tenant-scoped schema tables missing from the gate: {string.Join(", ", missing)}");

        // Anchors: supply-chain trust material and the per-tenant surfaces whose omission is what
        // let an unfiltered write ship. Named explicitly so a derivation that stops seeing them
        // fails here with a readable reason rather than merely thinning the set.
        foreach (string anchor in new[]
                 {
                     "signature_trust_anchor", "install_script_allowlist", "banners", "alert",
                     "alert_settings", "webhook_subscription", "npm_dist_tags", "oci_uploads",
                     "org_stats_snapshot",
                 })
        {
            Assert.Contains(anchor, TenantScopedTables);
        }
    }

    /// <summary>
    /// The one hand-maintained part of the set must still name real relations — a view renamed in
    /// <c>SchemaInitializer.Views.cs</c> or a table dropped from the schema would otherwise leave a
    /// dead string here that matches nothing and protects nothing.
    /// </summary>
    [Fact]
    public void NonSchemaTenantScopedRelations_AllExistInTheSchemaSources()
    {
        string schema = File.ReadAllText(SchemaTestPaths.SqliteSchema(SchemaTestPaths.SourceRoot()));
        var known = new HashSet<string>(SchemaSqlParser.CreatedTableNames(schema), StringComparer.OrdinalIgnoreCase);
        foreach (string file in SchemaTestPaths.SchemaInitializerFiles())
        {
            foreach (Match m in CreateViewRegex().Matches(File.ReadAllText(file)))
            {
                known.Add(m.Groups["name"].Value);
            }
        }

        var unknown = NonSchemaTenantScopedRelations.Where(r => !known.Contains(r)).ToList();
        Assert.True(
            unknown.Count == 0,
            $"NonSchemaTenantScopedRelations names relation(s) that no longer exist: {string.Join(", ", unknown)}");
    }

    [GeneratedRegex(@"CREATE\s+VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?(?<name>\w+)", RegexOptions.IgnoreCase)]
    private static partial Regex CreateViewRegex();

    private record struct SqlMatch(string Sql, int StartIndex);

    private static IEnumerable<SqlMatch> EnumerateSqlLiterals(string source)
    {
        // Blank the raw and verbatim literals out of a working copy as they are yielded, so the
        // plain-string pass below scans only the source OUTSIDE them. Blanking preserves length
        // and newlines, which keeps every match index (and therefore every reported line number)
        // valid against the original source.
        char[] outsideLiterals = source.ToCharArray();

        foreach (Match m in RawStringRegex().Matches(source))
        {
            Blank(outsideLiterals, m.Index, m.Length);
            yield return new SqlMatch(m.Groups["sql"].Value, m.Index);
        }

        foreach (Match m in VerbatimStringRegex().Matches(source))
        {
            Blank(outsideLiterals, m.Index, m.Length);
            yield return new SqlMatch(m.Groups["sql"].Value, m.Index);
        }

        string plainSource = new(outsideLiterals);
        foreach (var m in CoalesceConcatenated(PlainStringRegex().Matches(plainSource), plainSource))
        {
            yield return m;
        }
    }

    // Splices `"SELECT … " + "WHERE org_id = @x"` back into one logical SQL string. A query broken
    // across concatenated literals must be judged whole: scanning the fragments separately reads
    // the head as an unfiltered `SELECT … FROM tenant_table` and fails a query whose filter simply
    // lives in the next literal. Two literals belong to the same expression when nothing but
    // whitespace and `+` separates them.
    private static IEnumerable<SqlMatch> CoalesceConcatenated(MatchCollection matches, string source)
    {
        SqlMatch? pending = null;
        int pendingEnd = 0;

        foreach (Match m in matches)
        {
            string text = m.Groups["sql"].Value;
            if (pending is { } open && source[pendingEnd..m.Index].All(c => c is '+' || char.IsWhiteSpace(c)))
            {
                pending = new SqlMatch(open.Sql + text, open.StartIndex);
            }
            else
            {
                if (pending is { } previous)
                {
                    yield return previous;
                }

                pending = new SqlMatch(text, m.Index);
            }

            pendingEnd = m.Index + m.Length;
        }

        if (pending is { } last)
        {
            yield return last;
        }
    }

    // Overwrites a span with spaces, leaving line breaks in place so line numbering survives.
    private static void Blank(char[] buffer, int start, int length)
    {
        for (int i = start; i < start + length && i < buffer.Length; i++)
        {
            if (buffer[i] is not '\n' and not '\r')
            {
                buffer[i] = ' ';
            }
        }
    }

    private static bool LooksLikeSql(string s)
    {
        // Crude but reliable: a SQL string contains at least one of these top-level keywords.
        // Capitalized to avoid matching English prose containing the word "select" etc.
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

    private static List<string> TenantScopedTablesIn(string sql)
    {
        var found = new List<string>();
        foreach (Match m in TableRefRegex().Matches(sql))
        {
            string table = m.Groups["table"].Value;
            if (TenantScopedTables.Contains(table) && !found.Contains(table))
            {
                found.Add(table);
            }
        }
        return found;
    }

    /// <summary>
    /// True when the tenant column appears in a FILTERING position — a <c>WHERE</c> / <c>ON</c> /
    /// <c>HAVING</c> / <c>USING</c> clause, bound with an equality or membership operator — or, for
    /// a plain <c>INSERT … VALUES</c>, in the column list that binds the row to its tenant.
    ///
    /// <para>
    /// Mere presence of the column name is not enough: <c>SELECT org_id, name FROM packages</c>
    /// and <c>WHERE org_id != @orgId</c> both mention the column and both span every tenant.
    /// This is deliberately a clause-position check rather than a SQL parse — the goal is
    /// "the column constrains the result set", which the position plus operator shape captures
    /// for every statement shape this codebase actually writes.
    /// </para>
    ///
    /// <para>
    /// Known limitation, and the reason the <c>// xtenant:</c> opt-out still carries weight: the
    /// gate has no data-flow awareness. <c>WHERE org_id = @orgId</c> passes regardless of whether
    /// <c>@orgId</c> came from the authenticated principal or straight off a route parameter —
    /// the latter is textbook BOLA and is invisible here. Column-to-column predicates
    /// (<c>WHERE p.org_id = c.org_id</c>) likewise pass, because they are the correct shape inside
    /// a correlated subquery whose outer query is bound; only a reviewer can tell the two apart.
    /// </para>
    /// </summary>
    private static bool HasOrgFilter(string sql)
    {
        if (FilteringClausesOf(sql).Any(clause => TenantPredicateRegex().IsMatch(clause)))
        {
            return true;
        }

        // A plain `INSERT INTO t (org_id, …) VALUES (…)` binds the new row to its tenant through
        // the column list; there is no predicate to find. An INSERT … SELECT does not get this
        // pass — its SELECT still reads across tenants unless the SELECT itself is filtered, which
        // the clause scan above is what decides.
        return InsertColumnListBindsTenant(sql);
    }

    /// <summary>
    /// Splits the SQL into the regions that can constrain a result set. A region opens at
    /// <c>WHERE</c>/<c>ON</c>/<c>HAVING</c>/<c>USING</c> and closes at the next clause keyword that
    /// starts something other than a predicate (<c>SELECT</c>, <c>FROM</c>, <c>GROUP BY</c>,
    /// <c>SET</c>, <c>VALUES</c>, <c>DO</c>, a set operator, …). <c>AND</c>/<c>OR</c> continue the
    /// region rather than closing it.
    /// </summary>
    private static IEnumerable<string> FilteringClausesOf(string sql)
    {
        var opens = ClauseOpenRegex().Matches(sql);
        foreach (Match open in opens)
        {
            int start = open.Index + open.Length;
            var close = ClauseCloseRegex().Match(sql, start);
            yield return close.Success ? sql[start..close.Index] : sql[start..];
        }
    }

    private static bool InsertColumnListBindsTenant(string sql)
    {
        var insert = InsertColumnListRegex().Match(sql);
        return insert.Success
            && !SelectKeywordRegex().IsMatch(sql)
            && TenantColumnRegex().IsMatch(insert.Groups["cols"].Value);
    }

    // `org_id = …`, `org_id IN (…)`, `org_id IS NULL`, and the reversed `@orgId = org_id`. The
    // negative lookbehind/lookahead rejects the inverted forms `!=`, `<>` and `NOT IN`, which
    // mention the column while explicitly widening past the tenant.
    [GeneratedRegex(
        @"(?:(?<!\bNOT\s)\b(?:\w+\.)?(?:org_id|tenant_id)\s*(?:=(?!=)|\bIN\b|\bIS\b)"
        + @"|=\s*(?:\w+\.)?(?:org_id|tenant_id)\b)",
        RegexOptions.IgnoreCase)]
    private static partial Regex TenantPredicateRegex();

    [GeneratedRegex(@"\b(?:WHERE|ON|HAVING|USING)\b", RegexOptions.IgnoreCase)]
    private static partial Regex ClauseOpenRegex();

    [GeneratedRegex(
        @"\b(?:SELECT|FROM|SET|VALUES|DO|RETURNING|LIMIT|OFFSET|UNION|EXCEPT|INTERSECT"
        + @"|GROUP\s+BY|ORDER\s+BY|INSERT|UPDATE|DELETE|WITH)\b",
        RegexOptions.IgnoreCase)]
    private static partial Regex ClauseCloseRegex();

    [GeneratedRegex(@"\bINSERT\s+(?:OR\s+\w+\s+)?INTO\s+[\w"".]+\s*\((?<cols>[^)]*)\)", RegexOptions.IgnoreCase)]
    private static partial Regex InsertColumnListRegex();

    [GeneratedRegex(@"\bSELECT\b", RegexOptions.IgnoreCase)]
    private static partial Regex SelectKeywordRegex();

    [GeneratedRegex(@"\b(?:org_id|tenant_id)\b", RegexOptions.IgnoreCase)]
    private static partial Regex TenantColumnRegex();

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
        // Allow the marker anywhere in the small window above the line that opens the SQL
        // string. Real query call sites typically look like:
        //     await using var conn = ...;
        //     // xtenant: <reason>
        //     await conn.ExecuteAsync(
        //         """
        //         SELECT ...
        // so the comment sits two or three lines above the """. Five lines is generous
        // without being so wide that an unrelated earlier comment triggers a false pass.
        for (int probe = Math.Max(0, lineIndex - 5); probe <= lineIndex && probe < lines.Length; probe++)
        {
            if (lines[probe].Contains("xtenant:", StringComparison.OrdinalIgnoreCase))
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
