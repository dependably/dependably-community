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
    /// Tables whose rows belong to a tenant. Any SQL touching one of these MUST filter on
    /// <c>org_id</c> (or <c>tenant_id</c> for tables that use that name).
    ///
    /// The canonical read-model views belong here too. They carry <c>org_id</c> and span every
    /// tenant, so a query that selects from one without filtering is exactly as dangerous as one
    /// against the underlying tables — and this set is what the gate matches on, so a view left out
    /// of it would read from tenant rows with the gate silently passing.
    /// </summary>
    internal static readonly HashSet<string> TenantScopedTables = new(StringComparer.OrdinalIgnoreCase)
    {
        "artifact_inventory",
        "artifact_license",
        "org_storage_bytes",

        // Each table here has an org_id (or tenant_id) column FK'd to orgs(id) — kept in sync with
        // the schema (every CREATE TABLE that declares org_id/tenant_id belongs here). Tables that
        // sit at the data plane but carry no tenant column on purpose — cache_artifact,
        // vulnerabilities (OSV), spdx_license — are NOT listed.
        "packages",
        "org_settings",
        "users",
        "activity",
        "audit_log",
        "audit_event",
        "user_tokens",
        "service_tokens",
        "invites",
        "external_identities",
        "claim",
        "claim_history",
        "allowlist",
        "blocklist",
        "reserved_namespace",
        "quarantine",
        "license_allowlist",
        "license_blocklist",
        "upstream_registry",
        "upstream_source_pin",
        "nuget_symbol_index",
        "oci_blobs",
        "oci_tags",
        "rpm_repodata_state",
        "tenant_artifact_access",
        "tenant_storage",
        "tenant_provisioning_jobs",
        "tenant_saml_config",
        // SAML one-shot tables. Consume/issue queries are tenant-scoped (filter on tenant_id);
        // the expiry-only global retention sweeps opt out with `// xtenant:`.
        "saml_pending_requests",
        "saml_consumed_assertions",
        "saml_test_runs",
        // package_version_files declares its own org_id column (denormalized from the owning
        // package so the download-by-filename lookup is org-filtered without a second join).
        "package_version_files",
        // Version-scoped child tables: no org_id column of their own, reached via an org-scoped
        // package_versions / packages FK. Listed so unfiltered raw SQL against them must justify
        // the cross-tenant reach with `// xtenant:`.
        "package_versions",
        "package_version_vulns",
        "package_version_licenses",
        "maven_version_files",
        // MFA trusted-device rows carry tenant_id and are tenant-scoped.
        "mfa_trusted_devices",
    };

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

    private static bool HasOrgFilter(string sql)
    {
        // Either column name in any position of the SQL is enough — almost every legitimate
        // query gates on one of them. Cross-tenant queries that legitimately don't (e.g.
        // system-admin counts) use the opt-out comment.
        return sql.Contains("org_id", StringComparison.OrdinalIgnoreCase)
            || sql.Contains("tenant_id", StringComparison.OrdinalIgnoreCase);
    }

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
