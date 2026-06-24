using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: every SQL string in the codebase that references a tenant-scoped table
/// must also filter on <c>org_id</c> or <c>tenant_id</c>, OR carry an explicit opt-out
/// comment on the line that opens the string.
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
    /// </summary>
    private static readonly HashSet<string> TenantScopedTables = new(StringComparer.OrdinalIgnoreCase)
    {
        // Each table here has an org_id (or tenant_id) column FK'd to orgs(id) — kept in sync with
        // the schema (every CREATE TABLE that declares org_id/tenant_id belongs here). Tables that
        // sit at the data plane but carry no tenant column on purpose — metadata_cache (the
        // shared upstream-metadata cache, content-addressed like the proxy blob cache),
        // cache_artifact, vulnerabilities (OSV), spdx_license — are NOT listed.
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
        // Version-scoped child tables: no org_id column of their own, reached via an org-scoped
        // package_versions / packages FK. Listed so unfiltered raw SQL against them must justify
        // the cross-tenant reach with `// xtenant:`.
        "package_versions",
        "package_version_vulns",
        "package_version_licenses",
        // MFA trusted-device rows carry tenant_id and are tenant-scoped.
        "mfa_trusted_devices",
    };

    [GeneratedRegex(@"""""""\s*(?<sql>.*?)\s*""""""", RegexOptions.Singleline)]
    private static partial Regex RawStringRegex();

    [GeneratedRegex(@"@""(?<sql>(?:[^""]|"""")*)""", RegexOptions.Singleline)]
    private static partial Regex VerbatimStringRegex();

    [GeneratedRegex(@"\b(FROM|JOIN|INTO|UPDATE)\s+(?<table>[a-z_][a-z0-9_]*)", RegexOptions.IgnoreCase)]
    private static partial Regex TableRefRegex();

    [Fact]
    public void EverySqlAgainstTenantScopedTable_FiltersOnOrgId_OrIsExplicitlyOptedOut()
    {
        string srcRoot = LocateSourceRoot();
        Assert.True(Directory.Exists(srcRoot), $"src root not found at {srcRoot}");

        var violations = new List<string>();
        foreach (string file in Directory.EnumerateFiles(srcRoot, "*.cs", SearchOption.AllDirectories))
        {
            // Skip generated / obj / bin trees defensively.
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                || file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
            {
                continue;
            }

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

                string rel = Path.GetRelativePath(srcRoot, file);
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

    private static string LocateSourceRoot()
    {
        // Tests run from the test bin/ directory; walk up to the repo root and into src/.
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

    private static IEnumerable<SqlMatch> EnumerateSqlLiterals(string source)
    {
        foreach (Match m in RawStringRegex().Matches(source))
        {
            yield return new SqlMatch(m.Groups["sql"].Value, m.Index);
        }

        foreach (Match m in VerbatimStringRegex().Matches(source))
        {
            yield return new SqlMatch(m.Groups["sql"].Value, m.Index);
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
