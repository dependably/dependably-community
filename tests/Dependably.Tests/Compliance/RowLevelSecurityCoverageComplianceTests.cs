using Dependably.Infrastructure;
using Dependably.Infrastructure.RowLevelSecurity;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Forces a decision on row-level security for every table <c>Schema.pg.sql</c> declares. A table
/// with an <c>org_id</c>/<c>tenant_id</c> column is covered automatically — the installer derives
/// its policy set from the live catalogue — so the risk is the other kind: a new table holding
/// tenant data with no tenant column of its own (the <c>package_versions</c> shape), which no
/// derivation can see. Every such table must be named either as global below or in
/// PostgresRowLevelSecurityInstaller.ParentScopedTables, which covers it through its parent row, so
/// adding one is a reviewed choice rather than a silent gap.
/// </summary>
[Trait("Category", "Compliance")]
public sealed class RowLevelSecurityCoverageComplianceTests
{
    /// <summary>Instance-wide tables with no tenant data. RLS does not apply and is not needed.</summary>
    private static readonly string[] GlobalTables =
    [
        "orgs",                     // the tenant registry; read to resolve the tenant before one is known
        "instance_settings",
        "data_protection_keys",
        "system_admins",
        "system_tokens",            // system-admin API tokens, owned by system_admins
        "vulnerabilities",          // OSV advisory mirror
        "cache_artifact",           // shared proxy-cache plane; per-tenant reach is tenant_artifact_access
        "login_attempts",
        "account_send_throttle",
        "spdx_license",
        "jwt_revocations",
        "background_job_runs",
        "upstream_negative_cache",
        "instance_lock",
        "vuln_tracker_health",
        "vuln_tracker_fetch_log",
    ];

    /// <summary>
    /// Tenant data reached only through an FK to a tenant-scoped parent, with no tenant column of
    /// its own. Covered by a parent-scoped policy — the installer's list is the source of truth, so
    /// a table named here without a policy there cannot exist.
    /// </summary>
    private static readonly string[] ParentScopedTenantTables =
        [.. PostgresRowLevelSecurityInstaller.ParentScopedTables.Select(t => t.Table)];

    private static Dictionary<string, List<string>> PostgresTables() =>
        SchemaSqlParser.ParseTables(File.ReadAllText(SchemaTestPaths.PostgresSchema(SchemaTestPaths.SourceRoot())));

    private static bool HasTenantColumn(List<string> columns) =>
        columns.Any(c => c.Equals("org_id", StringComparison.OrdinalIgnoreCase)
                         || c.Equals("tenant_id", StringComparison.OrdinalIgnoreCase));

    [Fact]
    public void EveryTableWithoutATenantColumn_IsClassified()
    {
        var classified = new HashSet<string>(GlobalTables.Concat(ParentScopedTenantTables), StringComparer.OrdinalIgnoreCase);

        var unclassified = PostgresTables()
            .Where(t => !HasTenantColumn(t.Value) && !classified.Contains(t.Key))
            .Select(t => t.Key)
            .OrderBy(t => t, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            unclassified.Count == 0,
            "Tables in Schema.pg.sql with no org_id/tenant_id column that row-level security cannot cover. " +
            "Add each to GlobalTables (no tenant data) or to PostgresRowLevelSecurityInstaller.ParentScopedTables " +
            "with a predicate through its parent (tenant data behind an FK) " +
            "in RowLevelSecurityCoverageComplianceTests — or give it a tenant column so the policy covers it:\n  " +
            string.Join("\n  ", unclassified));
    }

    [Fact]
    public void EveryClassifiedTable_ExistsAndHasNoTenantColumn()
    {
        var tables = PostgresTables();

        var stale = GlobalTables.Concat(ParentScopedTenantTables)
            .Where(name => !tables.TryGetValue(name, out var columns) || HasTenantColumn(columns))
            .ToList();

        Assert.True(
            stale.Count == 0,
            "Classified tables that are missing from Schema.pg.sql, or that now carry a tenant column (and so are " +
            "covered by policy and must leave the list):\n  " + string.Join("\n  ", stale));
    }

    [Fact]
    public void NoTableIsClassifiedTwice()
    {
        var both = GlobalTables.Intersect(ParentScopedTenantTables, StringComparer.OrdinalIgnoreCase).ToList();
        Assert.Empty(both);
    }
}
