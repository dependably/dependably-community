using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Data.Sqlite;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Behavioural coverage for the projects plane's DDL, against a real SQLite database built by the
/// real <see cref="SchemaInitializer"/>. The static schema gates prove the two provider files agree
/// and that every temporal column carries its CHECK; these prove the constraints that actually
/// protect the data do what the design says — the two partial unique indexes that make duplicate
/// names and double-latest impossible, the enum CHECKs, and the FK cascade that makes an org
/// hard-delete reach every table on the plane.
/// </summary>
[Trait("Category", "Schema")]
public sealed class ProjectsPlaneSchemaTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme'), ('o2', 'other')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static async Task InsertProjectAsync(
        System.Data.Common.DbConnection conn, string id, string orgId, string name, string? parentId = null,
        string kind = "project")
        => await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name, parent_id, kind) VALUES (@id, @orgId, @name, @parentId, @kind)",
            new { id, orgId, name, parentId, kind });

    private static async Task InsertVersionAsync(
        System.Data.Common.DbConnection conn, string id, string projectId, string version, int isLatest)
        => await conn.ExecuteAsync(
            "INSERT INTO project_versions (id, org_id, project_id, version, is_latest) " +
            "VALUES (@id, 'o1', @projectId, @version, @isLatest)",
            new { id, projectId, version, isLatest });

    /// <summary>
    /// A plain <c>UNIQUE(org_id, parent_id, name)</c> would admit this pair, because both providers
    /// treat two NULL parents as distinct. The partial index on <c>parent_id IS NULL</c> is what
    /// actually refuses it.
    /// </summary>
    [Fact]
    public async Task TwoRootProjects_WithTheSameName_AreRefused()
    {
        await using var conn = await _db.OpenAsync();
        await InsertProjectAsync(conn, "p1", "o1", "web");

        var ex = await Assert.ThrowsAsync<SqliteException>(
            () => InsertProjectAsync(conn, "p2", "o1", "web"));
        Assert.Contains("UNIQUE", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TheSameRootProjectName_InAnotherOrg_IsAllowed()
    {
        await using var conn = await _db.OpenAsync();
        await InsertProjectAsync(conn, "p1", "o1", "web");
        await InsertProjectAsync(conn, "p2", "o2", "web");

        Assert.Equal(2, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM projects"));
    }

    [Fact]
    public async Task TwoChildrenOfOneCollection_WithTheSameName_AreRefused()
    {
        await using var conn = await _db.OpenAsync();
        await InsertProjectAsync(conn, "c1", "o1", "monorepo", kind: "collection");
        await InsertProjectAsync(conn, "p1", "o1", "api", parentId: "c1");

        var ex = await Assert.ThrowsAsync<SqliteException>(
            () => InsertProjectAsync(conn, "p2", "o1", "api", parentId: "c1"));
        Assert.Contains("UNIQUE", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TheSameChildName_UnderTwoDifferentCollections_IsAllowed()
    {
        await using var conn = await _db.OpenAsync();
        await InsertProjectAsync(conn, "c1", "o1", "repo-a", kind: "collection");
        await InsertProjectAsync(conn, "c2", "o1", "repo-b", kind: "collection");
        await InsertProjectAsync(conn, "p1", "o1", "api", parentId: "c1");
        await InsertProjectAsync(conn, "p2", "o1", "api", parentId: "c2");

        Assert.Equal(2, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM projects WHERE name = 'api'"));
    }

    [Fact]
    public async Task AnUnknownProjectKind_IsRefused()
    {
        await using var conn = await _db.OpenAsync();
        await Assert.ThrowsAsync<SqliteException>(
            () => InsertProjectAsync(conn, "p1", "o1", "web", kind: "folder"));
    }

    /// <summary>
    /// The partial unique index on <c>is_latest = 1</c> is the backstop that makes a lost-update
    /// double-latest impossible at commit rather than merely unlikely: the losing promoter gets a
    /// constraint violation and retries.
    /// </summary>
    [Fact]
    public async Task TwoLatestVersions_OfOneProject_AreRefused()
    {
        await using var conn = await _db.OpenAsync();
        await InsertProjectAsync(conn, "p1", "o1", "web");
        await InsertVersionAsync(conn, "v1", "p1", "1.0.0", isLatest: 1);

        var ex = await Assert.ThrowsAsync<SqliteException>(
            () => InsertVersionAsync(conn, "v2", "p1", "2.0.0", isLatest: 1));
        Assert.Contains("UNIQUE", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ManyNonLatestVersions_OfOneProject_AreAllowed()
    {
        await using var conn = await _db.OpenAsync();
        await InsertProjectAsync(conn, "p1", "o1", "web");
        await InsertVersionAsync(conn, "v1", "p1", "1.0.0", isLatest: 0);
        await InsertVersionAsync(conn, "v2", "p1", "2.0.0", isLatest: 0);
        await InsertVersionAsync(conn, "v3", "p1", "3.0.0", isLatest: 1);

        Assert.Equal(3, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM project_versions"));
    }

    /// <summary>
    /// Never-evaluated has to be distinguishable from evaluated-and-passing, which is why NULL is
    /// permitted and 'pass' is not the column default.
    /// </summary>
    [Fact]
    public async Task PolicyStatus_DefaultsToNull_AndRefusesAnUnknownValue()
    {
        await using var conn = await _db.OpenAsync();
        await InsertProjectAsync(conn, "p1", "o1", "web");
        await InsertVersionAsync(conn, "v1", "p1", "1.0.0", isLatest: 1);

        Assert.Null(await conn.ExecuteScalarAsync<string?>(
            "SELECT policy_status FROM project_versions WHERE id = 'v1'"));

        await Assert.ThrowsAsync<SqliteException>(() => conn.ExecuteAsync(
            "UPDATE project_versions SET policy_status = 'blocked' WHERE id = 'v1'"));
    }

    /// <summary>
    /// The two scope vocabularies are deliberately kept apart: a CycloneDX value must not be
    /// storable in the dev/prod column, and vice versa, so a future reader cannot conflate them.
    /// </summary>
    [Theory]
    [InlineData("required", "runtime", true)]
    [InlineData("excluded", "dev", true)]
    [InlineData(null, "unknown", true)]
    // 'dev' is not a CycloneDX scope, and 'required' is not a dependency scope.
    [InlineData("dev", "runtime", false)]
    [InlineData("required", "required", false)]
    public async Task ScopeColumns_AcceptOnlyTheirOwnVocabulary(
        string? sbomScope, string dependencyScope, bool accepted)
    {
        await using var conn = await _db.OpenAsync();
        await InsertProjectAsync(conn, "p1", "o1", "web");
        await InsertVersionAsync(conn, "v1", "p1", "1.0.0", isLatest: 1);

        Task Insert() => conn.ExecuteAsync(
            "INSERT INTO sbom_components (id, org_id, project_version_id, name, sbom_scope, dependency_scope) " +
            "VALUES ('c1', 'o1', 'v1', 'left-pad', @sbomScope, @dependencyScope)",
            new { sbomScope, dependencyScope });

        if (accepted)
        {
            await Insert();
            Assert.Equal(1, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM sbom_components"));
        }
        else
        {
            await Assert.ThrowsAsync<SqliteException>(Insert);
        }
    }

    [Fact]
    public async Task DependencyScope_DefaultsToUnknown_NotToProduction()
    {
        await using var conn = await _db.OpenAsync();
        await InsertProjectAsync(conn, "p1", "o1", "web");
        await InsertVersionAsync(conn, "v1", "p1", "1.0.0", isLatest: 1);
        await conn.ExecuteAsync(
            "INSERT INTO sbom_components (id, org_id, project_version_id, name) " +
            "VALUES ('c1', 'o1', 'v1', 'left-pad')");

        Assert.Equal("unknown", await conn.ExecuteScalarAsync<string>(
            "SELECT dependency_scope FROM sbom_components WHERE id = 'c1'"));
    }

    /// <summary>
    /// A component with no purl is legitimate and must not collide with any other; only the ones
    /// that DO declare a purl are deduped, which is what the partial unique index expresses.
    /// </summary>
    [Fact]
    public async Task ComponentsWithoutAPurl_DoNotCollide_ButDuplicatePurlsDo()
    {
        await using var conn = await _db.OpenAsync();
        await InsertProjectAsync(conn, "p1", "o1", "web");
        await InsertVersionAsync(conn, "v1", "p1", "1.0.0", isLatest: 1);

        await conn.ExecuteAsync(
            "INSERT INTO sbom_components (id, org_id, project_version_id, name) VALUES " +
            "('c1', 'o1', 'v1', 'anonymous-a'), ('c2', 'o1', 'v1', 'anonymous-b')");
        await conn.ExecuteAsync(
            "INSERT INTO sbom_components (id, org_id, project_version_id, name, purl) " +
            "VALUES ('c3', 'o1', 'v1', 'left-pad', 'pkg:npm/left-pad@1.3.0')");

        await Assert.ThrowsAsync<SqliteException>(() => conn.ExecuteAsync(
            "INSERT INTO sbom_components (id, org_id, project_version_id, name, purl) " +
            "VALUES ('c4', 'o1', 'v1', 'left-pad', 'pkg:npm/left-pad@1.3.0')"));
    }

    /// <summary>
    /// vuln_key deliberately has no foreign key: a VEX or SARIF document legitimately cites
    /// advisories the OSV feed has never served, and dropping those statements would hide exactly
    /// what a reader needs. This pins that the row stores such an id rather than rejecting it.
    /// </summary>
    [Fact]
    public async Task AnalysisRow_AcceptsAnAdvisoryIdWithNoVulnerabilitiesRow()
    {
        await using var conn = await _db.OpenAsync();
        await InsertProjectAsync(conn, "p1", "o1", "web");
        await InsertVersionAsync(conn, "v1", "p1", "1.0.0", isLatest: 1);

        await conn.ExecuteAsync(
            "INSERT INTO project_vuln_analysis (id, org_id, project_version_id, purl_key, vuln_key, vex_state, vex_source) " +
            "VALUES ('a1', 'o1', 'v1', 'pkg:npm/left-pad', 'CVE-2099-99999', 'not_affected', 'upload')");

        Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM vulnerabilities WHERE osv_id = 'CVE-2099-99999'"));
        Assert.Equal(1, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM project_vuln_analysis WHERE vuln_key = 'CVE-2099-99999'"));
    }

    [Fact]
    public async Task AnalysisRow_IsUniquePerVersionPurlAndAdvisory()
    {
        await using var conn = await _db.OpenAsync();
        await InsertProjectAsync(conn, "p1", "o1", "web");
        await InsertVersionAsync(conn, "v1", "p1", "1.0.0", isLatest: 1);

        await conn.ExecuteAsync(
            "INSERT INTO project_vuln_analysis (id, org_id, project_version_id, purl_key, vuln_key) " +
            "VALUES ('a1', 'o1', 'v1', 'pkg:npm/left-pad', 'CVE-2024-1')");

        await Assert.ThrowsAsync<SqliteException>(() => conn.ExecuteAsync(
            "INSERT INTO project_vuln_analysis (id, org_id, project_version_id, purl_key, vuln_key) " +
            "VALUES ('a2', 'o1', 'v1', 'pkg:npm/left-pad', 'CVE-2024-1')"));
    }

    [Fact]
    public async Task OneActiveDocument_PerVersionAndDocType()
    {
        await using var conn = await _db.OpenAsync();
        await InsertProjectAsync(conn, "p1", "o1", "web");
        await InsertVersionAsync(conn, "v1", "p1", "1.0.0", isLatest: 1);

        await conn.ExecuteAsync(
            "INSERT INTO project_documents (id, org_id, project_version_id, doc_type, format, sha256, blob_key) " +
            "VALUES ('d1', 'o1', 'v1', 'sbom', 'cyclonedx-json', 'aa', 'k1'), " +
            "       ('d2', 'o1', 'v1', 'sarif', 'sarif-json', 'bb', 'k2')");

        await Assert.ThrowsAsync<SqliteException>(() => conn.ExecuteAsync(
            "INSERT INTO project_documents (id, org_id, project_version_id, doc_type, format, sha256, blob_key) " +
            "VALUES ('d3', 'o1', 'v1', 'sbom', 'cyclonedx-json', 'cc', 'k3')"));
    }

    /// <summary>
    /// Org hard-delete is pure FK cascade, so every table on the plane has to hang off <c>orgs</c>
    /// either directly or through a parent that does. A table that survives the cascade leaks a
    /// deleted tenant's application inventory.
    /// </summary>
    [Fact]
    public async Task DeletingTheOrg_CascadesThroughEveryTableOnThePlane()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("PRAGMA foreign_keys = ON");
        await InsertProjectAsync(conn, "c1", "o1", "monorepo", kind: "collection");
        await InsertProjectAsync(conn, "p1", "o1", "web", parentId: "c1");
        await InsertVersionAsync(conn, "v1", "p1", "1.0.0", isLatest: 1);
        await conn.ExecuteAsync(
            "INSERT INTO project_documents (id, org_id, project_version_id, doc_type, format, sha256, blob_key) " +
            "VALUES ('d1', 'o1', 'v1', 'sbom', 'cyclonedx-json', 'aa', 'k1')");
        await conn.ExecuteAsync(
            "INSERT INTO sbom_components (id, org_id, project_version_id, name, purl) " +
            "VALUES ('cm1', 'o1', 'v1', 'left-pad', 'pkg:npm/left-pad@1.3.0')");
        await conn.ExecuteAsync(
            "INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name) " +
            "VALUES ('vu1', 'GHSA-x', 'npm', 'left-pad')");
        await conn.ExecuteAsync(
            "INSERT INTO sbom_component_vulns (id, component_id, vuln_id) VALUES ('scv1', 'cm1', 'vu1')");
        await conn.ExecuteAsync(
            "INSERT INTO project_vuln_analysis (id, org_id, project_version_id, purl_key, vuln_key) " +
            "VALUES ('a1', 'o1', 'v1', 'pkg:npm/left-pad', 'GHSA-x')");
        await conn.ExecuteAsync(
            "INSERT INTO sbom_policy_findings (id, org_id, project_version_id, component_id, arm, vuln_key) " +
            "VALUES ('f1', 'o1', 'v1', 'cm1', 'kev', 'GHSA-x')");

        await conn.ExecuteAsync("DELETE FROM orgs WHERE id = 'o1'");

        foreach (string table in new[]
                 {
                     "projects", "project_versions", "project_documents", "sbom_components",
                     "sbom_component_vulns", "project_vuln_analysis", "sbom_policy_findings",
                 })
        {
            // rawsql: the table name comes from this test's own literal list, never from input.
            long remaining = await conn.ExecuteScalarAsync<long>($"SELECT COUNT(*) FROM {table}");
            Assert.Equal(0, remaining);
        }

        // The advisory itself is global and must survive its last component link.
        Assert.Equal(1, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM vulnerabilities"));
    }

    /// <summary>
    /// The alert seam this plane raises through. A fresh install must accept the new type from the
    /// CREATE TABLE block alone, and must still refuse an unregistered one — a CHECK widened into a
    /// free-text column would be no gate at all.
    /// </summary>
    [Fact]
    public async Task AlertType_AcceptsSbomPolicyViolation_AndStillRefusesAnUnknownType()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO alert (id, org_id, type, source_ref, title) " +
            "VALUES ('al1', 'o1', 'sbom_policy_violation', 'pkg:npm/left-pad', 'Policy violation')");

        Assert.Equal(1, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM alert WHERE type = 'sbom_policy_violation'"));

        await Assert.ThrowsAsync<SqliteException>(() => conn.ExecuteAsync(
            "INSERT INTO alert (id, org_id, type, source_ref, title) " +
            "VALUES ('al2', 'o1', 'made_up_type', 'x', 'Nope')"));
    }

    [Fact]
    public async Task SbomPolicyAlertGate_DefaultsOn_LikeTheOtherTwo()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO alert_settings (org_id) VALUES ('o1')");

        var (quarantine, vuln, sbom) = await conn.QuerySingleAsync<(long Quarantine, long Vuln, long Sbom)>(
            "SELECT quarantine_alerts_enabled AS Quarantine, vuln_alerts_enabled AS Vuln, " +
            "sbom_policy_alerts_enabled AS Sbom FROM alert_settings WHERE org_id = 'o1'");

        Assert.Equal(1, quarantine);
        Assert.Equal(1, vuln);
        Assert.Equal(1, sbom);
    }
}
