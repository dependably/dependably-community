using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Integration;

/// <summary>
/// Live-Postgres coverage for the write side of INTEGER-encoded boolean columns:
/// <c>project_documents.tool_version_explicit_unknown</c>, <c>sbom_components.license_is_named</c>,
/// <c>sbom_components.is_external</c> (this SBOM epic), and <c>projects.is_active</c>/
/// <c>project_versions.is_active</c> (a pre-existing, live defect this file's own sweep turned up
/// while covering the SBOM columns above — the same one-character fix, filed and fixed together
/// under #711).
///
/// <para><b>Why this file exists.</b> Every one of those columns is declared <c>INTEGER</c> on
/// BOTH providers, but nothing before this file exercised the write path against a live Postgres
/// server. SQLite accepts a Dapper <c>bool</c> parameter into an <c>INTEGER</c> column silently
/// (it has no strict column typing); Npgsql instead maps a raw C# <c>bool</c>/<c>bool?</c> to
/// PostgreSQL's native <c>boolean</c> wire type, and Postgres has no implicit cast from
/// <c>boolean</c> to <c>integer</c> — the INSERT/UPDATE throws <c>42804</c>. 10,017 green SQLite
/// tests and a green <c>Category=Schema</c>/<c>Category=Compliance</c> run all missed this
/// because none of them writes these columns against a real Postgres backend. The read side is
/// unaffected either way — Dapper materializes an <c>integer</c> column into a C# <c>bool</c>
/// property on both providers without complaint — so only the write half needed live coverage.</para>
///
/// <para><b>A text-only sweep for this bug class is not reliable.</b> The <c>projects</c>/
/// <c>project_versions.is_active</c> instances were missed by an earlier grep-based sweep that
/// searched for <c>public bool</c> PROPERTY declarations — <c>ProjectRepository.Writes.cs</c>'s
/// <c>isActive</c> is a METHOD PARAMETER, a shape that sweep never looked for. Reliably catching
/// this class needs the C# compiler's own type information (a Roslyn-based compliance gate,
/// tracked separately), not a source-text pattern; this file's live-Postgres coverage is the
/// actual gate until one exists.</para>
///
/// <para>Every read below goes through <c>ExecuteScalarAsync&lt;long&gt;</c> against the raw
/// column, not through the repository's own typed read path, so a materialization-side coercion
/// bug could never mask a write-side one here.</para>
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class PostgresSbomDocumentWritePathTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    private static async Task<(string OrgId, string ProjectId, string ProjectVersionId)> SeedProjectVersionAsync(
        IMetadataStore store, string slug)
    {
        string orgId = await OrgSeeder.InsertAsync(store, slug);
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name) VALUES (@projectId, @orgId, @slug)",
            new { projectId, orgId, slug });
        await conn.ExecuteAsync(
            "INSERT INTO project_versions (id, org_id, project_id, version) VALUES (@versionId, @orgId, @projectId, '1.0.0')",
            new { versionId, orgId, projectId });
        return (orgId, projectId, versionId);
    }

    [Fact]
    public async Task UpsertAsync_WritesToolVersionExplicitlyUnknownTrue_AgainstLivePostgres()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();
        var (orgId, _, versionId) = await SeedProjectVersionAsync(store, "pg-write-doc");

        var repo = new ProjectDocumentRepository(store);
        var document = new ProjectDocument
        {
            OrgId = orgId,
            ProjectVersionId = versionId,
            DocType = "sbom",
            Format = "cyclonedx-json",
            SpecVersion = "1.6",
            ToolName = "cyclonedx-python",
            ToolVersion = null,
            Sha256 = new string('a', 64),
            SizeBytes = 100,
            BlobKey = $"hosted/{orgId}/{versionId}/sbom/{new string('a', 64)}",
            IngestVersion = SbomIngestVersion.Current,
            ToolVersionExplicitlyUnknown = true,
            UploadedAt = TestTime.KnownNow,
        };

        // The bug this test pins: `true` is a non-nullable bool, so this parameter is ALWAYS
        // present on every real upload — never an edge case a narrower test could miss.
        await repo.UpsertAsync(document);

        await using var conn = await store.OpenAsync();
        long stored = await conn.ExecuteScalarAsync<long>(
            "SELECT tool_version_explicit_unknown FROM project_documents WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId });
        Assert.Equal(1, stored);

        // The re-upload (UPDATE) arm of the same upsert — a second write must not regress
        // separately from the first.
        var reread = await repo.GetAsync(orgId, versionId, "sbom");
        Assert.NotNull(reread);
        await repo.UpsertAsync(new ProjectDocument
        {
            Id = reread!.Id,
            OrgId = orgId,
            ProjectVersionId = versionId,
            DocType = "sbom",
            Format = "cyclonedx-json",
            SpecVersion = "1.6",
            ToolName = "cyclonedx-python",
            Sha256 = new string('b', 64),
            SizeBytes = 100,
            BlobKey = $"hosted/{orgId}/{versionId}/sbom/{new string('b', 64)}",
            IngestVersion = SbomIngestVersion.Current,
            ToolVersionExplicitlyUnknown = false,
            UploadedAt = TestTime.KnownNow,
        });

        long updated = await conn.ExecuteScalarAsync<long>(
            "SELECT tool_version_explicit_unknown FROM project_documents WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId });
        Assert.Equal(0, updated);
    }

    [Fact]
    public async Task MergeComponentsAsync_WritesLicenseIsNamedAndIsExternal_OnBothInsertAndUpdate_AgainstLivePostgres()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();
        var (orgId, _, versionId) = await SeedProjectVersionAsync(store, "pg-write-components");

        var repo = new SbomIngestRepository(store);
        var component = new SbomComponentUpsert(
            Purl: "pkg:npm/left-pad@1.3.0",
            Ecosystem: "npm",
            PurlName: "left-pad",
            Version: "1.3.0",
            Name: "left-pad",
            ComponentType: "library",
            SbomScope: null,
            DependencyKind: null,
            DependencyPath: null,
            LicenseSpdx: "MIT",
            LicenseNamed: true,
            IsExternal: true);

        // INSERT arm — the exact failure mode this file pins: LicenseNamed/IsExternal are set to
        // real bool values here (true), always bound, never an edge case.
        await repo.MergeComponentsAsync(orgId, versionId, [component], TestTime.KnownNow);

        await using var conn = await store.OpenAsync();
        (long insertedLicenseIsNamed, long insertedIsExternal) = await conn.QuerySingleAsync<(long LicenseIsNamed, long IsExternal)>(
            "SELECT license_is_named, is_external FROM sbom_components WHERE project_version_id = @versionId AND name = 'left-pad'",
            new { versionId });
        Assert.Equal(1, insertedLicenseIsNamed);
        Assert.Equal(1, insertedIsExternal);

        // UPDATE arm — a second merge of the SAME (purl, name, version) key hits
        // UpdateComponentAsync, not InsertComponentAsync; both statements bind these two columns
        // independently and both must coerce.
        var updatedComponent = component with { LicenseNamed = false, IsExternal = false };
        await repo.MergeComponentsAsync(orgId, versionId, [updatedComponent], TestTime.KnownNow);

        (long updatedLicenseIsNamed, long updatedIsExternal) = await conn.QuerySingleAsync<(long LicenseIsNamed, long IsExternal)>(
            "SELECT license_is_named, is_external FROM sbom_components WHERE project_version_id = @versionId AND name = 'left-pad'",
            new { versionId });
        Assert.Equal(0, updatedLicenseIsNamed);
        Assert.Equal(0, updatedIsExternal);
    }

    [Fact]
    public async Task ProjectRepository_UpdateAsync_WritesProjectIsActive_AgainstLivePostgres()
    {
        // The PATCH /api/v1/projects/{id} write path — ProjectRepository.UpdateAsync always
        // writes all five columns including is_active, per its own doc comment, so this
        // parameter is bound on EVERY call, never an edge case.
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();
        var (orgId, projectId, _) = await SeedProjectVersionAsync(store, "pg-write-project-active");

        var repo = new ProjectRepository(store, TestTime.Frozen());

        var updated = await repo.UpdateAsync(
            orgId, projectId,
            new ProjectFields(
                Name: "app",
                Classifier: "application",
                Description: null,
                ParentId: null,
                IsActive: false));
        Assert.NotNull(updated);

        await using var conn = await store.OpenAsync();
        long stored = await conn.ExecuteScalarAsync<long>(
            "SELECT is_active FROM projects WHERE id = @projectId", new { projectId });
        Assert.Equal(0, stored);

        // Flip it back — both directions of the same non-nullable bool must coerce.
        await repo.UpdateAsync(
            orgId, projectId,
            new ProjectFields(
                Name: "app",
                Classifier: "application",
                Description: null,
                ParentId: null,
                IsActive: true));
        long reactivated = await conn.ExecuteScalarAsync<long>(
            "SELECT is_active FROM projects WHERE id = @projectId", new { projectId });
        Assert.Equal(1, reactivated);
    }

    [Fact]
    public async Task ProjectRepository_SetVersionActiveAsync_WritesProjectVersionIsActive_AgainstLivePostgres()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;
        await new SchemaInitializer(store).InitializeAsync();
        var (orgId, projectId, versionId) = await SeedProjectVersionAsync(store, "pg-write-version-active");

        var repo = new ProjectRepository(store, TestTime.Frozen());

        var updated = await repo.SetVersionActiveAsync(orgId, projectId, versionId, isActive: false);
        Assert.NotNull(updated);

        await using var conn = await store.OpenAsync();
        long stored = await conn.ExecuteScalarAsync<long>(
            "SELECT is_active FROM project_versions WHERE id = @versionId", new { versionId });
        Assert.Equal(0, stored);

        await repo.SetVersionActiveAsync(orgId, projectId, versionId, isActive: true);
        long reactivated = await conn.ExecuteScalarAsync<long>(
            "SELECT is_active FROM project_versions WHERE id = @versionId", new { versionId });
        Assert.Equal(1, reactivated);
    }
}
