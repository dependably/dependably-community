using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// SbomExportController (issue #379): CycloneDX 1.6 inventory/vdr re-renders, the vulnerabilities-
/// only VEX re-render, and verbatim original-document download. Every test seeds rows directly
/// against the projects-plane schema rather than going through <c>PUT /api/v1/sbom</c> — that
/// endpoint is a parallel, unmerged agent's work (see <see cref="RoundTrip_ExportedInventory_PreservesScopeAndComponents"/>
/// for the one test written specifically to be enabled once it lands).
/// </summary>
[Trait("Category", "Integration")]
public sealed class SbomExportControllerTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public SbomExportControllerTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    private static async Task<string> DefaultOrgIdAsync(System.Data.IDbConnection conn)
        => await conn.ExecuteScalarAsync<string>("SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
           ?? throw new InvalidOperationException("Default org not found.");

    private static async Task<(string ProjectId, string VersionId, string ProjectName, string VersionLabel)>
        SeedProjectVersionAsync(System.Data.IDbConnection conn, string orgId, string projectName = "shipyard-api", string versionLabel = "3.4.1")
    {
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO projects (id, org_id, kind, name, classifier, created_at)
            VALUES (@projectId, @orgId, 'project', @projectName, 'application', strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { projectId, orgId, projectName });
        await conn.ExecuteAsync(
            """
            INSERT INTO project_versions (id, org_id, project_id, version, is_latest, created_at)
            VALUES (@versionId, @orgId, @projectId, @versionLabel, 1, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { versionId, orgId, projectId, versionLabel });
        return (projectId, versionId, projectName, versionLabel);
    }

    private static async Task InsertComponentAsync(
        System.Data.IDbConnection conn, string orgId, string versionId,
        string purl, string name, string version, string? sbomScope, string dependencyScope,
        string? dependencyPath, string? licenseSpdx)
    {
        string id = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                 component_type, sbom_scope, dependency_scope, dependency_kind, dependency_path,
                 license_spdx, created_at)
            VALUES
                (@id, @orgId, @versionId, @purl, 'npm', @name, @version, @name,
                 'library', @sbomScope, @dependencyScope, 'direct', @dependencyPath,
                 @licenseSpdx, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { id, orgId, versionId, purl, name, version, sbomScope, dependencyScope, dependencyPath, licenseSpdx });
    }

    private async Task<string> CreateOtherOrgReadTokenAsync()
    {
        var orgRepo = _factory.Services.GetRequiredService<OrgRepository>();
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        var other = await orgRepo.CreateOrgAsync($"other-{Guid.NewGuid():N}"[..16]);
        var (raw, _) = await tokens.CreateServiceTokenAsync(
            other.Id, $"xtenant-{Guid.NewGuid():N}"[..16], """["read:packages"]""", expiresAt: null);
        return raw;
    }

    // ── export/sbom?variant=inventory ───────────────────────────────────────────

    [Fact]
    public async Task ExportSbom_Inventory_WritesScopeFromSbomScopeOnly_AndClosesTheDependencyGraph()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = await DefaultOrgIdAsync(conn);
        var (projectId, versionId, projectName, versionLabel) = await SeedProjectVersionAsync(conn, orgId);

        // Direct child of root, sbom_scope=excluded, dependency_scope=runtime — pins CONTRACT D1:
        // the export must read scope from sbom_scope, never dependency_scope.
        await InsertComponentAsync(conn, orgId, versionId,
            "pkg:nuget/Serilog@2.12.0", "Serilog", "2.12.0",
            sbomScope: "excluded", dependencyScope: "runtime",
            dependencyPath: """["pkg:nuget/Serilog@2.12.0"]""", licenseSpdx: "Apache-2.0");

        // Transitive child of Serilog, no sbom_scope recorded at all — dependency_scope=dev must
        // never leak into the exported "scope" field.
        await InsertComponentAsync(conn, orgId, versionId,
            "pkg:nuget/System.Text.Encodings.Web@4.7.1", "System.Text.Encodings.Web", "4.7.1",
            sbomScope: null, dependencyScope: "dev",
            dependencyPath: """["pkg:nuget/Serilog@2.12.0","pkg:nuget/System.Text.Encodings.Web@4.7.1"]""",
            licenseSpdx: "MIT");

        // Direct child of root, required scope.
        await InsertComponentAsync(conn, orgId, versionId,
            "pkg:npm/lodash@4.17.21", "lodash", "4.17.21",
            sbomScope: "required", dependencyScope: "runtime",
            dependencyPath: """["pkg:npm/lodash@4.17.21"]""", licenseSpdx: "MIT");

        using var c = await AdminClient();
        var resp = await c.GetAsync(
            $"/api/v1/projects/{projectId}/versions/{versionId}/export/sbom?variant=inventory");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("application/vnd.cyclonedx+json; version=1.7", resp.Content.Headers.ContentType!.ToString());

        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        var root = doc.RootElement;
        Assert.Equal("CycloneDX", root.GetProperty("bomFormat").GetString());
        Assert.Equal("1.7", root.GetProperty("specVersion").GetString());
        Assert.Equal(projectName, root.GetProperty("metadata").GetProperty("component").GetProperty("name").GetString());
        Assert.Equal(versionLabel, root.GetProperty("metadata").GetProperty("component").GetProperty("version").GetString());
        Assert.False(root.TryGetProperty("vulnerabilities", out _), "inventory variant must not carry a vulnerabilities array");

        var components = root.GetProperty("components").EnumerateArray().ToList();
        Assert.Equal(3, components.Count);

        var serilog = components.Single(x => x.GetProperty("name").GetString() == "Serilog");
        Assert.Equal("excluded", serilog.GetProperty("scope").GetString());

        var stew = components.Single(x => x.GetProperty("name").GetString() == "System.Text.Encodings.Web");
        Assert.False(stew.TryGetProperty("scope", out _), "a component with no sbom_scope must omit the scope field entirely");

        var lodash = components.Single(x => x.GetProperty("name").GetString() == "lodash");
        Assert.Equal("required", lodash.GetProperty("scope").GetString());
        Assert.Equal("MIT", lodash.GetProperty("licenses")[0].GetProperty("expression").GetString());

        // The dependency graph is closed: every ref that appears inside a dependsOn array also
        // has its own top-level entry — no dangling edges.
        var deps = root.GetProperty("dependencies").EnumerateArray().ToList();
        var allRefs = deps.Select(d => d.GetProperty("ref").GetString()).ToHashSet();
        foreach (var d in deps)
        {
            foreach (var child in d.GetProperty("dependsOn").EnumerateArray())
            {
                Assert.Contains(child.GetString(), allRefs);
            }
        }

        string rootRef = $"{projectName}@{versionLabel}";
        var rootDeps = deps.Single(d => d.GetProperty("ref").GetString() == rootRef)
            .GetProperty("dependsOn").EnumerateArray().Select(x => x.GetString()).ToList();
        Assert.Contains("pkg:nuget/Serilog@2.12.0", rootDeps);
        Assert.Contains("pkg:npm/lodash@4.17.21", rootDeps);
        Assert.DoesNotContain("pkg:nuget/System.Text.Encodings.Web@4.7.1", rootDeps);

        var serilogDeps = deps.Single(d => d.GetProperty("ref").GetString() == "pkg:nuget/Serilog@2.12.0")
            .GetProperty("dependsOn").EnumerateArray().Select(x => x.GetString()).ToList();
        Assert.Contains("pkg:nuget/System.Text.Encodings.Web@4.7.1", serilogDeps);
    }

    [Fact]
    public async Task ExportSbom_InvalidVariant_Returns422()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = await DefaultOrgIdAsync(conn);
        var (projectId, versionId, _, _) = await SeedProjectVersionAsync(conn, orgId, "variant-check", "1.0.0");

        using var c = await AdminClient();
        var resp = await c.GetAsync(
            $"/api/v1/projects/{projectId}/versions/{versionId}/export/sbom?variant=not-a-real-variant");
        Assert.Equal((HttpStatusCode)422, resp.StatusCode);
    }

    [Fact]
    public async Task ExportSbom_LatestLiteral_ResolvesTheLatestVersion()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = await DefaultOrgIdAsync(conn);
        var (projectId, versionId, _, versionLabel) = await SeedProjectVersionAsync(conn, orgId, "latest-check", "2.0.0");

        using var c = await AdminClient();
        var resp = await c.GetAsync($"/api/v1/projects/{projectId}/versions/latest/export/sbom?variant=inventory");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal(versionLabel, doc.RootElement.GetProperty("metadata").GetProperty("component").GetProperty("version").GetString());
    }

    [Fact]
    public async Task ExportSbom_UnknownProject_Returns404()
    {
        using var c = await AdminClient();
        var resp = await c.GetAsync($"/api/v1/projects/{Guid.NewGuid():N}/versions/latest/export/sbom?variant=inventory");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task ExportSbom_TokenFromOtherOrg_Returns404NotForbidden()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = await DefaultOrgIdAsync(conn);
        var (projectId, versionId, _, _) = await SeedProjectVersionAsync(conn, orgId, "xtenant-check", "1.0.0");

        string crossToken = await CreateOtherOrgReadTokenAsync();
        using var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", crossToken);
        var resp = await c.GetAsync($"/api/v1/projects/{projectId}/versions/{versionId}/export/sbom?variant=inventory");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── export/sbom?variant=vdr ──────────────────────────────────────────────────

    [Fact]
    public async Task ExportSbom_Vdr_CarriesAnalysisStatesMatchingTheDatabase()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = await DefaultOrgIdAsync(conn);
        var (projectId, versionId, _, _) = await SeedProjectVersionAsync(conn, orgId, "vdr-check", "1.0.0");

        string compId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                 component_type, sbom_scope, dependency_scope, dependency_kind, created_at)
            VALUES
                (@compId, @orgId, @versionId, 'pkg:npm/qs@6.10.2', 'npm', 'qs', '6.10.2', 'qs',
                 'library', 'required', 'runtime', 'direct', strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { compId, orgId, versionId });

        string vulnId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity, cvss_score, fetched_at)
            VALUES (@vulnId, 'CVE-2022-24999', 'npm', 'qs', 'HIGH', 7.5, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { vulnId });

        string linkId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO sbom_component_vulns (id, component_id, vuln_id, checked_at) VALUES (@linkId, @compId, @vulnId, strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
            new { linkId, compId, vulnId });

        string analysisId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO project_vuln_analysis
                (id, org_id, project_version_id, purl_key, vuln_key, vex_state, vex_justification,
                 vex_response, vex_detail, vex_source, updated_at)
            VALUES
                (@analysisId, @orgId, @versionId, 'pkg:npm/qs', 'CVE-2022-24999', 'exploitable', NULL,
                 'update', 'qs.parse is reachable from an unauthenticated route.', 'upload',
                 strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { analysisId, orgId, versionId });

        using var c = await AdminClient();
        var resp = await c.GetAsync($"/api/v1/projects/{projectId}/versions/{versionId}/export/sbom?variant=vdr");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        var vulns = doc.RootElement.GetProperty("vulnerabilities").EnumerateArray().ToList();
        var entry = Assert.Single(vulns);
        Assert.Equal("CVE-2022-24999", entry.GetProperty("id").GetString());
        Assert.Equal("NVD", entry.GetProperty("source").GetProperty("name").GetString());
        Assert.Equal(7.5, entry.GetProperty("ratings")[0].GetProperty("score").GetDouble());
        Assert.Equal("high", entry.GetProperty("ratings")[0].GetProperty("severity").GetString());
        Assert.Equal("exploitable", entry.GetProperty("analysis").GetProperty("state").GetString());
        Assert.Equal("update", entry.GetProperty("analysis").GetProperty("response")[0].GetString());
        Assert.Equal("pkg:npm/qs@6.10.2", entry.GetProperty("affects")[0].GetProperty("ref").GetString());
    }

    [Fact]
    public async Task ExportSbom_Vdr_CarriesTheAnalysisBlock_ForCanonicalizedCoordinates()
    {
        // The rows are keyed the way ingest keys them: %40 decoded, NuGet ids lowercased. An
        // exporter that re-derives the key by cutting the verbatim purl at an '@' finds neither,
        // and ships a VDR that omits the very analysis that says the finding is suppressed.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = await DefaultOrgIdAsync(conn);
        var (projectId, versionId, _, _) = await SeedProjectVersionAsync(conn, orgId, "vdr-canonical", "1.0.0");

        await SeedAnalysedComponentAsync(
            conn, orgId, versionId,
            purl: "pkg:npm/%40babel/core@7.24.7", ecosystem: "npm", purlName: "@babel/core",
            name: "@babel/core", version: "7.24.7",
            purlKey: "pkg:npm/@babel/core", osvId: "CVE-2100-4001");
        await SeedAnalysedComponentAsync(
            conn, orgId, versionId,
            purl: "pkg:nuget/Newtonsoft.Json@12.0.3", ecosystem: "nuget", purlName: "newtonsoft.json",
            name: "Newtonsoft.Json", version: "12.0.3",
            purlKey: "pkg:nuget/newtonsoft.json", osvId: "CVE-2100-4002");

        using var c = await AdminClient();
        var resp = await c.GetAsync($"/api/v1/projects/{projectId}/versions/{versionId}/export/sbom?variant=vdr");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        var byId = doc.RootElement.GetProperty("vulnerabilities").EnumerateArray()
            .ToDictionary(e => e.GetProperty("id").GetString()!);
        Assert.Equal(2, byId.Count);
        Assert.Equal("not_affected", byId["CVE-2100-4001"].GetProperty("analysis").GetProperty("state").GetString());
        Assert.Equal("not_affected", byId["CVE-2100-4002"].GetProperty("analysis").GetProperty("state").GetString());
    }

    private static async Task SeedAnalysedComponentAsync(
        System.Data.IDbConnection conn, string orgId, string versionId,
        string purl, string ecosystem, string purlName, string name, string version,
        string purlKey, string osvId)
    {
        string compId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                 component_type, dependency_scope, created_at)
            VALUES
                (@compId, @orgId, @versionId, @purl, @ecosystem, @purlName, @version, @name,
                 'library', 'runtime', strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { compId, orgId, versionId, purl, ecosystem, purlName, version, name });

        string vulnId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity, cvss_score, fetched_at)
            VALUES (@vulnId, @osvId, @ecosystem, @purlName, 'HIGH', 7.5, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { vulnId, osvId, ecosystem, purlName });
        await conn.ExecuteAsync(
            "INSERT INTO sbom_component_vulns (id, component_id, vuln_id, checked_at) VALUES (@id, @compId, @vulnId, strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
            new { id = Guid.NewGuid().ToString("N"), compId, vulnId });
        await conn.ExecuteAsync(
            """
            INSERT INTO project_vuln_analysis
                (id, org_id, project_version_id, purl_key, vuln_key, vex_state, vex_justification,
                 vex_source, updated_at)
            VALUES
                (@id, @orgId, @versionId, @purlKey, @osvId, 'not_affected', 'code_not_reachable',
                 'upload', strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, versionId, purlKey, osvId });
    }

    [Fact]
    public async Task ExportSbom_Vdr_OmitsAnalysisBlock_WhenNoTriageRowMatches()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = await DefaultOrgIdAsync(conn);
        var (projectId, versionId, _, _) = await SeedProjectVersionAsync(conn, orgId, "vdr-no-analysis", "1.0.0");

        string compId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                 component_type, dependency_scope, dependency_kind, created_at)
            VALUES
                (@compId, @orgId, @versionId, 'pkg:pypi/requests@2.28.1', 'pypi', 'requests', '2.28.1', 'requests',
                 'library', 'runtime', 'direct', strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { compId, orgId, versionId });

        string vulnId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity, cvss_score, fetched_at)
            VALUES (@vulnId, 'CVE-2023-32681', 'pypi', 'requests', 'MEDIUM', 6.1, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { vulnId });
        string linkId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO sbom_component_vulns (id, component_id, vuln_id, checked_at) VALUES (@linkId, @compId, @vulnId, strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
            new { linkId, compId, vulnId });

        using var c = await AdminClient();
        var resp = await c.GetAsync($"/api/v1/projects/{projectId}/versions/{versionId}/export/sbom?variant=vdr");
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        var entry = Assert.Single(doc.RootElement.GetProperty("vulnerabilities").EnumerateArray());
        Assert.False(entry.TryGetProperty("analysis", out _));
    }

    // ── export/vex ────────────────────────────────────────────────────────────

    [Fact]
    public async Task ExportVex_ListsUploadAndManualRows_ButExcludesRowsWithNoVexState()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = await DefaultOrgIdAsync(conn);
        var (projectId, versionId, _, _) = await SeedProjectVersionAsync(conn, orgId, "vex-check", "1.0.0");

        await conn.ExecuteAsync(
            """
            INSERT INTO project_vuln_analysis
                (id, org_id, project_version_id, purl_key, vuln_key, vex_state, vex_source, updated_at)
            VALUES (@id, @orgId, @versionId, 'pkg:npm/minimist', 'CVE-2021-44906', 'exploitable', 'upload', strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, versionId });

        await conn.ExecuteAsync(
            """
            INSERT INTO project_vuln_analysis
                (id, org_id, project_version_id, purl_key, vuln_key, vex_state, vex_justification, vex_source, updated_at)
            VALUES (@id, @orgId, @versionId, 'pkg:pypi/requests', 'CVE-2023-32681', 'not_affected', 'code_not_reachable', 'manual', strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, versionId });

        // A SARIF-only row: reachability facts, no VEX opinion — must not appear in a VEX export.
        await conn.ExecuteAsync(
            """
            INSERT INTO project_vuln_analysis
                (id, org_id, project_version_id, purl_key, vuln_key, reachability, updated_at)
            VALUES (@id, @orgId, @versionId, 'pkg:npm/lodash', 'CVE-9999-00000', 'reachable', strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, versionId });

        using var c = await AdminClient();
        var resp = await c.GetAsync($"/api/v1/projects/{projectId}/versions/{versionId}/export/vex");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("application/vnd.cyclonedx+json; version=1.7", resp.Content.Headers.ContentType!.ToString());

        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        var vulns = doc.RootElement.GetProperty("vulnerabilities").EnumerateArray().ToList();
        Assert.Equal(2, vulns.Count);
        Assert.DoesNotContain(vulns, v => v.GetProperty("id").GetString() == "CVE-9999-00000");

        var exploitable = vulns.Single(v => v.GetProperty("id").GetString() == "CVE-2021-44906");
        Assert.Equal("exploitable", exploitable.GetProperty("analysis").GetProperty("state").GetString());

        var notAffected = vulns.Single(v => v.GetProperty("id").GetString() == "CVE-2023-32681");
        Assert.Equal("not_affected", notAffected.GetProperty("analysis").GetProperty("state").GetString());
        Assert.Equal("code_not_reachable", notAffected.GetProperty("analysis").GetProperty("justification").GetString());
    }

    // ── sbom-documents/{id}/original ─────────────────────────────────────────────

    [Fact]
    public async Task DownloadOriginal_StreamsByteIdenticalBlob_WithDerivedFilenameAndFullSha256ETag()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = await DefaultOrgIdAsync(conn);
        var (projectId, versionId, projectName, versionLabel) = await SeedProjectVersionAsync(conn, orgId, "original-check", "1.0.0");

        byte[] bytes = Encoding.UTF8.GetBytes("""{"bomFormat":"CycloneDX","specVersion":"1.6"}""");
        string sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        string blobKey = BlobKeys.ProjectDocument(orgId, projectId, versionId, "sbom", sha256);
        await using (var blobStream = new MemoryStream(bytes))
        {
            await _factory.BlobStore.PutAsync(blobKey, blobStream);
        }

        string documentId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO project_documents
                (id, org_id, project_version_id, doc_type, format, spec_version, sha256, size_bytes, blob_key, uploaded_at)
            VALUES
                (@documentId, @orgId, @versionId, 'sbom', 'cyclonedx-json', '1.6', @sha256, @size, @blobKey, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { documentId, orgId, versionId, sha256, size = bytes.Length, blobKey });

        using var c = await AdminClient();
        var resp = await c.GetAsync($"/api/v1/sbom-documents/{documentId}/original");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        byte[] downloaded = await resp.Content.ReadAsByteArrayAsync();
        Assert.Equal(bytes, downloaded);
        string downloadedSha = Convert.ToHexString(SHA256.HashData(downloaded)).ToLowerInvariant();
        Assert.Equal(sha256, downloadedSha);

        Assert.Equal($"\"{sha256}\"", resp.Headers.ETag!.Tag);
        Assert.Equal(
            ProjectDocumentNaming.FileName(projectName, versionLabel, "sbom"),
            resp.Content.Headers.ContentDisposition!.FileName!.Trim('"'));
    }

    [Fact]
    public async Task DownloadOriginal_IfNoneMatchCurrentEtag_Returns304()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = await DefaultOrgIdAsync(conn);
        var (projectId, versionId, _, _) = await SeedProjectVersionAsync(conn, orgId, "etag-check", "1.0.0");

        byte[] bytes = Encoding.UTF8.GetBytes("""{"bomFormat":"CycloneDX"}""");
        string sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        string blobKey = BlobKeys.ProjectDocument(orgId, projectId, versionId, "sbom", sha256);
        await using (var blobStream = new MemoryStream(bytes))
        {
            await _factory.BlobStore.PutAsync(blobKey, blobStream);
        }

        string documentId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO project_documents
                (id, org_id, project_version_id, doc_type, format, spec_version, sha256, size_bytes, blob_key, uploaded_at)
            VALUES
                (@documentId, @orgId, @versionId, 'sbom', 'cyclonedx-json', '1.6', @sha256, @size, @blobKey, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { documentId, orgId, versionId, sha256, size = bytes.Length, blobKey });

        using var c = await AdminClient();
        c.DefaultRequestHeaders.IfNoneMatch.Add(new EntityTagHeaderValue($"\"{sha256}\""));
        var resp = await c.GetAsync($"/api/v1/sbom-documents/{documentId}/original");
        Assert.Equal(HttpStatusCode.NotModified, resp.StatusCode);
    }

    [Fact]
    public async Task DownloadOriginal_UnknownDocument_Returns404()
    {
        using var c = await AdminClient();
        var resp = await c.GetAsync($"/api/v1/sbom-documents/{Guid.NewGuid():N}/original");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    [Fact]
    public async Task DownloadOriginal_TokenFromOtherOrg_Returns404NotForbidden()
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string orgId = await DefaultOrgIdAsync(conn);
        var (projectId, versionId, _, _) = await SeedProjectVersionAsync(conn, orgId, "original-xtenant", "1.0.0");

        byte[] bytes = Encoding.UTF8.GetBytes("""{"bomFormat":"CycloneDX"}""");
        string sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        string blobKey = BlobKeys.ProjectDocument(orgId, projectId, versionId, "sbom", sha256);
        await using (var blobStream = new MemoryStream(bytes))
        {
            await _factory.BlobStore.PutAsync(blobKey, blobStream);
        }

        string documentId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO project_documents
                (id, org_id, project_version_id, doc_type, format, spec_version, sha256, size_bytes, blob_key, uploaded_at)
            VALUES
                (@documentId, @orgId, @versionId, 'sbom', 'cyclonedx-json', '1.6', @sha256, @size, @blobKey, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            """,
            new { documentId, orgId, versionId, sha256, size = bytes.Length, blobKey });

        string crossToken = await CreateOtherOrgReadTokenAsync();
        using var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", crossToken);
        var resp = await c.GetAsync($"/api/v1/sbom-documents/{documentId}/original");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    // ── Round trip ────────────────────────────────────────────────────────────────

    /// <summary>
    /// An exported inventory re-imports cleanly through the upload endpoint. Uploads the shared
    /// <c>cyclonedx-1.6-inventory.json</c> fixture, exports it back out, and re-uploads the
    /// export — asserting the second upload's component count matches the first, and that the
    /// scope vocabulary survives the round trip: the exported <c>scope</c> comes from
    /// <c>sbom_scope</c> alone, never from the reachability-owned dev/prod signal, checked
    /// through the fixture's <c>pkg:nuget/Serilog@2.12.0</c> (<c>scope: "excluded"</c>).
    /// </summary>
    [Fact]
    public async Task RoundTrip_ExportedInventory_PreservesScopeAndComponents()
    {
        string fixturePath = Path.Combine(FixtureManifest.SbomFixturesRoot, "cyclonedx-1.6-inventory.json");
        byte[] fixtureBytes = await File.ReadAllBytesAsync(fixturePath);

        using var c = await AdminClient();
        using var firstUpload = new ByteArrayContent(fixtureBytes);
        firstUpload.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        var putResp = await c.PutAsync(
            "/api/v1/sbom?projectName=shipyard-api&projectVersion=3.4.1&autoCreate=true", firstUpload);
        putResp.EnsureSuccessStatusCode();
        var putDoc = await JsonDocument.ParseAsync(await putResp.Content.ReadAsStreamAsync());
        string projectId = putDoc.RootElement.GetProperty("project").GetProperty("id").GetString()!;
        string versionId = putDoc.RootElement.GetProperty("projectVersion").GetProperty("id").GetString()!;
        int firstComponentTotal = putDoc.RootElement.GetProperty("components").GetProperty("total").GetInt32();

        var exportResp = await c.GetAsync($"/api/v1/projects/{projectId}/versions/{versionId}/export/sbom?variant=inventory");
        exportResp.EnsureSuccessStatusCode();
        byte[] exported = await exportResp.Content.ReadAsByteArrayAsync();

        var exportedDoc = JsonDocument.Parse(exported);
        var serilog = exportedDoc.RootElement.GetProperty("components").EnumerateArray()
            .Single(x => x.GetProperty("name").GetString() == "Serilog");
        Assert.Equal("excluded", serilog.GetProperty("scope").GetString());

        using var secondUpload = new ByteArrayContent(exported);
        secondUpload.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        var reimportResp = await c.PutAsync(
            "/api/v1/sbom?projectName=shipyard-api-reimport&projectVersion=3.4.1&autoCreate=true", secondUpload);
        reimportResp.EnsureSuccessStatusCode();
        var reimportDoc = await JsonDocument.ParseAsync(await reimportResp.Content.ReadAsStreamAsync());
        int secondComponentTotal = reimportDoc.RootElement.GetProperty("components").GetProperty("total").GetInt32();

        Assert.Equal(firstComponentTotal, secondComponentTotal);
    }
}
