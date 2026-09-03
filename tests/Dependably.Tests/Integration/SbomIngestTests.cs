using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// End-to-end coverage of the three document-upload surfaces against a real host, a frozen clock
/// and the shared spec-valid fixtures.
///
/// <para>The assertions deliberately read the database rather than the response body wherever a
/// response number could be right for the wrong reason: a merge that reports thirteen components
/// and writes eleven rows is exactly the failure a response-only assertion cannot see.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class SbomIngestTests : IAsyncLifetime
{
    // Its own host rather than the shared fixture, so the upload cap can be pinned low enough to
    // exercise the 413 path without moving 50 MB through the pipeline. The clock is frozen so
    // uploaded_at is an exact instant rather than whatever wall time the suite happened to run at.
    private readonly DependablyFactory _factory = new()
    {
        FrozenClock = TestTime.Frozen(),
        ExtraSettings = new Dictionary<string, string?> { ["Sbom:MaxUploadBytes"] = "65536" },
    };

    public async Task InitializeAsync() => await _factory.InitializeAsync();

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    private static string Fixtures(string name) =>
        Path.Combine(FixtureManifest.SbomFixturesRoot, name);

    private async Task<HttpClient> UploaderAsync()
    {
        string jwt = await _factory.CreateAdminJwt();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    private static HttpContent Document(string fixtureName)
    {
        var content = new ByteArrayContent(File.ReadAllBytes(Fixtures(fixtureName)));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return content;
    }

    private static async Task<JsonElement> BodyAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

    private async Task<T?> QueryAsync<T>(string sql, object? parameters = null)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<T>(sql, parameters);
    }

    private async Task<IReadOnlyList<T>> ListAsync<T>(string sql, object? parameters = null)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return (await conn.QueryAsync<T>(sql, parameters)).ToList();
    }

    private static string Project(string caller) => $"proj-{caller}";

    // ── SBOM ─────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task SbomUpload_CreatesProjectAndMergesTheWholeInventory()
    {
        string project = Project("inventory");
        using var client = await UploaderAsync();

        var response = await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=3.4.1&autoCreate=true&isLatest=true",
            Document("cyclonedx-1.6-inventory.json"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await BodyAsync(response);
        Assert.Equal(13, body.GetProperty("components").GetProperty("total").GetInt32());
        Assert.Equal(13, body.GetProperty("components").GetProperty("added").GetInt32());
        Assert.Equal(0, body.GetProperty("components").GetProperty("removed").GetInt32());
        Assert.Equal(0, body.GetProperty("embeddedVexStatements").GetInt32());
        Assert.Equal(project, body.GetProperty("project").GetProperty("name").GetString());
        Assert.Equal("3.4.1", body.GetProperty("projectVersion").GetProperty("version").GetString());

        string versionId = body.GetProperty("projectVersion").GetProperty("id").GetString()!;
        Assert.Equal(13, await QueryAsync<int>(
            "SELECT COUNT(*) FROM sbom_components WHERE project_version_id = @versionId",
            new { versionId }));

        // The document row records the producing tool and the spec version it declared, and the
        // classifier seeds the created project from metadata.component.type.
        Assert.Equal("1.6", await QueryAsync<string>(
            "SELECT spec_version FROM project_documents WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId }));
        Assert.Equal("cyclonedx-npm", await QueryAsync<string>(
            "SELECT tool_name FROM project_documents WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId }));
        Assert.Equal("application", await QueryAsync<string>(
            "SELECT p.classifier FROM projects p JOIN project_versions v ON v.project_id = p.id WHERE v.id = @versionId",
            new { versionId }));
        Assert.Equal(1, await QueryAsync<int>(
            "SELECT is_latest FROM project_versions WHERE id = @versionId", new { versionId }));
    }

    [Fact]
    public async Task SbomUpload_WithScanJobDisabled_ReportsNotQueuedAndWritesNoScanResults()
    {
        // The harness disables the sbom-scan job. The worker honours that switch on the enqueue,
        // so no upload in the suite fires an advisory query, and the response says so rather than
        // claiming a scan that will never run. Without this the worker drains on every upload and
        // writes sbom_component_vulns / vuln_checked_at / policy_status asynchronously while the
        // suite is asserting against the same rows.
        string project = Project("scan-gated");
        using var client = await UploaderAsync();

        var response = await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true",
            Document("cyclonedx-1.6-inventory.json"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await BodyAsync(response);
        Assert.False(body.GetProperty("scanQueued").GetBoolean());

        string versionId = body.GetProperty("projectVersion").GetProperty("id").GetString()!;
        Assert.Equal(0, await QueryAsync<int>(
            """
            SELECT COUNT(*) FROM sbom_component_vulns scv
            JOIN sbom_components sc ON sc.id = scv.component_id
            WHERE sc.project_version_id = @versionId
            """,
            new { versionId }));
        Assert.Equal(0, await QueryAsync<int>(
            "SELECT COUNT(*) FROM sbom_components WHERE project_version_id = @versionId AND vuln_checked_at IS NOT NULL",
            new { versionId }));
    }

    [Fact]
    public async Task SbomUpload_NormalizesPurlsAndKeepsScopeAndLicenceFacts()
    {
        string project = Project("facts");
        using var client = await UploaderAsync();
        var response = await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true",
            Document("cyclonedx-1.6-inventory.json"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        string versionId = (await BodyAsync(response))
            .GetProperty("projectVersion").GetProperty("id").GetString()!;

        // A scoped npm name arrives percent-encoded in the purl and must land decoded, or the
        // SARIF fold and the VEX binding key it differently from the SBOM did.
        Assert.Equal("@babel/core", await QueryAsync<string>(
            "SELECT purl_name FROM sbom_components WHERE project_version_id = @versionId AND name = '@babel/core'",
            new { versionId }));
        Assert.Equal("npm", await QueryAsync<string>(
            "SELECT ecosystem FROM sbom_components WHERE project_version_id = @versionId AND name = '@babel/core'",
            new { versionId }));

        // Raw CycloneDX scope is kept verbatim and stays display-only.
        Assert.Equal("excluded", await QueryAsync<string>(
            "SELECT sbom_scope FROM sbom_components WHERE project_version_id = @versionId AND name = 'Serilog'",
            new { versionId }));
        Assert.Null(await QueryAsync<string>(
            "SELECT sbom_scope FROM sbom_components WHERE project_version_id = @versionId AND name = 'urllib3'",
            new { versionId }));

        // Licences arrive in both the expression form and the license.id form; a component that
        // declares none records none rather than a fabricated value.
        Assert.Equal("MIT", await QueryAsync<string>(
            "SELECT license_spdx FROM sbom_components WHERE project_version_id = @versionId AND name = 'lodash'",
            new { versionId }));
        Assert.Equal("Apache-2.0", await QueryAsync<string>(
            "SELECT license_spdx FROM sbom_components WHERE project_version_id = @versionId AND name = 'requests'",
            new { versionId }));
        Assert.Null(await QueryAsync<string>(
            "SELECT license_spdx FROM sbom_components WHERE project_version_id = @versionId AND name = 'charset-normalizer'",
            new { versionId }));
    }

    [Fact]
    public async Task SbomUpload_StampsGraphPositionButNeverTheDevProdSignal()
    {
        string project = Project("graph");
        using var client = await UploaderAsync();
        var response = await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true",
            Document("cyclonedx-1.6-inventory.json"));
        string versionId = (await BodyAsync(response))
            .GetProperty("projectVersion").GetProperty("id").GetString()!;

        Assert.Equal("direct", await QueryAsync<string>(
            "SELECT dependency_kind FROM sbom_components WHERE project_version_id = @versionId AND name = 'lodash'",
            new { versionId }));
        Assert.Equal("transitive", await QueryAsync<string>(
            "SELECT dependency_kind FROM sbom_components WHERE project_version_id = @versionId AND name = 'minimist'",
            new { versionId }));
        Assert.Equal(
            """["pkg:npm/eslint@8.57.0","pkg:npm/minimist@1.2.5"]""",
            await QueryAsync<string>(
                "SELECT dependency_path FROM sbom_components WHERE project_version_id = @versionId AND name = 'minimist'",
                new { versionId }));

        // dependency_scope is the reachability scanner's column. An SBOM merge that wrote it
        // would report every component as classified before anything had classified it.
        var scopes = await ListAsync<string>(
            "SELECT DISTINCT dependency_scope FROM sbom_components WHERE project_version_id = @versionId",
            new { versionId });
        Assert.Equal(new[] { "unknown" }, scopes);
    }

    [Fact]
    public async Task SbomReupload_OfIdenticalBytes_IsAnIdempotentNoOp()
    {
        string project = Project("dedup");
        using var client = await UploaderAsync();
        string route = $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true";

        var first = await client.PutAsync(route, Document("cyclonedx-1.6-inventory.json"));
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var firstBody = await BodyAsync(first);

        var second = await client.PutAsync(route, Document("cyclonedx-1.6-inventory.json"));
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        var secondBody = await BodyAsync(second);

        Assert.Equal(0, secondBody.GetProperty("components").GetProperty("added").GetInt32());
        Assert.Equal(0, secondBody.GetProperty("components").GetProperty("removed").GetInt32());
        Assert.Equal(13, secondBody.GetProperty("components").GetProperty("unchanged").GetInt32());
        Assert.Equal(
            firstBody.GetProperty("documentId").GetString(),
            secondBody.GetProperty("documentId").GetString());
    }

    [Fact]
    public async Task SbomReupload_OfADifferentInventory_AddsAndRemovesInOnePass()
    {
        string project = Project("mixedmerge");
        using var client = await UploaderAsync();
        string route = $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true";

        await client.PutAsync(route, Document("cyclonedx-1.6-inventory.json"));
        var response = await client.PutAsync(route, Document("cyclonedx-1.6-vdr.json"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // The VDR fixture carries the same inventory plus embedded statements, so the merge
        // reports every row unchanged — the digest differs, so this is a real merge pass, not
        // the dedup no-op.
        var body = await BodyAsync(response);
        Assert.Equal(0, body.GetProperty("components").GetProperty("added").GetInt32());
        Assert.Equal(0, body.GetProperty("components").GetProperty("removed").GetInt32());
        Assert.Equal(13, body.GetProperty("components").GetProperty("unchanged").GetInt32());
        Assert.Equal(3, body.GetProperty("embeddedVexStatements").GetInt32());

        // Replacing it with the small 1.5 document removes the whole previous inventory and adds
        // that document's own — added and removed both non-zero in one call.
        var swapped = await client.PutAsync(route, Document("cyclonedx-1.5-minimal.json"));
        var swappedBody = await BodyAsync(swapped);
        Assert.Equal(2, swappedBody.GetProperty("components").GetProperty("added").GetInt32());
        Assert.Equal(13, swappedBody.GetProperty("components").GetProperty("removed").GetInt32());
    }

    [Theory]
    [InlineData("cyclonedx-1.4-minimal.json", 2)]
    [InlineData("cyclonedx-1.5-minimal.json", 2)]
    [InlineData("cyclonedx-1.7-minimal.json", 3)]
    public async Task SbomUpload_AcceptsTheWholeSupportedSpecRange(string fixture, int expected)
    {
        string project = Project("range-" + fixture);
        using var client = await UploaderAsync();
        var response = await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true",
            Document(fixture));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(expected, (await BodyAsync(response))
            .GetProperty("components").GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task SbomUpload_RejectsASpecVersionOutsideTheSupportedRange()
    {
        using var client = await UploaderAsync();
        var response = await client.PutAsync(
            $"/api/v1/sbom?projectName={Project("oldspec")}&projectVersion=1.0.0&autoCreate=true",
            Document("cyclonedx-1.3-unsupported.json"));

        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        Assert.Contains("1.3", (await BodyAsync(response)).GetProperty("detail").GetString());
    }

    [Fact]
    public async Task SbomUpload_RejectsADocumentOverTheConfiguredCapBeforeWritingAnything()
    {
        using var client = await UploaderAsync();
        // The fixture host caps uploads at 64 KiB; this body declares a Content-Length above it,
        // so the refusal happens before a byte is read.
        var oversize = new ByteArrayContent(Encoding.UTF8.GetBytes(new string('x', 100_000)));
        oversize.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        var response = await client.PutAsync(
            $"/api/v1/sbom?projectName={Project("toolarge")}&projectVersion=1.0.0&autoCreate=true",
            oversize);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Equal(0, await QueryAsync<int>(
            "SELECT COUNT(*) FROM projects WHERE name = @name", new { name = Project("toolarge") }));
    }

    [Fact]
    public async Task SbomUpload_RefusesToTargetACollection()
    {
        string collection = Project("collection");
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using (var conn = await store.OpenAsync())
        {
            string? orgId = await conn.ExecuteScalarAsync<string>(
                "SELECT id FROM orgs WHERE slug = 'default'");
            await conn.ExecuteAsync(
                """
                INSERT INTO projects (id, org_id, kind, name, classifier, created_at)
                VALUES (@id, @orgId, 'collection', @name, 'application', '2026-06-15T12:00:00Z')
                """,
                new { id = Guid.NewGuid().ToString("N"), orgId, name = collection });
        }

        using var client = await UploaderAsync();
        var response = await client.PutAsync(
            $"/api/v1/sbom?projectName={collection}&projectVersion=1.0.0&autoCreate=true",
            Document("cyclonedx-1.6-inventory.json"));

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task SbomUpload_WithoutAutoCreate_IsNotFound()
    {
        using var client = await UploaderAsync();
        var response = await client.PutAsync(
            $"/api/v1/sbom?projectName={Project("absent")}&projectVersion=1.0.0",
            Document("cyclonedx-1.6-inventory.json"));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task SbomUpload_WritesTheActivityRowWithItsOriginAndActor()
    {
        string project = Project("activity");
        using var client = await UploaderAsync();
        await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true",
            Document("cyclonedx-1.4-minimal.json"));

        // Activity is routed through the async writer, so drain the channel before reading.
        await _factory.Services.GetRequiredService<ActivityWriterHostedService>().WaitForIdleAsync();
        var row = await ListAsync<(string EventType, string Ecosystem, string ActorKind, string SourceIp)>(
            """
            SELECT event_type AS EventType, ecosystem AS Ecosystem,
                   actor_kind AS ActorKind, source_ip AS SourceIp
            FROM activity WHERE event_type = 'sbom_uploaded' AND detail LIKE @like
            """,
            new { like = $"%{project}%" });

        var (eventType, ecosystem, actorKind, sourceIp) = Assert.Single(row);
        Assert.Equal("sbom_uploaded", eventType);
        Assert.Equal("sbom", ecosystem);
        Assert.Equal("user", actorKind);
        Assert.False(string.IsNullOrWhiteSpace(sourceIp));

        // Creating a project is a tenant-configuration change, so it also lands in the audit log.
        Assert.Equal(1, await QueryAsync<int>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'project.create' AND detail LIKE @like",
            new { like = $"%{project}%" }));
    }

    // ── VEX ──────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task VexUpload_BindsMatchedStatementsAndKeepsUnmatchedOnesAsTheirOwnRows()
    {
        string project = Project("vex");
        using var client = await UploaderAsync();
        await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true",
            Document("cyclonedx-1.6-inventory.json"));

        var response = await client.PutAsync(
            $"/api/v1/vex?projectName={project}&projectVersion=1.0.0",
            Document("cyclonedx-1.6-vex.json"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var counts = (await BodyAsync(response)).GetProperty("statements");
        // Seven statements, six of which name a component this version's SBOM lists — matched and
        // unmatched in the same upload, which is the shape a real VEX has.
        Assert.Equal(7, counts.GetProperty("total").GetInt32());
        Assert.Equal(6, counts.GetProperty("applied").GetInt32());
        Assert.Equal(1, counts.GetProperty("unmatched").GetInt32());

        string versionId = (await QueryAsync<string>(
            "SELECT id FROM project_versions WHERE version = '1.0.0' AND project_id = (SELECT id FROM projects WHERE name = @name)",
            new { name = project }))!;

        Assert.Equal("exploitable", await QueryAsync<string>(
            "SELECT vex_state FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2021-44906'",
            new { versionId }));
        Assert.Equal("code_not_reachable", await QueryAsync<string>(
            "SELECT vex_justification FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2023-32681'",
            new { versionId }));
        Assert.Equal("upload", await QueryAsync<string>(
            "SELECT vex_source FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2023-32681'",
            new { versionId }));

        // The unmatched statement is kept, keyed on the version-less purl it named.
        Assert.Equal("pkg:npm/event-stream", await QueryAsync<string>(
            "SELECT purl_key FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'GHSA-mh6f-8j2x-4483'",
            new { versionId }));
    }

    [Fact]
    public async Task OpenVexUpload_IsDetectedByContentAndMappedOntoTheCycloneDxVocabulary()
    {
        string project = Project("openvex");
        using var client = await UploaderAsync();
        await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true",
            Document("cyclonedx-1.6-inventory.json"));

        var response = await client.PutAsync(
            $"/api/v1/vex?projectName={project}&projectVersion=1.0.0",
            Document("openvex-1.0.json"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var counts = (await BodyAsync(response)).GetProperty("statements");
        Assert.Equal(5, counts.GetProperty("total").GetInt32());
        Assert.Equal(4, counts.GetProperty("applied").GetInt32());
        Assert.Equal(1, counts.GetProperty("unmatched").GetInt32());

        string versionId = (await QueryAsync<string>(
            "SELECT id FROM project_versions WHERE version = '1.0.0' AND project_id = (SELECT id FROM projects WHERE name = @name)",
            new { name = project }))!;

        Assert.Equal("not_affected", await QueryAsync<string>(
            "SELECT vex_state FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2023-32681'",
            new { versionId }));
        Assert.Equal("code_not_reachable", await QueryAsync<string>(
            "SELECT vex_justification FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2023-32681'",
            new { versionId }));
        Assert.Equal("exploitable", await QueryAsync<string>(
            "SELECT vex_state FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2021-44906'",
            new { versionId }));
        Assert.Equal("resolved", await QueryAsync<string>(
            "SELECT vex_state FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2023-43804'",
            new { versionId }));
        Assert.Equal("in_triage", await QueryAsync<string>(
            "SELECT vex_state FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'GHSA-5crp-9r3c-p9vr'",
            new { versionId }));
        Assert.Equal("openvex-json", await QueryAsync<string>(
            "SELECT format FROM project_documents WHERE project_version_id = @versionId AND doc_type = 'vex'",
            new { versionId }));
    }

    [Fact]
    public async Task VexUpload_ForAnUnknownProjectVersion_IsNotFound()
    {
        using var client = await UploaderAsync();
        var response = await client.PutAsync(
            $"/api/v1/vex?projectName={Project("novex")}&projectVersion=9.9.9",
            Document("cyclonedx-1.6-vex.json"));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    // ── SARIF ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task SarifUpload_FoldsReachabilityAndTheDevProdSignal()
    {
        string project = Project("sarif");
        using var client = await UploaderAsync();
        await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true",
            Document("cyclonedx-1.6-inventory.json"));

        var response = await client.PutAsync(
            $"/api/v1/sarif?projectName={project}&projectVersion=1.0.0",
            Document("sarif-2.1.0-sbom-reach.json"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var counts = (await BodyAsync(response)).GetProperty("results");
        // Six of the seven results name a component the SBOM lists; the seventh names a package
        // that is not in the inventory. Matched and unmatched in one upload.
        Assert.Equal(7, counts.GetProperty("total").GetInt32());
        Assert.Equal(6, counts.GetProperty("applied").GetInt32());
        Assert.Equal(1, counts.GetProperty("unmatched").GetInt32());

        string versionId = (await QueryAsync<string>(
            "SELECT id FROM project_versions WHERE version = '1.0.0' AND project_id = (SELECT id FROM projects WHERE name = @name)",
            new { name = project }))!;

        Assert.Equal("dev", await QueryAsync<string>(
            "SELECT dependency_scope FROM sbom_components WHERE project_version_id = @versionId AND name = 'minimist'",
            new { versionId }));
        Assert.Equal("runtime", await QueryAsync<string>(
            "SELECT dependency_scope FROM sbom_components WHERE project_version_id = @versionId AND name = 'qs'",
            new { versionId }));
        // A component no result named keeps the unclassified default rather than being promoted.
        Assert.Equal("unknown", await QueryAsync<string>(
            "SELECT dependency_scope FROM sbom_components WHERE project_version_id = @versionId AND name = 'lodash'",
            new { versionId }));

        Assert.Equal("reachable", await QueryAsync<string>(
            "SELECT reachability FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2021-44906'",
            new { versionId }));
        Assert.Equal("high", await QueryAsync<string>(
            "SELECT confidence FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2021-44906'",
            new { versionId }));
        Assert.Equal(9.8, await QueryAsync<double>(
            "SELECT security_severity FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2021-44906'",
            new { versionId }));
        Assert.Equal("representative", await QueryAsync<string>(
            "SELECT severity_origin FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2023-43804'",
            new { versionId }));
        Assert.Equal(
            "ee971afd1c4d1b375b5431e77b14e0a23c08da706a5f8284d0dec663d5032668",
            await QueryAsync<string>(
                "SELECT fingerprint FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2021-44906'",
                new { versionId }));

        // A suppressed result is recorded as suppressed, not dropped.
        Assert.Equal(1, await QueryAsync<int>(
            "SELECT sarif_suppressed FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2023-32681'",
            new { versionId }));
        Assert.Equal(0, await QueryAsync<int>(
            "SELECT sarif_suppressed FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2022-24999'",
            new { versionId }));

        // The unmatched result is retained as its own analysis row.
        Assert.Equal(1, await QueryAsync<int>(
            "SELECT COUNT(*) FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'GHSA-mh6f-8j2x-4483'",
            new { versionId }));
    }

    [Fact]
    public async Task SarifUpload_FromAProducerCarryingNoneOfTheReachabilityBags_IsTolerated()
    {
        string project = Project("generic-sarif");
        using var client = await UploaderAsync();
        await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true",
            Document("cyclonedx-1.6-inventory.json"));

        var response = await client.PutAsync(
            $"/api/v1/sarif?projectName={project}&projectVersion=1.0.0",
            Document("sarif-2.1.0-generic.json"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var counts = (await BodyAsync(response)).GetProperty("results");
        Assert.Equal(2, counts.GetProperty("total").GetInt32());
        Assert.Equal(0, counts.GetProperty("applied").GetInt32());
        Assert.Equal(2, counts.GetProperty("unmatched").GetInt32());

        string versionId = (await QueryAsync<string>(
            "SELECT id FROM project_versions WHERE version = '1.0.0' AND project_id = (SELECT id FROM projects WHERE name = @name)",
            new { name = project }))!;

        // Rows exist, carrying no reachability facts — a producer that says nothing records
        // nothing, rather than recording a fabricated default.
        Assert.Equal(2, await QueryAsync<int>(
            "SELECT COUNT(*) FROM project_vuln_analysis WHERE project_version_id = @versionId",
            new { versionId }));
        Assert.Equal(0, await QueryAsync<int>(
            "SELECT COUNT(*) FROM project_vuln_analysis WHERE project_version_id = @versionId AND reachability IS NOT NULL",
            new { versionId }));
        // No component was annotated, so the dev/prod signal stays unclassified everywhere.
        Assert.Equal(0, await QueryAsync<int>(
            "SELECT COUNT(*) FROM sbom_components WHERE project_version_id = @versionId AND dependency_scope != 'unknown'",
            new { versionId }));
    }

    [Fact]
    public async Task SarifUpload_RejectsAVersionOtherThan210()
    {
        string project = Project("sarifversion");
        using var client = await UploaderAsync();
        await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true",
            Document("cyclonedx-1.4-minimal.json"));

        var body = new StringContent(
            """{"version":"2.0.0","runs":[]}""", Encoding.UTF8, "application/json");
        var response = await client.PutAsync(
            $"/api/v1/sarif?projectName={project}&projectVersion=1.0.0", body);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
    }

    // ── Ordering invariant ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task DocumentsUploadedBeforeAnySbom_AreStoredAndReAppliedWhenOneArrives()
    {
        string project = Project("ordering");
        using var client = await UploaderAsync();

        // Seed the version with a document that lists none of the components the VEX and SARIF
        // name, so nothing can bind on the first pass.
        await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true",
            Document("cyclonedx-1.4-minimal.json"));

        var vex = await client.PutAsync(
            $"/api/v1/vex?projectName={project}&projectVersion=1.0.0",
            Document("cyclonedx-1.6-vex.json"));
        Assert.Equal(7, (await BodyAsync(vex)).GetProperty("statements").GetProperty("unmatched").GetInt32());

        var sarif = await client.PutAsync(
            $"/api/v1/sarif?projectName={project}&projectVersion=1.0.0",
            Document("sarif-2.1.0-sbom-reach.json"));
        Assert.Equal(7, (await BodyAsync(sarif)).GetProperty("results").GetProperty("unmatched").GetInt32());

        string versionId = (await QueryAsync<string>(
            "SELECT id FROM project_versions WHERE version = '1.0.0' AND project_id = (SELECT id FROM projects WHERE name = @name)",
            new { name = project }))!;
        Assert.Equal(0, await QueryAsync<int>(
            "SELECT COUNT(*) FROM sbom_components WHERE project_version_id = @versionId AND dependency_scope = 'dev'",
            new { versionId }));

        // The inventory that actually contains those components arrives last. The stored VEX and
        // SARIF are re-applied against it, so the facts bind without either being re-uploaded.
        var full = await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true",
            Document("cyclonedx-1.6-inventory.json"));
        Assert.Equal(HttpStatusCode.OK, full.StatusCode);

        Assert.Equal("dev", await QueryAsync<string>(
            "SELECT dependency_scope FROM sbom_components WHERE project_version_id = @versionId AND name = 'minimist'",
            new { versionId }));
        Assert.Equal("exploitable", await QueryAsync<string>(
            "SELECT vex_state FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2021-44906'",
            new { versionId }));
        Assert.Equal("reachable", await QueryAsync<string>(
            "SELECT reachability FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2021-44906'",
            new { versionId }));
    }

    [Fact]
    public async Task ReuploadingAnSbom_LeavesTriageAndReachabilityIntact()
    {
        string project = Project("preserve");
        using var client = await UploaderAsync();
        string route = $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true";

        await client.PutAsync(route, Document("cyclonedx-1.6-inventory.json"));
        await client.PutAsync(
            $"/api/v1/vex?projectName={project}&projectVersion=1.0.0",
            Document("cyclonedx-1.6-vex.json"));
        await client.PutAsync(
            $"/api/v1/sarif?projectName={project}&projectVersion=1.0.0",
            Document("sarif-2.1.0-sbom-reach.json"));

        string versionId = (await QueryAsync<string>(
            "SELECT id FROM project_versions WHERE version = '1.0.0' AND project_id = (SELECT id FROM projects WHERE name = @name)",
            new { name = project }))!;
        int analysisRows = await QueryAsync<int>(
            "SELECT COUNT(*) FROM project_vuln_analysis WHERE project_version_id = @versionId",
            new { versionId });

        // A different SBOM document for the same version — the same inventory plus embedded
        // statements, so the digest differs and the merge really runs.
        await client.PutAsync(route, Document("cyclonedx-1.6-vdr.json"));

        Assert.Equal(analysisRows, await QueryAsync<int>(
            "SELECT COUNT(*) FROM project_vuln_analysis WHERE project_version_id = @versionId",
            new { versionId }));
        Assert.Equal("reachable", await QueryAsync<string>(
            "SELECT reachability FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2021-44906'",
            new { versionId }));
        Assert.Equal("dev", await QueryAsync<string>(
            "SELECT dependency_scope FROM sbom_components WHERE project_version_id = @versionId AND name = 'minimist'",
            new { versionId }));
        Assert.Equal("not_affected", await QueryAsync<string>(
            "SELECT vex_state FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2023-32681'",
            new { versionId }));
    }

    // ── Authorization ────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Upload_WithoutTheUploadCapability_IsForbidden()
    {
        string raw = await _factory.CreateAdminUserToken("""["read:packages"]""");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", raw);

        var response = await client.PutAsync(
            $"/api/v1/sbom?projectName={Project("nocap")}&projectVersion=1.0.0&autoCreate=true",
            Document("cyclonedx-1.4-minimal.json"));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Upload_WithAServiceTokenCarryingTheUploadCapability_IsAccepted()
    {
        string project = Project("service");
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        var org = await orgs.GetBySlugAsync("default");
        var (raw, _) = await tokens.CreateServiceTokenAsync(
            org!.Id, "ci-sbom", """["sbom:upload"]""", expiresAt: null);

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", raw);
        var response = await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true",
            Document("cyclonedx-1.4-minimal.json"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // A service token has no user row, so the audit discriminator must say so and carry the
        // token's own name — the join it would otherwise need is gone the moment it is revoked.
        await _factory.Services.GetRequiredService<ActivityWriterHostedService>().WaitForIdleAsync();
        var rows = await ListAsync<(string ActorKind, string ActorLabel)>(
            """
            SELECT actor_kind AS ActorKind, actor_label AS ActorLabel FROM activity
            WHERE event_type = 'sbom_uploaded' AND detail LIKE @like
            """,
            new { like = $"%{project}%" });
        var (actorKind, actorLabel) = Assert.Single(rows);
        Assert.Equal("service", actorKind);
        Assert.Equal("ci-sbom", actorLabel);
    }

    [Fact]
    public async Task Upload_WithNoQueryTarget_IsAValidationError()
    {
        using var client = await UploaderAsync();
        var response = await client.PutAsync(
            "/api/v1/sbom?projectVersion=1.0.0&autoCreate=true",
            Document("cyclonedx-1.4-minimal.json"));

        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        Assert.Equal("projectName", (await BodyAsync(response)).GetProperty("field").GetString());
    }
}
