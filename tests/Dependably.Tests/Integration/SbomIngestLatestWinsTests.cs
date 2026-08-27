using System.Data.Common;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Dependably.Tests.Integration;

/// <summary>
/// The two claims an upload makes that the happy path cannot check.
///
/// <para><b>The dedup no-op certifies an applied document, not a received one.</b> A byte-identical
/// re-upload answers 200 with <c>added: 0</c>. That is only true if the stored document row is
/// written after the merge succeeds — otherwise a merge that throws after the row commits leaves
/// the row naming a document whose inventory was never written, and every retry of the same bytes
/// short-circuits to that false success, permanently.</para>
///
/// <para><b>Latest-wins means a withdrawn statement is withdrawn.</b> Documents replace rather than
/// accumulate, and the normal way a VEX producer retracts an assertion is to republish without it.
/// A pure upsert never notices the omission, so a <c>not_affected</c> the producer has withdrawn
/// keeps suppressing its finding — a security-gate input removed while the gate goes on honouring
/// it. Manual triage is exempt: an operator's decision is not something an uploaded document may
/// withdraw.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class SbomIngestLatestWinsTests : IAsyncLifetime
{
    private ToggleFailingMetadataStore? _mergeStore;

    private readonly DependablyFactory _factory;

    public SbomIngestLatestWinsTests()
    {
        _factory = new DependablyFactory
        {
            FrozenClock = TestTime.Frozen(),
            ServiceOverrides = services =>
            {
                // Only the merge service is rewired, so the document store, the dedup read and
                // the project resolution all keep talking to the real database — the failure is
                // isolated to the apply step, which is exactly the window the ordering protects.
                services.RemoveAll<SbomMergeService>();
                services.AddSingleton(sp =>
                {
                    _mergeStore = new ToggleFailingMetadataStore(sp.GetRequiredService<IMetadataStore>());
                    return new SbomMergeService(new SbomIngestRepository(_mergeStore));
                });
            },
        };
    }

    public async Task InitializeAsync() => await _factory.InitializeAsync();

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    // ── harness ───────────────────────────────────────────────────────────────

    private static string Fixture(string name) =>
        Path.Combine(FixtureManifest.SbomFixturesRoot, name);

    private async Task<HttpClient> UploaderAsync()
    {
        string jwt = await _factory.CreateAdminJwt();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    private static HttpContent FileBody(string fixtureName)
    {
        var content = new ByteArrayContent(File.ReadAllBytes(Fixture(fixtureName)));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return content;
    }

    private static HttpContent JsonBody(string json)
    {
        var content = new StringContent(json, Encoding.UTF8);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return content;
    }

    private async Task<T?> ScalarAsync<T>(string sql, object? parameters = null)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<T>(sql, parameters);
    }

    private async Task ExecuteAsync(string sql, object? parameters = null)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(sql, parameters);
    }

    private async Task<string> VersionIdAsync(string project)
    {
        return (await ScalarAsync<string>(
            """
            SELECT v.id FROM project_versions v
            JOIN projects p ON p.id = v.project_id
            WHERE p.name = @project
            """,
            new { project }))!;
    }

    private static async Task<JsonElement> BodyAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

    // ── F3: the dedup arm must not certify a merge that never completed ────────

    [Fact]
    public async Task SbomUpload_WhoseMergeFails_LeavesNoDocumentRowAndTheRetryReapplies()
    {
        const string project = "latestwins-failed-merge";
        using var client = await UploaderAsync();

        var first = await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true",
            FileBody("cyclonedx-1.6-inventory.json"));
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        string versionId = await VersionIdAsync(project);
        string? firstSha = await ScalarAsync<string>(
            "SELECT sha256 FROM project_documents WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId });
        Assert.NotNull(firstSha);
        Assert.Equal(13, await ScalarAsync<long>(
            "SELECT COUNT(*) FROM sbom_components WHERE project_version_id = @versionId", new { versionId }));

        // The second document's merge throws after its bytes have been staged.
        Assert.NotNull(_mergeStore);
        _mergeStore!.Fail = true;
        await AssertUploadFailedAsync(client, project, "cyclonedx-1.5-minimal.json");

        // The stored document still names the first upload, so the second is not on record as
        // applied — the inventory and the digest agree with each other.
        Assert.Equal(firstSha, await ScalarAsync<string>(
            "SELECT sha256 FROM project_documents WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId }));
        Assert.Equal(13, await ScalarAsync<long>(
            "SELECT COUNT(*) FROM sbom_components WHERE project_version_id = @versionId", new { versionId }));

        // The retry of the identical bytes must do the work, not answer with the idempotent no-op.
        _mergeStore.Fail = false;
        var retry = await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0",
            FileBody("cyclonedx-1.5-minimal.json"));
        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
        var body = await BodyAsync(retry);
        Assert.True(body.GetProperty("components").GetProperty("added").GetInt32() > 0);
        Assert.NotEqual(firstSha, await ScalarAsync<string>(
            "SELECT sha256 FROM project_documents WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId }));
    }

    private static async Task AssertUploadFailedAsync(HttpClient client, string project, string fixture)
    {
        try
        {
            var response = await client.PutAsync(
                $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0",
                FileBody(fixture));
            Assert.True((int)response.StatusCode >= 500, $"expected a server error, got {(int)response.StatusCode}");
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("simulated", StringComparison.Ordinal))
        {
            // TestServer rethrows rather than mapping to a 500 depending on the pipeline;
            // either shape means the same thing here — the request did not succeed.
        }
    }

    // ── F4: retraction by omission ────────────────────────────────────────────

    private const string VexBoth = """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "vulnerabilities": [
            { "id": "CVE-2100-2001", "affects": [ { "ref": "pkg:npm/minimist@1.2.5" } ],
              "analysis": { "state": "not_affected", "justification": "code_not_reachable" } },
            { "id": "CVE-2100-2002", "affects": [ { "ref": "pkg:npm/qs@6.10.2" } ],
              "analysis": { "state": "not_affected", "justification": "code_not_present" } }
          ]
        }
        """;

    private const string VexSecondWithdrawn = """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "vulnerabilities": [
            { "id": "CVE-2100-2001", "affects": [ { "ref": "pkg:npm/minimist@1.2.5" } ],
              "analysis": { "state": "not_affected", "justification": "code_not_reachable" } }
          ]
        }
        """;

    [Fact]
    public async Task VexReupload_WithoutAStatement_RetractsItAndKeepsTheOnesItRepeats()
    {
        const string project = "latestwins-vex-retract";
        using var client = await UploaderAsync();
        await SeedInventoryAsync(client, project);
        string versionId = await VersionIdAsync(project);

        Assert.Equal(HttpStatusCode.OK, (await client.PutAsync(
            $"/api/v1/vex?projectName={project}&projectVersion=1.0.0", JsonBody(VexBoth))).StatusCode);
        Assert.Equal("not_affected", await VexStateAsync(versionId, "CVE-2100-2001"));
        Assert.Equal("not_affected", await VexStateAsync(versionId, "CVE-2100-2002"));

        Assert.Equal(HttpStatusCode.OK, (await client.PutAsync(
            $"/api/v1/vex?projectName={project}&projectVersion=1.0.0", JsonBody(VexSecondWithdrawn))).StatusCode);

        Assert.Equal("not_affected", await VexStateAsync(versionId, "CVE-2100-2001"));
        Assert.Null(await VexStateAsync(versionId, "CVE-2100-2002"));
    }

    [Fact]
    public async Task VexReupload_NeverRetractsAManuallyTriagedRow()
    {
        // The adversarial twin: retraction must reach exactly the upload-sourced rows. An
        // operator's decision outranks a document, on the retract side as on the write side.
        const string project = "latestwins-vex-manual";
        using var client = await UploaderAsync();
        await SeedInventoryAsync(client, project);
        string versionId = await VersionIdAsync(project);

        Assert.Equal(HttpStatusCode.OK, (await client.PutAsync(
            $"/api/v1/vex?projectName={project}&projectVersion=1.0.0", JsonBody(VexBoth))).StatusCode);

        // Promote the statement the next document withdraws into a manual decision.
        await ExecuteAsync(
            """
            UPDATE project_vuln_analysis SET vex_source = 'manual', vex_state = 'false_positive'
            WHERE project_version_id = @versionId AND vuln_key = 'CVE-2100-2002'
            """,
            new { versionId });

        Assert.Equal(HttpStatusCode.OK, (await client.PutAsync(
            $"/api/v1/vex?projectName={project}&projectVersion=1.0.0", JsonBody(VexSecondWithdrawn))).StatusCode);

        Assert.Equal("false_positive", await VexStateAsync(versionId, "CVE-2100-2002"));
        Assert.Equal("manual", await ScalarAsync<string>(
            "SELECT vex_source FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = 'CVE-2100-2002'",
            new { versionId }));
    }

    private const string SarifBoth = """
        {
          "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
          "version": "2.1.0",
          "runs": [
            {
              "tool": { "driver": { "name": "sbom-reach", "version": "0.4.0", "rules": [] } },
              "results": [
                {
                  "ruleId": "CVE-2100-3001",
                  "level": "error",
                  "message": { "text": "minimist@1.2.5 is vulnerable to CVE-2100-3001" },
                  "properties": {
                    "purl": "pkg:npm/minimist@1.2.5",
                    "reachability": "reachable",
                    "confidence": "high",
                    "dependencyScope": "dev"
                  }
                },
                {
                  "ruleId": "CVE-2100-3002",
                  "level": "error",
                  "message": { "text": "qs@6.10.2 is vulnerable to CVE-2100-3002" },
                  "properties": {
                    "purl": "pkg:npm/qs@6.10.2",
                    "reachability": "reachable",
                    "confidence": "high",
                    "dependencyScope": "dev"
                  }
                }
              ]
            }
          ]
        }
        """;

    private const string SarifSecondWithdrawn = """
        {
          "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
          "version": "2.1.0",
          "runs": [
            {
              "tool": { "driver": { "name": "sbom-reach", "version": "0.4.0", "rules": [] } },
              "results": [
                {
                  "ruleId": "CVE-2100-3001",
                  "level": "error",
                  "message": { "text": "minimist@1.2.5 is vulnerable to CVE-2100-3001" },
                  "properties": {
                    "purl": "pkg:npm/minimist@1.2.5",
                    "reachability": "reachable",
                    "confidence": "high",
                    "dependencyScope": "dev"
                  }
                }
              ]
            }
          ]
        }
        """;

    [Fact]
    public async Task SarifReupload_WithoutAResult_RetractsReachabilityAndTheComponentScope()
    {
        const string project = "latestwins-sarif-retract";
        using var client = await UploaderAsync();
        await SeedInventoryAsync(client, project);
        string versionId = await VersionIdAsync(project);

        Assert.Equal(HttpStatusCode.OK, (await client.PutAsync(
            $"/api/v1/sarif?projectName={project}&projectVersion=1.0.0", JsonBody(SarifBoth))).StatusCode);
        Assert.Equal("reachable", await ReachabilityAsync(versionId, "CVE-2100-3001"));
        Assert.Equal("reachable", await ReachabilityAsync(versionId, "CVE-2100-3002"));
        Assert.Equal("dev", await ScopeAsync(versionId, "pkg:npm/qs@6.10.2"));

        Assert.Equal(HttpStatusCode.OK, (await client.PutAsync(
            $"/api/v1/sarif?projectName={project}&projectVersion=1.0.0", JsonBody(SarifSecondWithdrawn))).StatusCode);

        Assert.Equal("reachable", await ReachabilityAsync(versionId, "CVE-2100-3001"));
        Assert.Null(await ReachabilityAsync(versionId, "CVE-2100-3002"));
        Assert.Equal("dev", await ScopeAsync(versionId, "pkg:npm/minimist@1.2.5"));
        // The scanner no longer says anything about qs, so it has no scanner verdict — 'unknown',
        // which reads as production and stays visible, not a stale 'dev' that hides it.
        Assert.Equal("unknown", await ScopeAsync(versionId, "pkg:npm/qs@6.10.2"));
    }

    private static async Task SeedInventoryAsync(HttpClient client, string project)
    {
        var response = await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true",
            FileBody("cyclonedx-1.6-inventory.json"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private Task<string?> VexStateAsync(string versionId, string vulnKey) =>
        ScalarAsync<string>(
            "SELECT vex_state FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = @vulnKey",
            new { versionId, vulnKey });

    private Task<string?> ReachabilityAsync(string versionId, string vulnKey) =>
        ScalarAsync<string>(
            "SELECT reachability FROM project_vuln_analysis WHERE project_version_id = @versionId AND vuln_key = @vulnKey",
            new { versionId, vulnKey });

    private Task<string?> ScopeAsync(string versionId, string purl) =>
        ScalarAsync<string>(
            "SELECT dependency_scope FROM sbom_components WHERE project_version_id = @versionId AND purl = @purl",
            new { versionId, purl });

    /// <summary>
    /// Wraps the real store and refuses to open a connection while <see cref="Fail"/> is set, so
    /// a test can fail one collaborator for one request and let every other one keep working.
    /// </summary>
    private sealed class ToggleFailingMetadataStore : IMetadataStore
    {
        private readonly IMetadataStore _inner;

        public ToggleFailingMetadataStore(IMetadataStore inner) => _inner = inner;

        public bool Fail { get; set; }

        public DbProvider Provider => _inner.Provider;

        public Task<DbConnection> OpenAsync(CancellationToken ct = default) =>
            Fail
                ? throw new InvalidOperationException("simulated transient metadata-store failure")
                : _inner.OpenAsync(ct);
    }
}
