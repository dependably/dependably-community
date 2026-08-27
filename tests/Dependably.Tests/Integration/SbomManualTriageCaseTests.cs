using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// The whole triage path against a real host: an uploaded VEX records an advisory, then a manual
/// decision cites the same advisory in a different case.
///
/// <para>An API client composes the advisory id itself, and no ecosystem agrees on one casing —
/// a CVE id is conventionally uppercase, a GHSA id's suffix lowercase. The stored spelling is
/// whatever the document that recorded it used, and every reader matches it case-insensitively,
/// so a triage that lands its own second row leaves one advisory on one component carrying two
/// analysis rows with contradictory states, both of which the analysis view, the policy resolve
/// and the VDR export consider a match.</para>
///
/// <para>The reverse order is the security case: a decision recorded by hand, then an uploaded
/// document citing the same advisory in another case. "Manual triage outranks an uploaded
/// statement" is enforced as the conflict update's WHERE clause, so a statement that conflicts
/// with nothing is never refused by it — the upload lands its own row and the operator's decision
/// stops being honoured. These drive the whole endpoint, so the per-request retraction sweep runs
/// too, which is the other half of the same behaviour.</para>
///
/// <para>The assertions read the database rather than the response body for the row count: a
/// response describing the row the endpoint just wrote is right either way, and the duplicate is
/// only visible in the table.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class SbomManualTriageCaseTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new() { FrozenClock = TestTime.Frozen() };

    public async Task InitializeAsync() => await _factory.InitializeAsync();

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    private static HttpContent Document(string fixtureName)
    {
        var content = new ByteArrayContent(
            File.ReadAllBytes(Path.Combine(FixtureManifest.SbomFixturesRoot, fixtureName)));
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return content;
    }

    private async Task<HttpClient> UploaderAsync()
    {
        string jwt = await _factory.CreateAdminJwt();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    private static HttpContent Inline(string json)
    {
        var content = new StringContent(json, Encoding.UTF8);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return content;
    }

    private static string VexJson(string advisoryId, string state) => $$"""
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "vulnerabilities": [
            {
              "id": "{{advisoryId}}",
              "affects": [ { "ref": "pkg:pypi/requests@2.28.1" } ],
              "analysis": { "state": "{{state}}" }
            }
          ]
        }
        """;

    private static string SarifJson(string advisoryId, string reachability) => $$"""
        {
          "version": "2.1.0",
          "runs": [
            {
              "tool": { "driver": { "name": "sbom-reach", "semanticVersion": "0.2.0" } },
              "results": [
                {
                  "ruleId": "{{advisoryId}}",
                  "level": "error",
                  "message": { "text": "requests@2.28.1 is vulnerable to {{advisoryId}}." },
                  "properties": {
                    "purl": "pkg:pypi/requests@2.28.1",
                    "reachability": "{{reachability}}",
                    "confidence": "high"
                  }
                }
              ]
            }
          ]
        }
        """;

    private sealed record Target(string ProjectId, string VersionId);

    private static async Task<Target> UploadSbomAndVexAsync(HttpClient client, string project)
    {
        var sbom = await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true",
            Document("cyclonedx-1.6-inventory.json"));
        Assert.Equal(HttpStatusCode.OK, sbom.StatusCode);

        var vex = await client.PutAsync(
            $"/api/v1/vex?projectName={project}&projectVersion=1.0.0",
            Document("cyclonedx-1.6-vex.json"));
        Assert.Equal(HttpStatusCode.OK, vex.StatusCode);

        var body = JsonDocument.Parse(await sbom.Content.ReadAsStringAsync()).RootElement;
        return new Target(
            body.GetProperty("project").GetProperty("id").GetString()!,
            body.GetProperty("projectVersion").GetProperty("id").GetString()!);
    }

    private static async Task<Target> UploadSbomAsync(HttpClient client, string project)
    {
        var sbom = await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true",
            Document("cyclonedx-1.6-inventory.json"));
        Assert.Equal(HttpStatusCode.OK, sbom.StatusCode);

        var body = JsonDocument.Parse(await sbom.Content.ReadAsStringAsync()).RootElement;
        return new Target(
            body.GetProperty("project").GetProperty("id").GetString()!,
            body.GetProperty("projectVersion").GetProperty("id").GetString()!);
    }

    private async Task<string?> StateAsync(Target target, string purlKey, string vulnKey)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT vex_state
            FROM project_vuln_analysis
            WHERE project_version_id = @versionId AND purl_key = @purlKey AND vuln_key = @vulnKey
            """,
            new { versionId = target.VersionId, purlKey, vulnKey });
    }

    private async Task<string?> UpdatedByAsync(Target target, string purlKey, string vulnKey)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT updated_by
            FROM project_vuln_analysis
            WHERE project_version_id = @versionId AND purl_key = @purlKey AND vuln_key = @vulnKey
            """,
            new { versionId = target.VersionId, purlKey, vulnKey });
    }

    private async Task<string?> ReachabilityAsync(Target target, string purlKey, string vulnKey)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT reachability
            FROM project_vuln_analysis
            WHERE project_version_id = @versionId AND purl_key = @purlKey AND vuln_key = @vulnKey
            """,
            new { versionId = target.VersionId, purlKey, vulnKey });
    }

    private static Task<HttpResponseMessage> TriageAsync(
        HttpClient client, Target target, string purlKey, string vulnKey, string vexState) =>
        client.PutAsJsonAsync(
            $"/api/v1/projects/{target.ProjectId}/versions/{target.VersionId}/analysis",
            new { purlKey, vulnKey, vexState });

    private async Task<IReadOnlyList<string>> StoredKeysAsync(Target target, string purlKey)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        var rows = await conn.QueryAsync<string>(
            """
            SELECT vuln_key
            FROM project_vuln_analysis
            WHERE project_version_id = @versionId AND purl_key = @purlKey
            ORDER BY vuln_key
            """,
            new { versionId = target.VersionId, purlKey });
        return rows.ToList();
    }

    private async Task<string?> SourceAsync(Target target, string purlKey, string vulnKey)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            """
            SELECT vex_source
            FROM project_vuln_analysis
            WHERE project_version_id = @versionId AND purl_key = @purlKey AND vuln_key = @vulnKey
            """,
            new { versionId = target.VersionId, purlKey, vulnKey });
    }

    [Fact]
    public async Task Triage_CitingAnUploadedAdvisoryInLowercase_UpdatesTheUploadedRow()
    {
        using var client = await UploaderAsync();
        var target = await UploadSbomAndVexAsync(client, "proj-triage-case");

        // Control: the VEX upload recorded the advisory under its own uppercase spelling.
        Assert.Equal("upload", await SourceAsync(target, "pkg:pypi/requests", "CVE-2023-32681"));

        var response = await TriageAsync(
            client, target, "pkg:pypi/requests", "cve-2023-32681", "exploitable");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("CVE-2023-32681", body.GetProperty("vulnKey").GetString());
        Assert.Equal("exploitable", body.GetProperty("vexState").GetString());
        Assert.Equal("manual", body.GetProperty("vexSource").GetString());

        string surviving = Assert.Single(await StoredKeysAsync(target, "pkg:pypi/requests"));
        Assert.Equal("CVE-2023-32681", surviving);
        Assert.Equal("manual", await SourceAsync(target, "pkg:pypi/requests", "CVE-2023-32681"));
    }

    [Fact]
    public async Task Triage_CitingADifferentAdvisory_AddsItsOwnRow()
    {
        // Adversarial twin: folding case must not fold two genuinely different advisories onto
        // one row — a triage of an advisory no document covers is still a new statement.
        using var client = await UploaderAsync();
        var target = await UploadSbomAndVexAsync(client, "proj-triage-distinct");

        var response = await TriageAsync(
            client, target, "pkg:pypi/requests", "CVE-2024-11111", "exploitable");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var keys = await StoredKeysAsync(target, "pkg:pypi/requests");
        Assert.Equal(["CVE-2023-32681", "CVE-2024-11111"], keys);
        Assert.Equal("upload", await SourceAsync(target, "pkg:pypi/requests", "CVE-2023-32681"));
        Assert.Equal("manual", await SourceAsync(target, "pkg:pypi/requests", "CVE-2024-11111"));
    }

    [Fact]
    public async Task Triage_CitingAGhsaIdInUppercase_KeepsTheStoredLowercaseSuffix()
    {
        using var client = await UploaderAsync();
        var target = await UploadSbomAndVexAsync(client, "proj-triage-ghsa");

        var response = await TriageAsync(
            client, target, "pkg:npm/event-stream", "GHSA-MH6F-8J2X-4483", "exploitable");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("GHSA-mh6f-8j2x-4483", body.GetProperty("vulnKey").GetString());

        string surviving = Assert.Single(await StoredKeysAsync(target, "pkg:npm/event-stream"));
        Assert.Equal("GHSA-mh6f-8j2x-4483", surviving);
        Assert.Equal("manual", await SourceAsync(target, "pkg:npm/event-stream", "GHSA-mh6f-8j2x-4483"));
    }

    [Fact]
    public async Task VexUpload_CitingAManualDecisionInAnotherCase_DoesNotOverrideIt()
    {
        // The security assertion: an uploaded statement must not defeat the manual guard by
        // citing the advisory in a case the stored row does not use.
        using var client = await UploaderAsync();
        var target = await UploadSbomAsync(client, "proj-guard-case");

        var triage = await TriageAsync(
            client, target, "pkg:pypi/requests", "cve-2023-32681", "not_affected");
        Assert.Equal(HttpStatusCode.OK, triage.StatusCode);

        var upload = await client.PutAsync(
            "/api/v1/vex?projectName=proj-guard-case&projectVersion=1.0.0",
            Inline(VexJson("CVE-2023-32681", "exploitable")));

        Assert.Equal(HttpStatusCode.OK, upload.StatusCode);
        string surviving = Assert.Single(await StoredKeysAsync(target, "pkg:pypi/requests"));
        Assert.Equal("cve-2023-32681", surviving);
        Assert.Equal("manual", await SourceAsync(target, "pkg:pypi/requests", "cve-2023-32681"));
        Assert.Equal("not_affected", await StateAsync(target, "pkg:pypi/requests", "cve-2023-32681"));
    }

    [Fact]
    public async Task SarifUpload_CitingAManualDecisionInAnotherCase_AnnotatesItAndLeavesTheVexArm()
    {
        using var client = await UploaderAsync();
        var target = await UploadSbomAsync(client, "proj-guard-sarif");

        await TriageAsync(client, target, "pkg:pypi/requests", "cve-2023-32681", "not_affected");

        var upload = await client.PutAsync(
            "/api/v1/sarif?projectName=proj-guard-sarif&projectVersion=1.0.0",
            Inline(SarifJson("CVE-2023-32681", "reachable")));

        Assert.Equal(HttpStatusCode.OK, upload.StatusCode);
        string surviving = Assert.Single(await StoredKeysAsync(target, "pkg:pypi/requests"));
        Assert.Equal("cve-2023-32681", surviving);
        Assert.Equal("manual", await SourceAsync(target, "pkg:pypi/requests", "cve-2023-32681"));
        Assert.Equal("not_affected", await StateAsync(target, "pkg:pypi/requests", "cve-2023-32681"));
        Assert.Equal("reachable", await ReachabilityAsync(target, "pkg:pypi/requests", "cve-2023-32681"));
    }

    [Fact]
    public async Task VexUpload_CitingAnUploadedRowInAnotherCase_UpdatesItAndSurvivesTheSweep()
    {
        // The per-request retraction sweep runs inside this endpoint, so an upload-sourced row the
        // writer resolved onto must still be recognised as asserted by the document that wrote it.
        using var client = await UploaderAsync();
        var target = await UploadSbomAsync(client, "proj-sweep-case");

        Assert.Equal(HttpStatusCode.OK, (await client.PutAsync(
            "/api/v1/vex?projectName=proj-sweep-case&projectVersion=1.0.0",
            Inline(VexJson("CVE-2023-32681", "not_affected")))).StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await client.PutAsync(
            "/api/v1/vex?projectName=proj-sweep-case&projectVersion=1.0.0",
            Inline(VexJson("cve-2023-32681", "exploitable")))).StatusCode);

        string surviving = Assert.Single(await StoredKeysAsync(target, "pkg:pypi/requests"));
        Assert.Equal("CVE-2023-32681", surviving);
        Assert.Equal("upload", await SourceAsync(target, "pkg:pypi/requests", "CVE-2023-32681"));
        Assert.Equal("exploitable", await StateAsync(target, "pkg:pypi/requests", "CVE-2023-32681"));
    }

    [Fact]
    public async Task VexUpload_CitingADifferentAdvisoryThanTheManualDecision_LeavesTheDecisionAlone()
    {
        // Adversarial twin for the guard: it refuses a conflicting statement, it does not refuse
        // every statement, and it does not fold two advisories onto one row.
        using var client = await UploaderAsync();
        var target = await UploadSbomAsync(client, "proj-guard-distinct");

        await TriageAsync(client, target, "pkg:pypi/requests", "cve-2023-32681", "not_affected");

        Assert.Equal(HttpStatusCode.OK, (await client.PutAsync(
            "/api/v1/vex?projectName=proj-guard-distinct&projectVersion=1.0.0",
            Inline(VexJson("CVE-2024-11111", "exploitable")))).StatusCode);

        var keys = await StoredKeysAsync(target, "pkg:pypi/requests");
        Assert.Equal(["CVE-2024-11111", "cve-2023-32681"], keys);
        Assert.Equal("manual", await SourceAsync(target, "pkg:pypi/requests", "cve-2023-32681"));
        Assert.Equal("not_affected", await StateAsync(target, "pkg:pypi/requests", "cve-2023-32681"));
        Assert.Equal("upload", await SourceAsync(target, "pkg:pypi/requests", "CVE-2024-11111"));
    }

    [Fact]
    public async Task SarifUpload_ByAnotherActor_DoesNotClaimAuthorshipOfAManualDecision()
    {
        // Two distinct actors, because a single-actor test would read green against a writer that
        // restamps: the triage editor's "set by" line has to keep naming the operator who made the
        // call, not the uploader of a log that merely observed reachability.
        using var operatorClient = await UploaderAsync();
        var target = await UploadSbomAsync(operatorClient, "proj-provenance");
        await TriageAsync(operatorClient, target, "pkg:pypi/requests", "cve-2023-32681", "not_affected");

        string? decidedBy = await UpdatedByAsync(target, "pkg:pypi/requests", "cve-2023-32681");
        Assert.NotNull(decidedBy);

        string scannerId = await _factory.CreateUser("scanner@example.test", "Sc4nner-pass!", "admin");
        Assert.NotEqual(decidedBy, scannerId);
        using var scannerClient = _factory.CreateClient();
        scannerClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer", await _factory.CreateUserJwt(scannerId, "admin"));

        var upload = await scannerClient.PutAsync(
            "/api/v1/sarif?projectName=proj-provenance&projectVersion=1.0.0",
            Inline(SarifJson("CVE-2023-32681", "reachable")));

        Assert.Equal(HttpStatusCode.OK, upload.StatusCode);
        string surviving = Assert.Single(await StoredKeysAsync(target, "pkg:pypi/requests"));
        Assert.Equal("cve-2023-32681", surviving);
        Assert.Equal("reachable", await ReachabilityAsync(target, "pkg:pypi/requests", "cve-2023-32681"));
        Assert.Equal("not_affected", await StateAsync(target, "pkg:pypi/requests", "cve-2023-32681"));
        Assert.Equal("manual", await SourceAsync(target, "pkg:pypi/requests", "cve-2023-32681"));
        Assert.Equal(decidedBy, await UpdatedByAsync(target, "pkg:pypi/requests", "cve-2023-32681"));
    }
}
