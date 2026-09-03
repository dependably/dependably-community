using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Dependably.Tests.Integration;

/// <summary>
/// <c>sbom_components.dependency_scope_source</c>: the provenance tag that lets
/// <c>ResetUnnamedDependencyScopeAsync</c> tell a manifest-declaration fill apart from a
/// reachability scanner's own verdict.
///
/// <para>Before this column existed, <c>dependency_scope &lt;&gt; 'unknown'</c> implied
/// "a SARIF named this component", because SARIF was the only writer. Once CycloneDX ingest
/// gained a second writer (the manifest dev-declaration fill), that implication broke: the SARIF
/// retraction sweep kept resetting anything the *current* scan didn't name, wiping a manifest
/// fill on the very next SARIF upload — even a clean, zero-result one, the common case for a
/// component with no findings, which is exactly the population the fill exists for. These tests
/// pin the fix: the sweep now only ever resets a 'scanner'-sourced row.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class DependencyScopeProvenanceTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new() { FrozenClock = TestTime.Frozen() };

    public async Task InitializeAsync() => await _factory.InitializeAsync();

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    private async Task<HttpClient> UploaderAsync()
    {
        string jwt = await _factory.CreateAdminJwt();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    private static HttpContent SbomWithDevDeclaration(string purl = "pkg:npm/left-pad@1.0.0") => Json($$"""
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "metadata": { "component": { "type": "application", "name": "app", "version": "1.0.0" } },
          "components": [
            {
              "type": "library",
              "name": "left-pad",
              "version": "1.0.0",
              "purl": "{{purl}}",
              "properties": [ { "name": "cdx:npm:package:development", "value": "true" } ]
            }
          ]
        }
        """);

    private static HttpContent ZeroResultSarif() => Json("""
        {
          "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
          "version": "2.1.0",
          "runs": [ { "tool": { "driver": { "name": "sbom-reach", "rules": [] } }, "results": [] } ]
        }
        """);

    private static HttpContent SarifNaming(string purl, string ruleId, string reachability) => Json($$"""
        {
          "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
          "version": "2.1.0",
          "runs": [
            {
              "tool": { "driver": { "name": "sbom-reach", "rules": [ { "id": "{{ruleId}}" } ] } },
              "results": [
                {
                  "ruleId": "{{ruleId}}",
                  "message": { "text": "finding" },
                  "properties": {
                    "purl": "{{purl}}",
                    "reachability": "{{reachability}}",
                    "dependencyScope": "runtime"
                  }
                }
              ]
            }
          ]
        }
        """);

    private static HttpContent Json(string json)
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

    private const string ScopeSql =
        "SELECT dependency_scope FROM sbom_components WHERE project_version_id = @versionId AND purl = @purl";
    private const string SourceSql =
        "SELECT dependency_scope_source FROM sbom_components WHERE project_version_id = @versionId AND purl = @purl";

    [Fact]
    public async Task ManifestFill_SurvivesAZeroResultSarifUploadForTheSameVersion()
    {
        using var client = await UploaderAsync();
        const string purl = "pkg:npm/left-pad@1.0.0";

        var sbomResp = await client.PutAsync(
            "/api/v1/sbom?projectName=proj-provenance-a&projectVersion=1.0.0&autoCreate=true",
            SbomWithDevDeclaration(purl));
        Assert.Equal(HttpStatusCode.OK, sbomResp.StatusCode);
        var body = JsonDocument.Parse(await sbomResp.Content.ReadAsStringAsync()).RootElement;
        string versionId = body.GetProperty("projectVersion").GetProperty("id").GetString()!;

        Assert.Equal("dev", await ScalarAsync<string>(ScopeSql, new { versionId, purl }));
        Assert.Equal("manifest", await ScalarAsync<string>(SourceSql, new { versionId, purl }));

        var sarifResp = await client.PutAsync(
            "/api/v1/sarif?projectName=proj-provenance-a&projectVersion=1.0.0", ZeroResultSarif());
        Assert.Equal(HttpStatusCode.OK, sarifResp.StatusCode);

        Assert.Equal("dev", await ScalarAsync<string>(ScopeSql, new { versionId, purl }));
        Assert.Equal("manifest", await ScalarAsync<string>(SourceSql, new { versionId, purl }));
    }

    [Fact]
    public async Task ManifestFill_SurvivesAnSbomReUploadThatReappliesAnAlreadyStoredSarif()
    {
        using var client = await UploaderAsync();
        const string purl = "pkg:npm/left-pad@1.0.0";

        var sbomResp = await client.PutAsync(
            "/api/v1/sbom?projectName=proj-provenance-b&projectVersion=1.0.0&autoCreate=true",
            SbomWithDevDeclaration(purl));
        var body = JsonDocument.Parse(await sbomResp.Content.ReadAsStringAsync()).RootElement;
        string versionId = body.GetProperty("projectVersion").GetProperty("id").GetString()!;

        await client.PutAsync("/api/v1/sarif?projectName=proj-provenance-b&projectVersion=1.0.0", ZeroResultSarif());
        Assert.Equal("dev", await ScalarAsync<string>(ScopeSql, new { versionId, purl }));

        // Re-uploading the SBOM re-applies the stored SARIF as part of the same request — the
        // exact sequence a real `sbom-reach analyze` upload of both documents together triggers.
        var reuploadResp = await client.PutAsync(
            "/api/v1/sbom?projectName=proj-provenance-b&projectVersion=1.0.0&autoCreate=true",
            SbomWithDevDeclaration(purl));
        Assert.Equal(HttpStatusCode.OK, reuploadResp.StatusCode);

        Assert.Equal("dev", await ScalarAsync<string>(ScopeSql, new { versionId, purl }));
    }

    [Fact]
    public async Task AScannerVerdict_IsStillResetToUnknown_WhenALaterSarifNoLongerNamesTheComponent()
    {
        using var client = await UploaderAsync();
        const string purl = "pkg:npm/left-pad@1.0.0";

        var sbomResp = await client.PutAsync(
            "/api/v1/sbom?projectName=proj-provenance-c&projectVersion=1.0.0&autoCreate=true",
            // No manifest declaration this time — the scanner is the only signal.
            Json("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "metadata": { "component": { "type": "application", "name": "app", "version": "1.0.0" } },
                  "components": [
                    { "type": "library", "name": "left-pad", "version": "1.0.0", "purl": "pkg:npm/left-pad@1.0.0" }
                  ]
                }
                """));
        var body = JsonDocument.Parse(await sbomResp.Content.ReadAsStringAsync()).RootElement;
        string versionId = body.GetProperty("projectVersion").GetProperty("id").GetString()!;
        Assert.Equal("unknown", await ScalarAsync<string>(ScopeSql, new { versionId, purl }));

        // A SARIF names the component with a real finding, asserting dependencyScope=runtime.
        await client.PutAsync(
            "/api/v1/sarif?projectName=proj-provenance-c&projectVersion=1.0.0",
            SarifNaming(purl, "CVE-2100-0001", "reachable"));
        Assert.Equal("runtime", await ScalarAsync<string>(ScopeSql, new { versionId, purl }));
        Assert.Equal("scanner", await ScalarAsync<string>(SourceSql, new { versionId, purl }));

        // A later scan no longer finds anything against this component (advisory fixed, or the
        // scan simply stops naming it) — the reset must still fire for a scanner-sourced row.
        await client.PutAsync("/api/v1/sarif?projectName=proj-provenance-c&projectVersion=1.0.0", ZeroResultSarif());

        Assert.Equal("unknown", await ScalarAsync<string>(ScopeSql, new { versionId, purl }));
        Assert.Null(await ScalarAsync<string>(SourceSql, new { versionId, purl }));
    }

    [Fact]
    public async Task AScannerVerdict_StillOverridesAManifestFill_AndSurvivesALaterSbomReUpload()
    {
        using var client = await UploaderAsync();
        const string purl = "pkg:npm/left-pad@1.0.0";

        var sbomResp = await client.PutAsync(
            "/api/v1/sbom?projectName=proj-provenance-d&projectVersion=1.0.0&autoCreate=true",
            SbomWithDevDeclaration(purl));
        var body = JsonDocument.Parse(await sbomResp.Content.ReadAsStringAsync()).RootElement;
        string versionId = body.GetProperty("projectVersion").GetProperty("id").GetString()!;
        Assert.Equal("dev", await ScalarAsync<string>(ScopeSql, new { versionId, purl }));

        await client.PutAsync(
            "/api/v1/sarif?projectName=proj-provenance-d&projectVersion=1.0.0",
            SarifNaming(purl, "CVE-2100-0002", "reachable"));
        Assert.Equal("runtime", await ScalarAsync<string>(ScopeSql, new { versionId, purl }));
        Assert.Equal("scanner", await ScalarAsync<string>(SourceSql, new { versionId, purl }));

        // The SBOM's manifest still declares it a dev dependency, but the column is no longer
        // 'unknown' — the scanner verdict must not be downgraded, provenance included.
        await client.PutAsync(
            "/api/v1/sbom?projectName=proj-provenance-d&projectVersion=1.0.0&autoCreate=true",
            SbomWithDevDeclaration(purl));

        Assert.Equal("runtime", await ScalarAsync<string>(ScopeSql, new { versionId, purl }));
        Assert.Equal("scanner", await ScalarAsync<string>(SourceSql, new { versionId, purl }));
    }
}
