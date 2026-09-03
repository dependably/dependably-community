using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// The regression this repo actually hit: <see cref="SbomIngestVersion.Current"/> was not bumped
/// when the manifest dev-declaration fill (<c>SPEC-650</c>) landed, so a document already stored
/// under the older revision short-circuited on its SHA-256 forever — every component a
/// reachability scanner had not classified stayed at <c>dependency_scope = 'unknown'</c>, and no
/// re-upload of the identical bytes could ever fill it. <see cref="SbomIngestVersionGateTests"/>
/// covers the re-merge mechanism generically (via <c>license_spdx</c>); this test pins the exact
/// field this repo actually shipped a silent gap for.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ManifestDevDeclaredIngestVersionTests : IAsyncLifetime
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

    private static HttpContent Document()
    {
        const string json = """
            {
              "bomFormat": "CycloneDX",
              "specVersion": "1.6",
              "metadata": { "component": { "type": "application", "name": "app", "version": "1.0.0" } },
              "components": [
                {
                  "type": "library",
                  "name": "left-pad",
                  "version": "1.0.0",
                  "purl": "pkg:npm/left-pad@1.0.0",
                  "properties": [ { "name": "cdx:npm:package:development", "value": "true" } ]
                }
              ]
            }
            """;
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

    private static async Task<string> UploadAsync(HttpClient client, string project)
    {
        var response = await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true", Document());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        return body.GetProperty("projectVersion").GetProperty("id").GetString()!;
    }

    private Task<string> DependencyScopeAsync(string versionId) =>
        ScalarAsync<string>(
            "SELECT dependency_scope FROM sbom_components WHERE project_version_id = @versionId AND purl = @purl",
            new { versionId, purl = "pkg:npm/left-pad@1.0.0" })!;

    [Fact]
    public async Task ReuploadOfADocumentStoredBeforeThisRevision_FillsDependencyScopeFromTheManifest()
    {
        using var client = await UploaderAsync();
        string versionId = await UploadAsync(client, "proj-manifest-scope-stale");

        Assert.Equal(SbomIngestVersion.Current, await ScalarAsync<int>(
            "SELECT ingest_version FROM project_documents WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId }));

        // Stand in for what a build at revision 2 (before SPEC-650) actually left behind: the
        // manifest declaration ignored, dependency_scope never touched.
        await ExecuteAsync(
            "UPDATE project_documents SET ingest_version = 2 WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId });
        await ExecuteAsync(
            "UPDATE sbom_components SET dependency_scope = 'unknown' WHERE project_version_id = @versionId",
            new { versionId });
        Assert.Equal("unknown", await DependencyScopeAsync(versionId));

        var response = await client.PutAsync(
            "/api/v1/sbom?projectName=proj-manifest-scope-stale&projectVersion=1.0.0&autoCreate=true", Document());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        Assert.Equal("dev", await DependencyScopeAsync(versionId));
        Assert.Equal(SbomIngestVersion.Current, await ScalarAsync<int>(
            "SELECT ingest_version FROM project_documents WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId }));
    }
}
