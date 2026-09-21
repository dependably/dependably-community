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
/// CISA 2026 minimum elements (issue #685) — the ingest half: the Component Producer / Component
/// Author split (D10) and <c>metadata.lifecycles</c> capture (D5), from upload through to the
/// stored row.
///
/// <para>Both failure modes this covers are silent, the same class <see cref="Sbom17ComponentFieldTests"/>
/// pins for the 1.7 fields: a column left out of the merge's equality check never updates on a row
/// that already exists, and a projection revision that is not bumped leaves every already-stored
/// document on the older build's rows. Neither shows up in a response body — both report
/// success — so these assert against the columns themselves.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class Sbom685MinimumElementsIngestTests : IAsyncLifetime
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

    /// <summary>
    /// One component whose <c>authors[]</c> and <c>publisher</c> NAME DIFFERENT ENTITIES —
    /// the adversarial shape a collapsed single column could not distinguish — plus a document
    /// <c>metadata.lifecycles</c> declaring the defined <c>post-build</c> phase.
    /// </summary>
    private static HttpContent Document() =>
        JsonContent("""
            {
              "bomFormat": "CycloneDX",
              "specVersion": "1.7",
              "metadata": {
                "lifecycles": [ { "phase": "post-build" } ]
              },
              "components": [
                {
                  "type": "library",
                  "name": "axios",
                  "purl": "pkg:npm/axios",
                  "version": "1.6.0",
                  "authors": [ { "name": "Ada Lovelace" } ],
                  "publisher": "Acme Corp"
                }
              ]
            }
            """);

    private static HttpContent JsonContent(string json)
    {
        var content = new ByteArrayContent(Encoding.UTF8.GetBytes(json));
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

    private static async Task<string> UploadAsync(HttpClient client, string project, HttpContent document)
    {
        var response = await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true", document);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        return body.GetProperty("projectVersion").GetProperty("id").GetString()!;
    }

    private Task<string?> StoredAuthorAsync(string versionId) =>
        ScalarAsync<string?>(
            "SELECT component_author FROM sbom_components WHERE project_version_id = @versionId",
            new { versionId });

    private Task<string?> StoredProducerAsync(string versionId) =>
        ScalarAsync<string?>(
            "SELECT component_producer FROM sbom_components WHERE project_version_id = @versionId",
            new { versionId });

    private Task<string?> StoredLifecyclesAsync(string versionId) =>
        ScalarAsync<string?>(
            "SELECT lifecycles FROM project_documents WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId });

    [Fact]
    public async Task Upload_StoresProducerDistinctFromAuthor_AndTheDeclaredLifecyclePhase()
    {
        using var client = await UploaderAsync();
        string versionId = await UploadAsync(client, "proj-685-store", Document());

        // Adversarial: publisher and authors[] name DIFFERENT entities in the fixture, so a
        // regression that folds publisher back into author (or vice versa) is visible here —
        // a fixture where the two happened to agree would not catch it.
        Assert.Equal("Ada Lovelace", await StoredAuthorAsync(versionId));
        Assert.Equal("Acme Corp", await StoredProducerAsync(versionId));

        string? lifecycles = await StoredLifecyclesAsync(versionId);
        Assert.NotNull(lifecycles);
        Assert.Contains("post-build", lifecycles);
    }

    [Fact]
    public async Task Reupload_WhenOnlyThePublisherChanged_UpdatesTheExistingRow()
    {
        using var client = await UploaderAsync();
        string versionId = await UploadAsync(client, "proj-685-merge", Document());

        var changed = JsonContent("""
            {
              "bomFormat": "CycloneDX",
              "specVersion": "1.7",
              "metadata": { "lifecycles": [ { "phase": "post-build" } ] },
              "components": [
                {
                  "type": "library",
                  "name": "axios",
                  "purl": "pkg:npm/axios",
                  "version": "1.6.0",
                  "authors": [ { "name": "Ada Lovelace" } ],
                  "publisher": "Different Org"
                }
              ]
            }
            """);
        var response = await client.PutAsync(
            "/api/v1/sbom?projectName=proj-685-merge&projectVersion=1.0.0&autoCreate=true", changed);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Fails if component_producer is missing from the merge's equality check: the component
        // would compare equal on every other column, be reported unchanged, and keep the stale
        // producer.
        Assert.Equal("Different Org", await StoredProducerAsync(versionId));
        Assert.Equal(1, await ScalarAsync<int>(
            "SELECT COUNT(*) FROM sbom_components WHERE project_version_id = @versionId",
            new { versionId }));
    }

    [Fact]
    public async Task Reupload_OfIdenticalBytesAtAStaleRevision_RepopulatesProducerAndLifecycles()
    {
        using var client = await UploaderAsync();
        var document = Document();
        string versionId = await UploadAsync(client, "proj-685-stale", document);

        // Stand in for rows an older, narrower projection wrote: the document is byte-identical
        // and its stamp predates this build, and the derived rows are missing both facts.
        await ExecuteAsync(
            "UPDATE project_documents SET ingest_version = 3, lifecycles = NULL WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId });
        await ExecuteAsync(
            "UPDATE sbom_components SET component_producer = NULL WHERE project_version_id = @versionId",
            new { versionId });

        var response = await client.PutAsync(
            "/api/v1/sbom?projectName=proj-685-stale&projectVersion=1.0.0&autoCreate=true", Document());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Fails if SbomIngestVersion.Current was not advanced past the revision that predates
        // these columns: identical bytes at a stamp equal to Current short-circuit, and the rows
        // keep the older projection's NULLs with nothing ever correcting them.
        Assert.Equal("Acme Corp", await StoredProducerAsync(versionId));
        string? lifecycles = await StoredLifecyclesAsync(versionId);
        Assert.NotNull(lifecycles);
        Assert.Contains("post-build", lifecycles);
        Assert.True(SbomIngestVersion.Current > 3);
    }
}
