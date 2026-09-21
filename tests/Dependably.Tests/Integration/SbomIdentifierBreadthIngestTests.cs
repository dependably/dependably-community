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
/// CISA D13 (Component Identifiers), issue #691 — the ingest half: the merge/re-upload path for
/// <c>sbom_components.additional_identifiers</c>, from upload through to the stored row. The same
/// silent-failure class <see cref="Sbom685MinimumElementsIngestTests"/> pins for
/// <c>component_producer</c>/<c>lifecycles</c>: a column left out of the merge's equality check or
/// its UPDATE statement never actually changes on a re-upload that reports success, and a
/// projection revision that is not bumped leaves every already-stored document on the older
/// build's rows — neither shows up in a response body, so these assert against the column itself.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SbomIdentifierBreadthIngestTests : IAsyncLifetime
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

    private const string CpeOne = "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*";
    private const string CpeTwo = "cpe:2.3:a:acme:widget:9.9:*:*:*:*:*:*:*";

    private static HttpContent DocumentWithCpe(string cpe) =>
        JsonContent($$"""
            {
              "bomFormat": "CycloneDX",
              "specVersion": "1.7",
              "components": [
                {
                  "type": "library",
                  "name": "id-widget",
                  "purl": "pkg:npm/id-widget",
                  "version": "1.0.0",
                  "cpe": "{{cpe}}"
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

    private Task<string?> StoredAdditionalIdentifiersAsync(string versionId) =>
        ScalarAsync<string?>(
            "SELECT additional_identifiers FROM sbom_components WHERE project_version_id = @versionId",
            new { versionId });

    /// <summary>
    /// The ONLY thing that changes between the two uploads is the asserted CPE — name, version and
    /// purl are byte-identical, so the component matches the SAME existing row on both merge key
    /// components (<c>SbomIngestRepository.MergeKey</c>). This single scenario fails under EITHER
    /// of two independent defects: dropping <c>additional_identifiers</c> from
    /// <c>UpdateComponentAsync</c>'s SQL (the row is correctly detected as changed but the UPDATE
    /// never writes the new value) and dropping the column from <c>IsUnchanged</c>'s comparison
    /// (the row is incorrectly read as unchanged and the UPDATE never runs at all) — both leave the
    /// FIRST upload's CPE stored forever.
    /// </summary>
    [Fact]
    public async Task Reupload_WhenOnlyTheAssertedIdentifierChanged_UpdatesTheExistingRow()
    {
        using var client = await UploaderAsync();
        string versionId = await UploadAsync(client, "proj-691-merge", DocumentWithCpe(CpeOne));

        var response = await client.PutAsync(
            "/api/v1/sbom?projectName=proj-691-merge&projectVersion=1.0.0&autoCreate=true",
            DocumentWithCpe(CpeTwo));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        string? stored = await StoredAdditionalIdentifiersAsync(versionId);
        Assert.NotNull(stored);
        Assert.Contains(CpeTwo, stored, StringComparison.Ordinal);
        Assert.DoesNotContain(CpeOne, stored, StringComparison.Ordinal);
        Assert.Equal(1, await ScalarAsync<int>(
            "SELECT COUNT(*) FROM sbom_components WHERE project_version_id = @versionId",
            new { versionId }));
    }

    [Fact]
    public async Task Reupload_OfIdenticalBytesAtAStaleRevision_RepopulatesAdditionalIdentifiers()
    {
        using var client = await UploaderAsync();
        string versionId = await UploadAsync(client, "proj-691-stale", DocumentWithCpe(CpeOne));

        // Stand in for rows an older, narrower projection wrote: the document is byte-identical
        // and its stamp predates revision 7 (additional_identifiers), and the derived row has
        // never captured it.
        await ExecuteAsync(
            "UPDATE project_documents SET ingest_version = 6 WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId });
        await ExecuteAsync(
            "UPDATE sbom_components SET additional_identifiers = NULL WHERE project_version_id = @versionId",
            new { versionId });

        var response = await client.PutAsync(
            "/api/v1/sbom?projectName=proj-691-stale&projectVersion=1.0.0&autoCreate=true",
            DocumentWithCpe(CpeOne));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Fails if SbomIngestVersion.Current was not advanced past the revision that predates
        // additional_identifiers: identical bytes at a stamp equal to Current short-circuit, and
        // the row keeps the older projection's NULL with nothing ever correcting it.
        string? stored = await StoredAdditionalIdentifiersAsync(versionId);
        Assert.NotNull(stored);
        Assert.Contains(CpeOne, stored, StringComparison.Ordinal);
        Assert.True(SbomIngestVersion.Current > 6);
    }
}
