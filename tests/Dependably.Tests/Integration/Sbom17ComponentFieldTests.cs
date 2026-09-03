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
/// The two component fields CycloneDX 1.7 added — <c>versionRange</c> and <c>isExternal</c> —
/// from upload through to the stored row.
///
/// <para>Both failure modes these cover are silent. A column left out of the merge's equality
/// check never updates on a row that already exists, so the merge reports the component
/// unchanged and skips the write: the widened projection appears to do nothing, and only for
/// components whose identity happens to be stable. A projection revision that is not bumped
/// leaves every already-stored document on the older build's rows. Neither shows up in a
/// response body — both report success — so these assert against the columns themselves.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class Sbom17ComponentFieldTests : IAsyncLifetime
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

    /// <summary>A one-component 1.7 document whose only variable is the declared version range.</summary>
    private static HttpContent RangeDocument(string versionRange)
    {
        string json = $$"""
            {
              "bomFormat": "CycloneDX",
              "specVersion": "1.7",
              "components": [
                {
                  "type": "library",
                  "name": "axios",
                  "purl": "pkg:npm/axios",
                  "versionRange": "{{versionRange}}",
                  "isExternal": true
                }
              ]
            }
            """;
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

    private Task<string?> StoredRangeAsync(string versionId) =>
        ScalarAsync<string?>(
            "SELECT version_range FROM sbom_components WHERE project_version_id = @versionId",
            new { versionId });

    private Task<bool?> StoredIsExternalAsync(string versionId) =>
        ScalarAsync<bool?>(
            "SELECT is_external FROM sbom_components WHERE project_version_id = @versionId",
            new { versionId });

    [Fact]
    public async Task Upload_StoresBothFieldsAndLeavesVersionNullForARangeComponent()
    {
        using var client = await UploaderAsync();
        string versionId = await UploadAsync(
            client, "proj-17-store", RangeDocument("vers:npm/>=1.6.0|<2.0.0"));

        Assert.Equal("vers:npm/>=1.6.0|<2.0.0", await StoredRangeAsync(versionId));
        Assert.True(await StoredIsExternalAsync(versionId));

        // The specification admits versionRange INSTEAD of version, so the absent version is the
        // document being well-formed rather than a field the producer dropped.
        Assert.Null(await ScalarAsync<string?>(
            "SELECT version FROM sbom_components WHERE project_version_id = @versionId",
            new { versionId }));
    }

    [Fact]
    public async Task Reupload_WhenOnlyTheVersionRangeChanged_UpdatesTheExistingRow()
    {
        using var client = await UploaderAsync();
        string versionId = await UploadAsync(
            client, "proj-17-merge", RangeDocument("vers:npm/>=1.6.0|<2.0.0"));

        // Same purl, so the merge matches the existing row rather than inserting a second one:
        // this goes down the update arm, which is the arm the equality check guards.
        var response = await client.PutAsync(
            "/api/v1/sbom?projectName=proj-17-merge&projectVersion=1.0.0&autoCreate=true",
            RangeDocument("vers:npm/>=2.0.0|<3.0.0"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Fails if version_range is missing from the merge's equality check: the component would
        // compare equal on every other column, be reported unchanged, and keep the stale range.
        Assert.Equal("vers:npm/>=2.0.0|<3.0.0", await StoredRangeAsync(versionId));
        Assert.Equal(1, await ScalarAsync<int>(
            "SELECT COUNT(*) FROM sbom_components WHERE project_version_id = @versionId",
            new { versionId }));
    }

    [Fact]
    public async Task Reupload_OfIdenticalBytesAtAStaleRevision_RepopulatesBothFields()
    {
        using var client = await UploaderAsync();
        var document = RangeDocument("vers:npm/>=1.6.0|<2.0.0");
        string versionId = await UploadAsync(client, "proj-17-stale", document);

        // Stand in for rows an older, narrower projection wrote: the document is byte-identical
        // and its stamp predates this build, and the derived row is missing both values.
        await ExecuteAsync(
            "UPDATE project_documents SET ingest_version = 1 WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId });
        await ExecuteAsync(
            "UPDATE sbom_components SET version_range = NULL, is_external = NULL WHERE project_version_id = @versionId",
            new { versionId });

        var response = await client.PutAsync(
            "/api/v1/sbom?projectName=proj-17-stale&projectVersion=1.0.0&autoCreate=true",
            RangeDocument("vers:npm/>=1.6.0|<2.0.0"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Fails if SbomIngestVersion.Current was not advanced past the revision that predates
        // these columns: identical bytes at a stamp equal to Current short-circuit, and the row
        // keeps the older projection's NULLs with nothing ever correcting them.
        Assert.Equal("vers:npm/>=1.6.0|<2.0.0", await StoredRangeAsync(versionId));
        Assert.True(await StoredIsExternalAsync(versionId));
        Assert.True(SbomIngestVersion.Current > 1);
    }
}
