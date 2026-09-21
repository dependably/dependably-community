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
/// CISA X4/P4a (#688) — the ingest half: the merge/re-upload path for
/// <c>sbom_components.explicit_unknown_fields</c>, from upload through to the stored row. The
/// same silent-failure class <see cref="SbomIdentifierBreadthIngestTests"/> pins for
/// <c>additional_identifiers</c>: a column left out of the merge's equality check or its UPDATE
/// statement never actually changes on a re-upload that reports success, and a projection
/// revision that is not bumped leaves every already-stored document on the older build's rows —
/// neither shows up in a response body, so these assert against the column itself.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SbomExplicitUnknownIngestTests : IAsyncLifetime
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

    // supplier is the only field that varies between the two documents — name and version are
    // byte-identical, so the component matches the SAME existing row on SbomIngestRepository's
    // merge key, the same isolation SbomIdentifierBreadthIngestTests uses for additional_identifiers.
    private static HttpContent SpdxDocument(string supplier) =>
        JsonContent($$"""
            {
              "spdxVersion": "SPDX-2.3",
              "dataLicense": "CC0-1.0",
              "SPDXID": "SPDXRef-DOCUMENT",
              "name": "doc",
              "documentNamespace": "https://example.com/spdx/doc",
              "creationInfo": { "creators": [], "created": "2026-08-01T10:10:00Z" },
              "packages": [
                {
                  "name": "explicit-unknown-widget",
                  "SPDXID": "SPDXRef-Package-explicit-unknown-widget",
                  "versionInfo": "1.0.0",
                  "downloadLocation": "NOASSERTION",
                  "supplier": "{{supplier}}",
                  "externalRefs": [
                    { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/explicit-unknown-widget@1.0.0" }
                  ]
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

    private Task<string?> StoredExplicitUnknownFieldsAsync(string versionId) =>
        ScalarAsync<string?>(
            "SELECT explicit_unknown_fields FROM sbom_components WHERE project_version_id = @versionId",
            new { versionId });

    [Fact]
    public async Task Upload_WhenSupplierIsExplicitlyNoAssertion_StoresTheProducerMarker()
    {
        using var client = await UploaderAsync();
        string versionId = await UploadAsync(client, "proj-688-insert", SpdxDocument("NOASSERTION"));

        string? stored = await StoredExplicitUnknownFieldsAsync(versionId);
        Assert.NotNull(stored);
        Assert.Contains(SbomExplicitUnknownFields.Producer, stored, StringComparison.Ordinal);
    }

    /// <summary>
    /// Fails under EITHER of two independent defects: dropping <c>explicit_unknown_fields</c>
    /// from <c>UpdateComponentAsync</c>'s SQL (the row is correctly detected as changed but the
    /// UPDATE never writes the new value) and dropping the column from <c>IsUnchanged</c>'s
    /// comparison (the row is incorrectly read as unchanged and the UPDATE never runs at all) —
    /// both leave the first upload's explicit-unknown marker stored forever, silently misreporting
    /// a supplier who later names a real producer as still having said nothing.
    /// </summary>
    [Fact]
    public async Task Reupload_WhenSupplierChangesFromNoAssertionToAName_ClearsTheProducerMarker()
    {
        using var client = await UploaderAsync();
        string versionId = await UploadAsync(client, "proj-688-merge", SpdxDocument("NOASSERTION"));

        var response = await client.PutAsync(
            "/api/v1/sbom?projectName=proj-688-merge&projectVersion=1.0.0&autoCreate=true",
            SpdxDocument("Organization: Example Org"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        string? stored = await StoredExplicitUnknownFieldsAsync(versionId);
        Assert.True(stored is null || !stored.Contains(SbomExplicitUnknownFields.Producer, StringComparison.Ordinal));
        Assert.Equal("Example Org", await ScalarAsync<string>(
            "SELECT component_producer FROM sbom_components WHERE project_version_id = @versionId",
            new { versionId }));
        Assert.Equal(1, await ScalarAsync<int>(
            "SELECT COUNT(*) FROM sbom_components WHERE project_version_id = @versionId",
            new { versionId }));
    }

    [Fact]
    public async Task Reupload_OfIdenticalBytesAtAStaleRevision_RepopulatesExplicitUnknownFields()
    {
        using var client = await UploaderAsync();
        string versionId = await UploadAsync(client, "proj-688-stale", SpdxDocument("NOASSERTION"));

        // Stand in for rows an older, narrower projection wrote: the document is byte-identical
        // and its stamp predates revision 8 (explicit_unknown_fields), and the derived row has
        // never captured it.
        await ExecuteAsync(
            "UPDATE project_documents SET ingest_version = 7 WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId });
        await ExecuteAsync(
            "UPDATE sbom_components SET explicit_unknown_fields = NULL WHERE project_version_id = @versionId",
            new { versionId });

        var response = await client.PutAsync(
            "/api/v1/sbom?projectName=proj-688-stale&projectVersion=1.0.0&autoCreate=true",
            SpdxDocument("NOASSERTION"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Fails if SbomIngestVersion.Current was not advanced past the revision that predates
        // explicit_unknown_fields: identical bytes at a stamp equal to Current short-circuit, and
        // the row keeps the older projection's NULL with nothing ever correcting it.
        string? stored = await StoredExplicitUnknownFieldsAsync(versionId);
        Assert.NotNull(stored);
        Assert.Contains(SbomExplicitUnknownFields.Producer, stored, StringComparison.Ordinal);
        Assert.True(SbomIngestVersion.Current > 7);
    }
}
