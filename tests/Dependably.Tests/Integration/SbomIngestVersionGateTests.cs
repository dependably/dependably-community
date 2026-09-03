using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// The re-merge mechanism: <c>project_documents.ingest_version</c> and the dedup arm's equality
/// check against <see cref="SbomIngestVersion.Current"/>.
///
/// <para>Ingest short-circuits on the stored document's SHA-256, which is correct while the
/// projection is fixed and wrong the moment it widens: a build that records a field its
/// predecessor discarded would leave every already-stored document's rows exactly as the older
/// build wrote them, and the only thing that would ever repopulate them is the project's content
/// happening to change. The projects whose dependencies are most stable are precisely the ones
/// that would never self-correct.</para>
///
/// <para><b>Both failure directions are silent</b>, which is why they are worth a gate. Nothing
/// raises when the constant stops being bumped as the projection widens, and nothing raises when
/// the dedup arm drops the comparison — rows simply keep the older projection's values, and every
/// response still reports success. The response body cannot tell the two apart either: a dedup
/// short-circuit and a genuine re-merge of unchanged content both report
/// <c>added = 0, unchanged = 13</c>. These tests therefore assert against a column the merge
/// rewrites, not against the response.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class SbomIngestVersionGateTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new() { FrozenClock = TestTime.Frozen() };

    public async Task InitializeAsync() => await _factory.InitializeAsync();

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    private const string Fixture = "cyclonedx-1.6-inventory.json";

    private async Task<HttpClient> UploaderAsync()
    {
        string jwt = await _factory.CreateAdminJwt();
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }

    private static HttpContent Document()
    {
        var content = new ByteArrayContent(
            File.ReadAllBytes(Path.Combine(FixtureManifest.SbomFixturesRoot, Fixture)));
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

    private Task<int> LicensedComponentCountAsync(string versionId) =>
        ScalarAsync<int>(
            "SELECT COUNT(*) FROM sbom_components WHERE project_version_id = @versionId AND license_spdx IS NOT NULL",
            new { versionId })!;

    private Task<int> StoredIngestVersionAsync(string versionId) =>
        ScalarAsync<int>(
            "SELECT ingest_version FROM project_documents WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId })!;

    [Fact]
    public async Task Upload_StampsTheRunningIngestVersionOnTheDocumentRow()
    {
        using var client = await UploaderAsync();
        string versionId = await UploadAsync(client, "proj-stamp");

        // The column defaults to 0, so a writer that never names it leaves every document looking
        // permanently stale — the whole corpus would re-merge on every upload, forever.
        Assert.Equal(SbomIngestVersion.Current, await StoredIngestVersionAsync(versionId));
        Assert.NotEqual(0, SbomIngestVersion.Current);
    }

    [Fact]
    public async Task Reupload_WhenTheStoredIngestVersionIsStale_ReMergesTheComponentRows()
    {
        using var client = await UploaderAsync();
        string versionId = await UploadAsync(client, "proj-stale");

        int licensed = await LicensedComponentCountAsync(versionId);
        Assert.Equal(12, licensed);

        // Stand in for rows an older, narrower projection wrote: the document is byte-identical
        // and its version predates this build, and the derived rows are missing a value this
        // build would have recorded.
        await ExecuteAsync(
            "UPDATE project_documents SET ingest_version = 0 WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId });
        await ExecuteAsync(
            "UPDATE sbom_components SET license_spdx = NULL WHERE project_version_id = @versionId",
            new { versionId });
        Assert.Equal(0, await LicensedComponentCountAsync(versionId));

        var response = await client.PutAsync(
            "/api/v1/sbom?projectName=proj-stale&projectVersion=1.0.0&autoCreate=true", Document());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // The rows are rebuilt from the document rather than left as the older projection wrote
        // them, and the stamp advances so the next identical upload is a no-op again.
        Assert.Equal(licensed, await LicensedComponentCountAsync(versionId));
        Assert.Equal(SbomIngestVersion.Current, await StoredIngestVersionAsync(versionId));
    }

    [Fact]
    public async Task Reupload_AtTheCurrentIngestVersion_StillShortCircuits()
    {
        using var client = await UploaderAsync();
        string versionId = await UploadAsync(client, "proj-current");

        // The adversarial twin of the test above: same mutation to the derived rows, but the
        // stored version is left current. Without this, a build that simply stopped deduping
        // would satisfy the stale-version test and nothing would notice.
        await ExecuteAsync(
            "UPDATE sbom_components SET license_spdx = NULL WHERE project_version_id = @versionId",
            new { versionId });

        var response = await client.PutAsync(
            "/api/v1/sbom?projectName=proj-current&projectVersion=1.0.0&autoCreate=true", Document());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Still zero: identical bytes at the current projection revision do no work, which is the
        // property that keeps a CI job re-pushing an unchanged build cheap.
        Assert.Equal(0, await LicensedComponentCountAsync(versionId));
    }
}
