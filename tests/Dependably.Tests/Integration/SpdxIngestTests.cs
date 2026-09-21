using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// SPDX 2.3 ingest through the real <c>PUT /api/v1/sbom</c> upload path: format detection off the
/// document's own content, the projection SPDX lands in, and the specific claim this front end
/// exists to make — that an SPDX document and an equivalent CycloneDX document of the same project
/// produce the same <c>sbom_components</c> rows. CycloneDX's own coverage of the shared merge,
/// dedup, VEX/SARIF re-apply and authorization paths lives in <see cref="SbomIngestTests"/> and is
/// not repeated here: SPDX shares every one of those once <see cref="SbomController"/> has decided
/// which parser produced the document.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SpdxIngestTests : IAsyncLifetime
{
    private readonly DependablyFactory _factory = new() { FrozenClock = TestTime.Frozen() };

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

    private static string Project(string caller) => $"proj-spdx-{caller}";

    [Fact]
    public async Task SpdxUpload_FromARealSyftDocument_IsDetectedAndMergedIntoTheSharedProjection()
    {
        string project = Project("syft");
        using var client = await UploaderAsync();

        var response = await client.PutAsync(
            $"/api/v1/sbom?projectName={project}&projectVersion=1.0.0&autoCreate=true",
            Document("spdx-2.3-npm-syft.json"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await BodyAsync(response);
        // The document's own subject (the scanned directory, described via a DESCRIBES
        // relationship) is excluded from the inventory, same as CycloneDX's metadata.component —
        // leaving the three real npm packages Syft found: the manifest's own package, chalk and
        // lodash.
        Assert.Equal(3, body.GetProperty("components").GetProperty("total").GetInt32());

        string versionId = body.GetProperty("projectVersion").GetProperty("id").GetString()!;

        Assert.Equal("spdx-json", await QueryAsync<string>(
            "SELECT format FROM project_documents WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId }));
        Assert.Equal("SPDX-2.3", await QueryAsync<string>(
            "SELECT spec_version FROM project_documents WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId }));
        Assert.Equal("syft", await QueryAsync<string>(
            "SELECT tool_name FROM project_documents WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId }));
        Assert.Equal("1.46.0", await QueryAsync<string>(
            "SELECT tool_version FROM project_documents WHERE project_version_id = @versionId AND doc_type = 'sbom'",
            new { versionId }));

        Assert.Equal("npm", await QueryAsync<string>(
            "SELECT ecosystem FROM sbom_components WHERE project_version_id = @versionId AND name = 'chalk'",
            new { versionId }));
        Assert.Equal("pkg:npm/chalk@5.3.0", await QueryAsync<string>(
            "SELECT purl FROM sbom_components WHERE project_version_id = @versionId AND name = 'chalk'",
            new { versionId }));
        // chalk's licenseConcluded is NOASSERTION; licenseDeclared is the real MIT fact, and the
        // fallback is what surfaces it.
        Assert.Equal("MIT", await QueryAsync<string>(
            "SELECT license_spdx FROM sbom_components WHERE project_version_id = @versionId AND name = 'chalk'",
            new { versionId }));
        // lodash declares neither — both fields are NOASSERTION — so it records no licence rather
        // than a fabricated one.
        Assert.Null(await QueryAsync<string>(
            "SELECT license_spdx FROM sbom_components WHERE project_version_id = @versionId AND name = 'lodash'",
            new { versionId }));
        // Every supplier in this real document is NOASSERTION, so component_producer stays null
        // for all three — Syft did not claim a producer for any of them.
        Assert.Equal(0, await QueryAsync<int>(
            "SELECT COUNT(*) FROM sbom_components WHERE project_version_id = @versionId AND component_producer IS NOT NULL",
            new { versionId }));

        // Syft's directory scan describes the scanned directory itself, not the npm package its
        // DEPENDENCY_OF edges are actually rooted at one level below — the resolved root ref then
        // has no outgoing edge in the DEPENDS_ON-family graph, so the honest answer is
        // graph-unknown for chalk, not a fabricated direct/transitive position. The SAME real
        // fixture also declares CONTAINS from that directory root straight to chalk, but
        // SpdxParser deliberately keeps that OUT of dependency_kind/dependency_path (see
        // SpdxParser.ReadContainedRefs and CycloneDxComponent.ContainmentDeclared's own doc
        // comment) — it feeds D17's scoring separately instead (SbomConformanceScorerFixtureTests
        // pins that), never these two columns, so a genuine multi-hop DEPENDS_ON chain elsewhere
        // in a document can never be overwritten by a root-level CONTAINS to the same component.
        Assert.Equal("graph-unknown", await QueryAsync<string>(
            "SELECT dependency_kind FROM sbom_components WHERE project_version_id = @versionId AND name = 'chalk'",
            new { versionId }));
        Assert.Null(await QueryAsync<string>(
            "SELECT dependency_path FROM sbom_components WHERE project_version_id = @versionId AND name = 'chalk'",
            new { versionId }));
        Assert.Equal(1, await QueryAsync<int>(
            "SELECT containment_declared FROM sbom_components WHERE project_version_id = @versionId AND name = 'chalk'",
            new { versionId }));
    }

    [Fact]
    public async Task SpdxUpload_RejectsASpdxVersionOutsideTheAcceptedSet()
    {
        using var client = await UploaderAsync();
        var response = await client.PutAsync(
            $"/api/v1/sbom?projectName={Project("oldspdx")}&projectVersion=1.0.0&autoCreate=true",
            Document("spdx-2.2-unsupported.json"));

        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        Assert.Contains("SPDX-2.2", (await BodyAsync(response)).GetProperty("detail").GetString());
    }

    [Fact]
    public async Task SpdxAndCycloneDxDocumentsOfTheSameProject_ProduceTheSameComponentRow()
    {
        using var client = await UploaderAsync();

        var cycloneDxResponse = await client.PutAsync(
            $"/api/v1/sbom?projectName={Project("cdx-equiv")}&projectVersion=1.0.0&autoCreate=true",
            Document("cyclonedx-1.6-equivalence.json"));
        var spdxResponse = await client.PutAsync(
            $"/api/v1/sbom?projectName={Project("spdx-equiv")}&projectVersion=1.0.0&autoCreate=true",
            Document("spdx-2.3-equivalence.json"));

        Assert.Equal(HttpStatusCode.OK, cycloneDxResponse.StatusCode);
        Assert.Equal(HttpStatusCode.OK, spdxResponse.StatusCode);

        string cdxVersionId = (await BodyAsync(cycloneDxResponse))
            .GetProperty("projectVersion").GetProperty("id").GetString()!;
        string spdxVersionId = (await BodyAsync(spdxResponse))
            .GetProperty("projectVersion").GetProperty("id").GetString()!;

        var cdxRow = await RowAsync(cdxVersionId);
        var spdxRow = await RowAsync(spdxVersionId);

        // Every field the CISA "at minimum" mapping list names — including presentation metadata
        // (description, copyright, the linked URLs), not only identity/licence/graph — read back
        // identically regardless of which format asserted it. org_id, project_version_id, id and
        // created_at are excluded deliberately: those name where the row lives, not what it says.
        // component_hashes is excluded from this struct too, but not because it is untested — see
        // the checksum assertion below, which compares it on its own terms.
        Assert.Equal(cdxRow, spdxRow);

        // component_hashes is stored VERBATIM per format at ingest (SPDX's "SHA256" is not the
        // same string as CycloneDX's "SHA-256", even though both assert the same algorithm over
        // the same digest) — the two formats are reconciled at the export boundary, not at rest.
        // A strict string-equality assertion here would therefore fail on a difference that is
        // correct by design; this checks the two rows assert the same fact instead: the same
        // digest, under algorithm spellings that resolve to the same normalized name.
        string? cdxHashes = await QueryAsync<string>(
            "SELECT component_hashes FROM sbom_components WHERE project_version_id = @versionId AND name = 'left-pad'",
            new { versionId = cdxVersionId });
        string? spdxHashes = await QueryAsync<string>(
            "SELECT component_hashes FROM sbom_components WHERE project_version_id = @versionId AND name = 'left-pad'",
            new { versionId = spdxVersionId });
        Assert.NotNull(cdxHashes);
        Assert.NotNull(spdxHashes);
        Assert.Equal(NormalizedHashFacts(cdxHashes), NormalizedHashFacts(spdxHashes));
    }

    // {alg (hyphens stripped), content}, so "SHA-256" and "SHA256" compare equal while the actual
    // digest content still has to match exactly.
    private static HashSet<(string Alg, string Content)> NormalizedHashFacts(string hashesJson) =>
        JsonDocument.Parse(hashesJson).RootElement.EnumerateArray()
            .Select(h => (
                Alg: h.GetProperty("alg").GetString()!.Replace("-", string.Empty, StringComparison.Ordinal),
                Content: h.GetProperty("content").GetString()!))
            .ToHashSet();

    [Fact]
    public async Task SbomUpload_RefusesADocumentCarryingBothSpdxAndCycloneDxMarkers()
    {
        using var client = await UploaderAsync();
        // Both an unambiguous spdxVersion and a bomFormat: "CycloneDX" marker on the same
        // document — genuinely ambiguous, and the one shape neither parser may resolve by
        // precedence: parsing it under the wrong one finds none of the fields it expects, yields
        // zero components, and the merge would then delete every component the version already
        // held. Refusing before either parser runs is what keeps that from ever being reachable.
        var body = new StringContent(
            """
            {
              "bomFormat": "CycloneDX",
              "specVersion": "1.6",
              "spdxVersion": "SPDX-2.3",
              "components": [ { "type": "library", "name": "x", "version": "1.0.0" } ]
            }
            """,
            System.Text.Encoding.UTF8, "application/json");

        var response = await client.PutAsync(
            $"/api/v1/sbom?projectName={Project("ambiguous-both")}&projectVersion=1.0.0&autoCreate=true", body);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        Assert.Equal(0, await QueryAsync<int>(
            "SELECT COUNT(*) FROM projects WHERE name = @name", new { name = Project("ambiguous-both") }));
    }

    [Fact]
    public async Task SbomUpload_RefusesADocumentCarryingNeitherMarker()
    {
        using var client = await UploaderAsync();
        var body = new StringContent(
            """{ "components": [ { "type": "library", "name": "x", "version": "1.0.0" } ] }""",
            System.Text.Encoding.UTF8, "application/json");

        var response = await client.PutAsync(
            $"/api/v1/sbom?projectName={Project("no-marker")}&projectVersion=1.0.0&autoCreate=true", body);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
    }

    private sealed record ComponentFacts(
        string Purl, string Ecosystem, string PurlName, string Version, string Name,
        string ComponentType, string LicenseSpdx, string ComponentAuthor, string ComponentProducer,
        string DependencyKind, string DependencyPath, string Description, string Copyright,
        string WebsiteUrl, string DistributionUrl);

    private async Task<ComponentFacts> RowAsync(string versionId)
    {
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        return await conn.QuerySingleAsync<ComponentFacts>(
            """
            SELECT purl AS Purl, ecosystem AS Ecosystem, purl_name AS PurlName, version AS Version,
                   name AS Name, component_type AS ComponentType, license_spdx AS LicenseSpdx,
                   component_author AS ComponentAuthor, component_producer AS ComponentProducer,
                   dependency_kind AS DependencyKind, dependency_path AS DependencyPath,
                   description AS Description, copyright AS Copyright,
                   website_url AS WebsiteUrl, distribution_url AS DistributionUrl
            FROM sbom_components WHERE project_version_id = @versionId AND name = 'left-pad'
            """,
            new { versionId });
    }
}
