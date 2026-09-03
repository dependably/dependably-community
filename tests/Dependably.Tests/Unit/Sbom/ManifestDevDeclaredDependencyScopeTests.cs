using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Xunit;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// The CycloneDX-side fill of <c>sbom_components.dependency_scope</c> from a manifest's own
/// dev-dependency declaration (<see cref="CycloneDxComponent.ManifestDevDeclared"/>), driven
/// through the real merge and ingest repository rather than a hand-inserted row.
///
/// <para>The column is scanner-owned: a manifest declaration is only ever allowed to fill the
/// 'unknown' default, never to overwrite a value a reachability scanner already asserted. Every
/// test here proves one side of that: a fresh component gets filled, an already-filled component
/// stays filled, and a scanner verdict survives a re-upload of the SBOM that reported the
/// opposite manifest declaration.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class ManifestDevDeclaredDependencyScopeTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly SbomIngestRepository _ingest;
    private readonly SbomMergeService _merge;

    public ManifestDevDeclaredDependencyScopeTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _ingest = new SbomIngestRepository(_fixture.Store);
        _merge = new SbomMergeService(_ingest);
    }

    private const string ComponentPurl = "pkg:npm/left-pad@1.0.0";

    private static string InventoryJson(string? manifestDevValue) => $$"""
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "metadata": { "component": { "type": "application", "name": "app", "version": "1.0.0" } },
          "components": [
            {
              "type": "library",
              "name": "left-pad",
              "version": "1.0.0",
              "purl": "pkg:npm/left-pad@1.0.0"
              {{(manifestDevValue is null ? "" : $$""", "properties": [ { "name": "cdx:npm:package:development", "value": "{{manifestDevValue}}" } ]""")}}
            }
          ]
        }
        """;

    private static CycloneDxDocument Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return CycloneDxParser.Parse(doc.RootElement);
    }

    private async Task<string> InsertProjectVersionAsync(string orgId)
    {
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name) VALUES (@projectId, @orgId, @name)",
            new { projectId, orgId, name = $"proj-{projectId[..8]}" });
        await conn.ExecuteAsync(
            "INSERT INTO project_versions (id, org_id, project_id, version) VALUES (@versionId, @orgId, @projectId, '1.0.0')",
            new { versionId, orgId, projectId });
        return versionId;
    }

    private async Task<string> DependencyScopeAsync(string orgId, string versionId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT dependency_scope FROM sbom_components WHERE org_id = @orgId AND project_version_id = @versionId AND purl = @purl",
            new { orgId, versionId, purl = ComponentPurl }))!;
    }

    private async Task<string> ComponentIdAsync(string orgId, string versionId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM sbom_components WHERE org_id = @orgId AND project_version_id = @versionId AND purl = @purl",
            new { orgId, versionId, purl = ComponentPurl }))!;
    }

    [Fact]
    public async Task FirstIngest_FillsDevFromATrueManifestDeclaration()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"mdd-a-{Guid.NewGuid():N}");
        string versionId = await InsertProjectVersionAsync(orgId);

        await _merge.MergeComponentsAsync(orgId, versionId, Parse(InventoryJson("true")), TestTime.KnownNow);

        Assert.Equal("dev", await DependencyScopeAsync(orgId, versionId));
    }

    [Fact]
    public async Task FirstIngest_FillsRuntimeFromAFalseManifestDeclaration()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"mdd-b-{Guid.NewGuid():N}");
        string versionId = await InsertProjectVersionAsync(orgId);

        await _merge.MergeComponentsAsync(orgId, versionId, Parse(InventoryJson("false")), TestTime.KnownNow);

        Assert.Equal("runtime", await DependencyScopeAsync(orgId, versionId));
    }

    [Fact]
    public async Task FirstIngest_StaysUnknownWhenTheDocumentDeclaresNothing()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"mdd-c-{Guid.NewGuid():N}");
        string versionId = await InsertProjectVersionAsync(orgId);

        await _merge.MergeComponentsAsync(orgId, versionId, Parse(InventoryJson(null)), TestTime.KnownNow);

        Assert.Equal("unknown", await DependencyScopeAsync(orgId, versionId));
    }

    [Fact]
    public async Task ReUpload_FillsAPreviouslyUnknownComponentOnASecondPass()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"mdd-d-{Guid.NewGuid():N}");
        string versionId = await InsertProjectVersionAsync(orgId);

        await _merge.MergeComponentsAsync(orgId, versionId, Parse(InventoryJson(null)), TestTime.KnownNow);
        Assert.Equal("unknown", await DependencyScopeAsync(orgId, versionId));

        await _merge.MergeComponentsAsync(orgId, versionId, Parse(InventoryJson("true")), TestTime.KnownNow);
        Assert.Equal("dev", await DependencyScopeAsync(orgId, versionId));
    }

    [Fact]
    public async Task ScannerVerdict_IsNeverDowngradedByARe_UploadedSbomsOppositeDeclaration()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"mdd-e-{Guid.NewGuid():N}");
        string versionId = await InsertProjectVersionAsync(orgId);

        await _merge.MergeComponentsAsync(orgId, versionId, Parse(InventoryJson(null)), TestTime.KnownNow);
        string componentId = await ComponentIdAsync(orgId, versionId);

        // A reachability scanner asserts 'runtime' — the authoritative verdict a SARIF upload
        // would write via ApplyComponentFactsAsync.
        await _ingest.ApplyComponentFactsAsync(
            orgId,
            new[] { new SbomComponentFactWrite(componentId, "runtime", DependencyKind: null, DependencyPath: null) });
        Assert.Equal("runtime", await DependencyScopeAsync(orgId, versionId));

        // The same SBOM is re-uploaded, this time declaring the component a dev dependency in
        // its manifest. The scanner's 'runtime' verdict must survive.
        await _merge.MergeComponentsAsync(orgId, versionId, Parse(InventoryJson("true")), TestTime.KnownNow);

        Assert.Equal("runtime", await DependencyScopeAsync(orgId, versionId));
    }

    [Fact]
    public async Task ReUploadingAnUnchangedManifestDeclaration_StaysIdempotent()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"mdd-f-{Guid.NewGuid():N}");
        string versionId = await InsertProjectVersionAsync(orgId);

        await _merge.MergeComponentsAsync(orgId, versionId, Parse(InventoryJson("true")), TestTime.KnownNow);
        var counts = await _merge.MergeComponentsAsync(orgId, versionId, Parse(InventoryJson("true")), TestTime.KnownNow);

        Assert.Equal(0, counts.Added);
        Assert.Equal(1, counts.Unchanged);
        Assert.Equal("dev", await DependencyScopeAsync(orgId, versionId));
    }
}
