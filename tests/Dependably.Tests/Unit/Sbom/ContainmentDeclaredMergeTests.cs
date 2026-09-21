using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Xunit;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// <c>sbom_components.containment_declared</c> through the real merge and ingest repository,
/// pinning the exact silent-hole shape <see cref="SbomIngestRepository"/>'s own
/// <c>IsUnchanged</c> doc comment names: "a field compared nowhere is a field that never updates
/// on a row that already exists."
///
/// <para><c>IsUnchanged</c> is what <see cref="SbomIngestRepository.MergeComponentsAsync"/>
/// reads to decide whether an existing (purl, name, version) match needs a real UPDATE or can be
/// skipped as already correct. Deleting the <c>ContainmentDeclared</c> comparison from it does
/// not fail on FIRST ingest (the row does not exist yet, so it always inserts) — it fails on
/// RE-ingest, exactly the case the <c>SbomIngestVersion</c> bump exists to force a re-merge for.
/// Every test in this file re-merges the SAME component across two SPDX documents, so a mutant
/// that drops the comparison is caught on the SECOND call, not the first.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class ContainmentDeclaredMergeTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly SbomIngestRepository _ingest;
    private readonly SbomMergeService _merge;

    public ContainmentDeclaredMergeTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _ingest = new SbomIngestRepository(_fixture.Store);
        _merge = new SbomMergeService(_ingest);
    }

    private static string SpdxDocument(bool declareContains)
    {
        string containsRelationship = declareContains
            ? """, { "spdxElementId": "SPDXRef-Package-demo-app", "relatedSpdxElement": "SPDXRef-Package-left-pad", "relationshipType": "CONTAINS" }"""
            : "";

        return $$"""
            {
              "spdxVersion": "SPDX-2.3",
              "SPDXID": "SPDXRef-DOCUMENT",
              "name": "demo-app",
              "creationInfo": { "creators": [], "created": "2026-08-01T10:10:00Z" },
              "documentDescribes": ["SPDXRef-Package-demo-app"],
              "packages": [
                { "name": "demo-app", "SPDXID": "SPDXRef-Package-demo-app", "versionInfo": "2.0.0", "downloadLocation": "NOASSERTION" },
                {
                  "name": "left-pad", "SPDXID": "SPDXRef-Package-left-pad", "versionInfo": "1.3.0",
                  "downloadLocation": "NOASSERTION",
                  "externalRefs": [
                    { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/left-pad@1.3.0" }
                  ]
                }
              ],
              "relationships": [
                { "spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-Package-demo-app", "relationshipType": "DESCRIBES" }
                {{containsRelationship}}
              ]
            }
            """;
    }

    private static CycloneDxDocument Parse(bool declareContains)
    {
        using var doc = JsonDocument.Parse(SpdxDocument(declareContains));
        return SpdxParser.Parse(doc.RootElement);
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

    private async Task<bool> ContainmentDeclaredAsync(string orgId, string versionId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        long value = await conn.ExecuteScalarAsync<long>(
            "SELECT containment_declared FROM sbom_components WHERE org_id = @orgId AND project_version_id = @versionId AND name = 'left-pad'",
            new { orgId, versionId });
        return value == 1;
    }

    [Fact]
    public async Task FirstIngest_LeavesContainmentDeclaredFalse_WhenTheDocumentAssertsNoContainsEdge()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cd-a-{Guid.NewGuid():N}");
        string versionId = await InsertProjectVersionAsync(orgId);

        await _merge.MergeComponentsAsync(orgId, versionId, Parse(declareContains: false), TestTime.KnownNow);

        Assert.False(await ContainmentDeclaredAsync(orgId, versionId));
    }

    [Fact]
    public async Task FirstIngest_SetsContainmentDeclaredTrue_WhenTheDocumentAssertsAContainsEdge()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cd-b-{Guid.NewGuid():N}");
        string versionId = await InsertProjectVersionAsync(orgId);

        await _merge.MergeComponentsAsync(orgId, versionId, Parse(declareContains: true), TestTime.KnownNow);

        Assert.True(await ContainmentDeclaredAsync(orgId, versionId));
    }

    [Fact]
    public async Task ReUpload_FlipsContainmentDeclaredFalseToTrue_AndDoesNotCountAsUnchanged()
    {
        // The exact silent-hole shape: a component that ALREADY exists (same purl, name,
        // version — the merge key IsUnchanged decides on) whose ONLY changed fact between the
        // two uploads is containment. If IsUnchanged does not compare ContainmentDeclared, this
        // second merge reads as "nothing changed" and UpdateComponentAsync never runs, leaving
        // the stored column at its stale value forever.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cd-c-{Guid.NewGuid():N}");
        string versionId = await InsertProjectVersionAsync(orgId);

        await _merge.MergeComponentsAsync(orgId, versionId, Parse(declareContains: false), TestTime.KnownNow);
        Assert.False(await ContainmentDeclaredAsync(orgId, versionId));

        var counts = await _merge.MergeComponentsAsync(orgId, versionId, Parse(declareContains: true), TestTime.KnownNow);

        Assert.True(await ContainmentDeclaredAsync(orgId, versionId));
        // Zero, not one: IsUnchanged must have read this component as CHANGED (containment
        // flipped), so UpdateComponentAsync ran rather than the merge skipping it as identical.
        Assert.Equal(0, counts.Unchanged);
    }

    [Fact]
    public async Task ReUpload_FlipsContainmentDeclaredTrueToFalse_AndDoesNotCountAsUnchanged()
    {
        // The inverse direction of the same silent hole — a re-upload that DROPS a previously
        // declared CONTAINS edge must also be read as a real change, not skipped.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cd-d-{Guid.NewGuid():N}");
        string versionId = await InsertProjectVersionAsync(orgId);

        await _merge.MergeComponentsAsync(orgId, versionId, Parse(declareContains: true), TestTime.KnownNow);
        Assert.True(await ContainmentDeclaredAsync(orgId, versionId));

        var counts = await _merge.MergeComponentsAsync(orgId, versionId, Parse(declareContains: false), TestTime.KnownNow);

        Assert.False(await ContainmentDeclaredAsync(orgId, versionId));
        Assert.Equal(0, counts.Unchanged);
    }

    [Fact]
    public async Task ReUploadingAnUnchangedContainsDeclaration_StaysIdempotent()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cd-e-{Guid.NewGuid():N}");
        string versionId = await InsertProjectVersionAsync(orgId);

        await _merge.MergeComponentsAsync(orgId, versionId, Parse(declareContains: true), TestTime.KnownNow);
        var counts = await _merge.MergeComponentsAsync(orgId, versionId, Parse(declareContains: true), TestTime.KnownNow);

        Assert.Equal(0, counts.Added);
        Assert.Equal(1, counts.Unchanged);
        Assert.True(await ContainmentDeclaredAsync(orgId, versionId));
    }
}
