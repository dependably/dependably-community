using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;
using NJsonSchema;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// CISA D13 (Component Identifiers): identifiers a document asserts beside <c>purl</c> — CPE,
/// SWHID, OmniBOR, a commit hash, a UUID — survive the full ingest-merge-export pipeline for BOTH
/// CycloneDX and SPDX sources (not a hand-seeded row asserted only at the export boundary, which
/// would say nothing about whether the parsers or the merge actually carry the value). Seeds
/// values shaped the way a real producer writes them — a CPE with colons and asterisks, real
/// SWHID/gitoid syntax, a 40-hex commit hash, an RFC 4122 UUID — rather than convenient
/// placeholders, per the epic's own "seed the awkward values" lesson.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ComponentIdentifierBreadthTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly SbomIngestRepository _ingest;
    private readonly SbomMergeService _merge;
    private readonly SbomExportService _export;

    public ComponentIdentifierBreadthTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _ingest = new SbomIngestRepository(_fixture.Store);
        _merge = new SbomMergeService(_ingest);
        var tracker = new InstanceVulnTrackerConfig((_, _) => Task.FromResult<string?>(null), _clock);
        _export = new SbomExportService(
            _fixture.Store, _clock, new ProjectRepository(_fixture.Store, _clock), tracker,
            Dependably.Tests.Infrastructure.TestSbomAuthorSigner.Unconfigured(_fixture.Store, _clock));
    }

    private const string AwkwardCpe = "cpe:2.3:a:acme:widget_framework:1.0:*:*:*:enterprise:*:*:*";
    private const string Cpe22 = "cpe:/a:acme:widget_framework:1.0";
    private const string SwhidOne = "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2";
    private const string SwhidTwo = "swh:1:dir:d198bc9d7a6bcf6db04f476d29314f157507d505";
    private const string GitoidOne = "gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
    private const string CommitHashOne = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1";
    private const string CommitHashTwo = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
    private const string UuidUrnOne = "urn:uuid:550e8400-e29b-41d4-a716-446655440000";
    private const string UuidUrnTwo = "urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8";

    private static CycloneDxDocument ParseCycloneDx(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return CycloneDxParser.Parse(doc.RootElement);
    }

    private static JsonDocument ParseSpdx(string json, out CycloneDxDocument document)
    {
        var doc = JsonDocument.Parse(json);
        document = SpdxParser.Parse(doc.RootElement);
        return doc;
    }

    private async Task<(string OrgId, string ProjectId, string VersionId)> SeedProjectVersionAsync(string slug)
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"{slug}-{Guid.NewGuid():N}"[..30]);
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name) VALUES (@projectId, @orgId, @name)",
            new { projectId, orgId, name = $"proj-{projectId[..8]}" });
        await conn.ExecuteAsync(
            "INSERT INTO project_versions (id, org_id, project_id, version) VALUES (@versionId, @orgId, @projectId, '1.0.0')",
            new { versionId, orgId, projectId });
        return (orgId, projectId, versionId);
    }

    private static string CycloneDxInventory() => $$"""
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.7",
          "metadata": { "component": { "type": "application", "name": "app", "version": "1.0.0" } },
          "components": [
            {
              "type": "library", "name": "rich-widget", "version": "1.0.0",
              "purl": "pkg:npm/rich-widget@1.0.0",
              "cpe": "{{AwkwardCpe}}",
              "swhid": ["{{SwhidOne}}", "{{SwhidTwo}}"],
              "omniborId": ["{{GitoidOne}}"],
              "pedigree": { "commits": [ { "uid": "{{CommitHashOne}}" }, { "uid": "{{CommitHashTwo}}" } ] },
              "externalReferences": [
                { "type": "other", "url": "{{UuidUrnOne}}" },
                { "type": "other", "url": "{{UuidUrnTwo}}" }
              ]
            },
            {
              "type": "library", "name": "bare-widget", "version": "2.0.0"
            }
          ]
        }
        """;

    /// <summary>
    /// The mutant this catches: <c>BuildComponentObject</c> dropping the <c>cpe</c>/<c>swhid</c>/
    /// <c>omniborId</c> assignments (or <c>BuildComponentProperties</c> dropping the commit-hash/
    /// uuid disclosure loop) leaves this green on the ingest side and red only here, because
    /// nothing else in the suite renders a document from a component actually carrying these
    /// fields.
    /// </summary>
    [Fact]
    public async Task CycloneDx_RoundTrip_CarriesEveryIdentifierKindThroughToExport()
    {
        var (orgId, projectId, versionId) = await SeedProjectVersionAsync("cdx-id");
        await _merge.MergeComponentsAsync(orgId, versionId, ParseCycloneDx(CycloneDxInventory()), _clock.GetUtcNow());

        string json = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default with { SpecVersion = "1.7" },
            CancellationToken.None))!;
        using var doc = JsonDocument.Parse(json);
        var components = doc.RootElement.GetProperty("components").EnumerateArray().ToList();

        var rich = components.Single(c => c.GetProperty("name").GetString() == "rich-widget");
        Assert.Equal(AwkwardCpe, rich.GetProperty("cpe").GetString());
        var swhids = rich.GetProperty("swhid").EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Equal([SwhidOne, SwhidTwo], swhids);
        var omniborIds = rich.GetProperty("omniborId").EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Equal([GitoidOne], omniborIds);

        var richProps = rich.TryGetProperty("properties", out var richPropsEl)
            ? richPropsEl.EnumerateArray().ToList()
            : [];
        // D13d repeatability: BOTH asserted commit hashes and BOTH asserted UUIDs survive as
        // separate property entries — a fixture carrying only one of each could not distinguish
        // the correct repeatable emission from an implementation that only keeps the last (or
        // the first) match per kind.
        var commitHashValues = richProps
            .Where(p => p.GetProperty("name").GetString() == DependablyExportProperties.IdentifierCommitHash)
            .Select(p => p.GetProperty("value").GetString())
            .ToList();
        Assert.Equal([CommitHashOne, CommitHashTwo], commitHashValues);
        var uuidValues = richProps
            .Where(p => p.GetProperty("name").GetString() == DependablyExportProperties.IdentifierUuid)
            .Select(p => p.GetProperty("value").GetString())
            .ToList();
        Assert.Equal([UuidUrnOne, UuidUrnTwo], uuidValues);
        // Has a purl AND every other identifier kind — must NOT carry the D13a absence marker.
        Assert.DoesNotContain(richProps, p => p.GetProperty("name").GetString() == DependablyExportProperties.IdentifierStatus);

        var bare = components.Single(c => c.GetProperty("name").GetString() == "bare-widget");
        Assert.False(bare.TryGetProperty("purl", out _));
        Assert.False(bare.TryGetProperty("cpe", out _));
        Assert.False(bare.TryGetProperty("swhid", out _));
        Assert.False(bare.TryGetProperty("omniborId", out _));
        var bareProps = bare.GetProperty("properties").EnumerateArray().ToList();
        Assert.Contains(
            bareProps, p => p.GetProperty("name").GetString() == DependablyExportProperties.IdentifierStatus
                && p.GetProperty("value").GetString() == DependablyExportProperties.UnknownValue);
    }

    private static string SpdxInventory() => $$"""
        {
          "spdxVersion": "SPDX-2.3",
          "SPDXID": "SPDXRef-DOCUMENT",
          "name": "doc",
          "creationInfo": { "creators": [], "created": "2026-08-01T10:10:00Z" },
          "packages": [
            {
              "name": "spdx-widget", "SPDXID": "SPDXRef-Package-widget", "downloadLocation": "NOASSERTION",
              "externalRefs": [
                { "referenceCategory": "SECURITY", "referenceType": "cpe22Type", "referenceLocator": "{{Cpe22}}" },
                { "referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": "{{AwkwardCpe}}" },
                { "referenceCategory": "PERSISTENT-ID", "referenceType": "swh", "referenceLocator": "{{SwhidOne}}" },
                { "referenceCategory": "PERSISTENT-ID", "referenceType": "gitoid", "referenceLocator": "{{GitoidOne}}" },
                { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/spdx-widget@1.0.0" }
              ]
            }
          ]
        }
        """;

    /// <summary>
    /// The fixture asserts BOTH a <c>cpe22Type</c> and a <c>cpe23Type</c> SECURITY ref — standard
    /// real-world SPDX practice, and the shape D13d ("include all of them") names. The mutants
    /// this catches: (1) <c>SpdxParser.ReadAdditionalIdentifiers</c> mapping the WRONG
    /// (category, type) pair — e.g. swapping <c>swh</c>/<c>gitoid</c> — passes every OTHER test
    /// in the suite (nothing else asserts the SPDX identifier mapping) while silently mislabeling
    /// an asserted SWHID as an OmniBOR id or vice-versa; (2) deleting the <c>cpe22Type</c> arm
    /// entirely passes every OTHER fixture in the suite (they all carry <c>cpe23Type</c> only) and
    /// only shows up here; (3) dropping the CPE overflow disclosure loses the second CPE — the
    /// native <c>cpe</c> field can only ever hold one — leaving D13d unmet for exactly the
    /// document shape it is supposed to cover.
    /// </summary>
    [Fact]
    public async Task Spdx_RoundTrip_CarriesCpeSwhidAndOmniborThroughToExport()
    {
        var (orgId, projectId, versionId) = await SeedProjectVersionAsync("spdx-id");
        using var raw = ParseSpdx(SpdxInventory(), out var document);
        await _merge.MergeComponentsAsync(orgId, versionId, document, _clock.GetUtcNow());

        string json = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default with { SpecVersion = "1.7" },
            CancellationToken.None))!;
        using var doc = JsonDocument.Parse(json);
        var component = doc.RootElement.GetProperty("components").EnumerateArray()
            .Single(c => c.GetProperty("name").GetString() == "spdx-widget");

        // The FIRST asserted CPE (document order: cpe22Type) occupies the singular native field —
        // the less-precise form, exactly the case the finding names.
        Assert.Equal(Cpe22, component.GetProperty("cpe").GetString());
        Assert.Equal([SwhidOne], component.GetProperty("swhid").EnumerateArray().Select(e => e.GetString()).ToList());
        Assert.Equal([GitoidOne], component.GetProperty("omniborId").EnumerateArray().Select(e => e.GetString()).ToList());

        // D13d: the SECOND CPE (cpe23Type — the more precise form) must still survive the render,
        // disclosed via the dependably:identifier:cpe overflow property rather than dropped.
        var properties = component.GetProperty("properties").EnumerateArray().ToList();
        Assert.Contains(
            properties, p => p.GetProperty("name").GetString() == DependablyExportProperties.IdentifierCpe
                && p.GetProperty("value").GetString() == AwkwardCpe);
    }

    // ── schema validation on the awkward values ─────────────────────────────────

    private static readonly Lazy<Task<JsonSchema>> Schema17 = new(() => JsonSchema.FromFileAsync(
        Path.Combine(FixtureManifest.CycloneDxSchemaFixturesRoot, "bom-1.7.schema.json")));
    private static readonly Lazy<Task<JsonSchema>> Schema16 = new(() => JsonSchema.FromFileAsync(
        Path.Combine(FixtureManifest.CycloneDxSchemaFixturesRoot, "bom-1.6.schema.json")));

    /// <summary>
    /// The finding this pins: <c>cpe</c>/<c>swhid</c>/<c>omniborId</c> are legal component fields
    /// under BOTH 1.6 and 1.7 (unlike <c>versionRange</c>/<c>isExternal</c>, which are 1.7-only),
    /// so nothing in <c>BuildComponentObject</c> may version-gate them the way those two fields
    /// are gated — a mutant that added such a gate would still pass every OTHER schema test
    /// (none of them seeds a component carrying these fields) and only show up here.
    /// </summary>
    [Theory]
    [InlineData("1.6")]
    [InlineData("1.7")]
    public async Task ExportedDocument_WithAwkwardIdentifierValues_ValidatesAgainstTheOfficialSchema(string specVersion)
    {
        var (orgId, projectId, versionId) = await SeedProjectVersionAsync($"schema-id-{specVersion.Replace('.', '-')}");
        await _merge.MergeComponentsAsync(orgId, versionId, ParseCycloneDx(CycloneDxInventory()), _clock.GetUtcNow());

        string json = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default with { SpecVersion = specVersion },
            CancellationToken.None))!;

        var schema = await (specVersion == "1.6" ? Schema16.Value : Schema17.Value);
        var errors = schema.Validate(json);
        Assert.True(errors.Count == 0, $"CycloneDX {specVersion} schema validation failed:\n" + string.Join('\n', errors));
    }
}
