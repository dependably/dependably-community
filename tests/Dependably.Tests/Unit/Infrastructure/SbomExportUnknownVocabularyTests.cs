using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// CISA P2/P4/X4/D16c/D16d: component completeness (Coverage, distinct from the scan-coverage
/// properties <see cref="SbomExportFidelityTests"/> already pins), the two-state unknown/withheld
/// vocabulary's five "indicate unknown" sites, and the licence gaps #685 deferred — a URL fallback
/// for a licence with no SPDX identifier (D16c) and a best-effort proprietary-conditions marker
/// (D16d). Each test pairs a positive case (the property is present with the expected value) with
/// a negative one (the property is absent once the underlying field IS known) — the shape this
/// epic's own retrospective calls out: a test that only asserts the value a wrong mapping would
/// also produce pins nothing.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomExportUnknownVocabularyTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly SbomExportService _export;

    public SbomExportUnknownVocabularyTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        var tracker = new InstanceVulnTrackerConfig((_, _) => Task.FromResult<string?>(null), _clock);
        _export = new SbomExportService(_fixture.Store, _clock, new ProjectRepository(_fixture.Store, _clock), tracker, Dependably.Tests.Infrastructure.TestSbomAuthorSigner.Unconfigured(_fixture.Store, _clock));
    }

    private async Task<(string ProjectId, string VersionId)> SeedProjectVersionAsync(string orgId, string name)
    {
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO projects (id, org_id, kind, name, classifier, created_at)
            VALUES (@projectId, @orgId, 'project', @name, 'application', @now)
            """,
            new { projectId, orgId, name, now = _clock.GetUtcNow().ToUtcIso() });
        await conn.ExecuteAsync(
            """
            INSERT INTO project_versions (id, org_id, project_id, version, is_latest, created_at)
            VALUES (@versionId, @orgId, @projectId, '1.0.0', 1, @now)
            """,
            new { versionId, orgId, projectId, now = _clock.GetUtcNow().ToUtcIso() });
        return (projectId, versionId);
    }

    private async Task<string> InsertComponentAsync(
        string orgId, string versionId, string name,
        string? version = "1.0.0", string? versionRange = null, string? licenseSpdx = null,
        string? licenseUrl = null, bool? licenseNamed = null, string? componentProducer = null,
        string? componentHashes = null, string? toolName = null, string? toolVersion = null)
    {
        string id = Guid.NewGuid().ToString("N");
        string purl = $"pkg:npm/{name}@{version ?? "0"}";
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                 component_type, dependency_kind, version_range, license_spdx, license_url,
                 license_is_named, component_producer, component_hashes, created_at)
            VALUES
                (@id, @orgId, @versionId, @purl, 'npm', @name, @version, @name,
                 'library', 'direct', @versionRange, @licenseSpdx, @licenseUrl,
                 @licenseNamed, @componentProducer, @componentHashes, @now)
            """,
            new
            {
                id,
                orgId,
                versionId,
                purl,
                name,
                version,
                versionRange,
                licenseSpdx,
                licenseUrl,
                licenseNamed,
                componentProducer,
                componentHashes,
                now = _clock.GetUtcNow().ToUtcIso(),
            });

        if (toolName is not null)
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO project_documents
                    (id, org_id, project_version_id, doc_type, format, spec_version, blob_key,
                     sha256, size_bytes, tool_name, tool_version, uploaded_at)
                VALUES
                    (@id, @orgId, @versionId, 'sbom', 'cyclonedx-json', '1.6', 'blobkey',
                     'deadbeef', 10, @toolName, @toolVersion, @now)
                ON CONFLICT (project_version_id, doc_type) DO UPDATE SET
                    tool_name = excluded.tool_name, tool_version = excluded.tool_version
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId,
                    versionId,
                    toolName,
                    toolVersion,
                    now = _clock.GetUtcNow().ToUtcIso(),
                });
        }

        return id;
    }

    private static Dictionary<string, string> PropsOf(JsonElement entry) =>
        entry.TryGetProperty("properties", out var props)
            ? props.EnumerateArray()
                .ToDictionary(p => p.GetProperty("name").GetString()!, p => p.GetProperty("value").GetString()!)
            : new Dictionary<string, string>(StringComparer.Ordinal);

    private async Task<JsonElement> ExportComponentAsync(string orgId, string projectId, string versionId, string name)
    {
        string json = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("components").EnumerateArray()
            .Single(c => c.GetProperty("name").GetString() == name)
            .Clone();
    }

    // ── D10e: Component Producer ──────────────────────────────────────────────

    [Fact]
    public async Task AbsentProducer_EmitsUnknownProducerStatus_PresentProducer_OmitsIt()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"prod-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        await InsertComponentAsync(orgId, versionId, "no-producer");
        await InsertComponentAsync(orgId, versionId, "has-producer", componentProducer: "Acme Corp");

        var noProducer = PropsOf(await ExportComponentAsync(orgId, projectId, versionId, "no-producer"));
        Assert.Equal("unknown", noProducer[DependablyExportProperties.ProducerStatus]);

        var hasProducer = PropsOf(await ExportComponentAsync(orgId, projectId, versionId, "has-producer"));
        Assert.False(hasProducer.ContainsKey(DependablyExportProperties.ProducerStatus));
    }

    // ── D12a: Component Version ───────────────────────────────────────────────

    [Fact]
    public async Task AbsentVersionAndRange_EmitsUnknownVersionStatus()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"ver-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        await InsertComponentAsync(orgId, versionId, "no-version", version: null);

        var props = PropsOf(await ExportComponentAsync(orgId, projectId, versionId, "no-version"));
        Assert.Equal("unknown", props[DependablyExportProperties.VersionStatus]);
    }

    [Fact]
    public async Task VersionRangeExplainsAbsence_OmitsUnknownVersionStatus()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"ver-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        await InsertComponentAsync(orgId, versionId, "ranged", version: null, versionRange: "^1.0.0");

        var props = PropsOf(await ExportComponentAsync(orgId, projectId, versionId, "ranged"));
        Assert.False(props.ContainsKey(DependablyExportProperties.VersionStatus));
    }

    [Fact]
    public async Task FixedVersion_OmitsUnknownVersionStatus()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"ver-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        await InsertComponentAsync(orgId, versionId, "fixed", version: "2.0.0");

        var props = PropsOf(await ExportComponentAsync(orgId, projectId, versionId, "fixed"));
        Assert.False(props.ContainsKey(DependablyExportProperties.VersionStatus));
    }

    // ── D14d: Component Hash Value ────────────────────────────────────────────

    [Fact]
    public async Task NoHashAtAll_EmitsUnknownHashStatus_AssertedHashPresent_OmitsIt()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"hash-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        await InsertComponentAsync(orgId, versionId, "no-hash");
        await InsertComponentAsync(
            orgId, versionId, "has-hash",
            componentHashes: """[{"alg":"SHA-256","content":"deadbeefcafebabe0011223344556677deadbeefcafebabe0011223344556677"}]""");

        var noHash = PropsOf(await ExportComponentAsync(orgId, projectId, versionId, "no-hash"));
        Assert.Equal("unknown", noHash[DependablyExportProperties.HashStatus]);

        var hasHash = PropsOf(await ExportComponentAsync(orgId, projectId, versionId, "has-hash"));
        Assert.False(hasHash.ContainsKey(DependablyExportProperties.HashStatus));
    }

    // ── D16e/D16c/D16d: Component Licence ─────────────────────────────────────

    [Fact]
    public async Task AbsentLicense_EmitsUnknownLicenseStatus_PresentLicense_OmitsIt()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"lic-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        await InsertComponentAsync(orgId, versionId, "no-license");
        await InsertComponentAsync(orgId, versionId, "mit", licenseSpdx: "MIT");

        var noLicense = PropsOf(await ExportComponentAsync(orgId, projectId, versionId, "no-license"));
        Assert.Equal("unknown", noLicense[DependablyExportProperties.LicenseStatus]);

        var mit = PropsOf(await ExportComponentAsync(orgId, projectId, versionId, "mit"));
        Assert.False(mit.ContainsKey(DependablyExportProperties.LicenseStatus));
    }

    [Fact]
    public async Task LicenseRefToken_EmitsNonSpdxListedLicenseTrue_PlainSpdxId_OmitsIt()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"prop-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        await InsertComponentAsync(orgId, versionId, "custom-license", licenseSpdx: "LicenseRef-Acme-Custom");
        await InsertComponentAsync(orgId, versionId, "mit", licenseSpdx: "MIT");

        var custom = PropsOf(await ExportComponentAsync(orgId, projectId, versionId, "custom-license"));
        Assert.Equal("true", custom[DependablyExportProperties.NonSpdxListedLicense]);

        var mit = PropsOf(await ExportComponentAsync(orgId, projectId, versionId, "mit"));
        Assert.False(mit.ContainsKey(DependablyExportProperties.NonSpdxListedLicense));
    }

    /// <summary>
    /// D16d's own doc comment names this limit explicitly: a <c>LicenseRef-</c> token is SPDX's
    /// mechanism for referencing ANY licence outside the SPDX List, not only a proprietary one —
    /// scanners emit it for permissive/public-domain licences too. This pins that the property
    /// still fires (it observes "outside the SPDX List", not "proprietary"), which is the honest
    /// behaviour the renamed property documents rather than a false positive to fix.
    /// </summary>
    [Fact]
    public async Task LicenseRefToken_FiresForAPermissiveLicenceTooByDesign()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"prop-perm-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        await InsertComponentAsync(
            orgId, versionId, "public-domain", licenseSpdx: "LicenseRef-scancode-public-domain");

        var props = PropsOf(await ExportComponentAsync(orgId, projectId, versionId, "public-domain"));
        Assert.Equal("true", props[DependablyExportProperties.NonSpdxListedLicense]);
    }

    [Fact]
    public async Task NonSpdxLicenseWithUrl_EmitsNativeNameUrlShape_NotAnExpression()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"licurl-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        await InsertComponentAsync(
            orgId, versionId, "named-license",
            licenseSpdx: "Acme Software License", licenseUrl: "https://acme.example/license.txt",
            licenseNamed: true);
        await InsertComponentAsync(orgId, versionId, "mit", licenseSpdx: "MIT");

        var named = await ExportComponentAsync(orgId, projectId, versionId, "named-license");
        var namedLicenses = Assert.Single(named.GetProperty("licenses").EnumerateArray());
        Assert.False(namedLicenses.TryGetProperty("expression", out _));
        var licenseObj = namedLicenses.GetProperty("license");
        Assert.Equal("Acme Software License", licenseObj.GetProperty("name").GetString());
        Assert.Equal("https://acme.example/license.txt", licenseObj.GetProperty("url").GetString());

        var mit = await ExportComponentAsync(orgId, projectId, versionId, "mit");
        var mitLicense = Assert.Single(mit.GetProperty("licenses").EnumerateArray());
        Assert.Equal("MIT", mitLicense.GetProperty("expression").GetString());
        Assert.False(mitLicense.TryGetProperty("license", out _));
    }

    /// <summary>
    /// The exact defect the schema's own url-presence discriminator could not represent: a
    /// CycloneDX <c>{"license":{"name": …}}</c> entry — legal with NO <c>url</c> at all, and a
    /// very common real-world shape. Before <c>license_is_named</c> existed, this fell through to
    /// the expression arm and put free text in a field the schema defines as a valid SPDX licence
    /// expression — a "code right, data wrong" defect a schema-validity check alone cannot catch,
    /// because free text happens to still be a syntactically valid JSON string.
    /// </summary>
    [Fact]
    public async Task NonSpdxLicenseWithNoUrl_EmitsNativeNameOnlyShape_NeverAnExpression()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"licnourl-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        await InsertComponentAsync(
            orgId, versionId, "named-no-url",
            licenseSpdx: "Apache License 2.0 (custom notice)", licenseUrl: null, licenseNamed: true);

        var named = await ExportComponentAsync(orgId, projectId, versionId, "named-no-url");
        var namedLicenses = Assert.Single(named.GetProperty("licenses").EnumerateArray());
        Assert.False(namedLicenses.TryGetProperty("expression", out _));
        var licenseObj = namedLicenses.GetProperty("license");
        Assert.Equal("Apache License 2.0 (custom notice)", licenseObj.GetProperty("name").GetString());
        Assert.False(licenseObj.TryGetProperty("url", out _));
    }

    // ── D8b: SBOM Tool Version ────────────────────────────────────────────────

    [Fact]
    public async Task OriginalToolNamedNoVersion_EmitsToolVersionStatusOnItsOwnEntryOnly()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"tool-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        await InsertComponentAsync(orgId, versionId, "pkg", toolName: "cyclonedx-npm", toolVersion: null);

        string json = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        using var doc = JsonDocument.Parse(json);
        var tools = doc.RootElement.GetProperty("metadata").GetProperty("tools").GetProperty("components")
            .EnumerateArray().ToList();

        var original = Assert.Single(tools, t => t.GetProperty("name").GetString() == "cyclonedx-npm");
        Assert.False(original.TryGetProperty("version", out _));
        var originalProps = PropsOf(original);
        Assert.Equal("unknown", originalProps[DependablyExportProperties.ToolVersionStatus]);

        var dependably = Assert.Single(tools, t => t.GetProperty("name").GetString() == "dependably-community");
        Assert.True(dependably.TryGetProperty("version", out _));
        Assert.False(PropsOf(dependably).ContainsKey(DependablyExportProperties.ToolVersionStatus));
    }

    // ── P2/P2f: Coverage, distinct from scan coverage ─────────────────────────

    private static Dictionary<string, string> MetadataPropsOf(JsonDocument doc) =>
        doc.RootElement.GetProperty("metadata").GetProperty("properties").EnumerateArray()
            .ToDictionary(p => p.GetProperty("name").GetString()!, p => p.GetProperty("value").GetString()!);

    [Fact]
    public async Task UnfilteredNonEmptyDocument_FullInventoryRenderedTrue()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cov-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        await InsertComponentAsync(orgId, versionId, "pkg");

        string json = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var props = MetadataPropsOf(JsonDocument.Parse(json));

        Assert.Equal("all", props[DependablyExportProperties.ComponentFilter]);
        Assert.Equal("true", props[DependablyExportProperties.FullInventoryRendered]);
    }

    [Fact]
    public async Task FilteredDocument_FullInventoryRenderedFalse_DistinctFromScanCoverage()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cov-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        await InsertComponentAsync(orgId, versionId, "pkg");

        string json = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default with { Filter = SbomComponentFilter.Prod },
            CancellationToken.None))!;
        var props = MetadataPropsOf(JsonDocument.Parse(json));

        Assert.Equal("prod", props[DependablyExportProperties.ComponentFilter]);
        // The scan-coverage properties describe only how much of the KEPT set was scanned; they
        // say nothing about whether the document is narrowed, which is exactly the confusion
        // dependably:full-inventory-rendered exists to prevent.
        Assert.Equal("false", props[DependablyExportProperties.FullInventoryRendered]);
        Assert.True(props.ContainsKey(DependablyExportProperties.UnscannedCount));
    }

    /// <summary>
    /// The empty-set guard: an unfiltered render of a project version with ZERO components is
    /// NOT the same claim as a genuinely full, non-empty inventory — a project that has never had
    /// an SBOM's worth of dependencies recorded is indistinguishable, from this property alone,
    /// from one whose upload was simply incomplete.
    /// </summary>
    [Fact]
    public async Task UnfilteredButEmptyDocument_FullInventoryRenderedFalse()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cov-empty-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");

        string json = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;
        var props = MetadataPropsOf(JsonDocument.Parse(json));

        Assert.Equal("all", props[DependablyExportProperties.ComponentFilter]);
        Assert.Empty(JsonDocument.Parse(json).RootElement.GetProperty("components").EnumerateArray());
        Assert.Equal("false", props[DependablyExportProperties.FullInventoryRendered]);
    }

    /// <summary>
    /// A standalone VEX document asserts no <c>components[]</c> array of its own at all — it can
    /// never truthfully claim to render dependably's full component set, regardless of how many
    /// components the underlying project version has. This must hold even when the version's own
    /// inventory IS complete, because the claim is about what THIS document carries, not about
    /// what dependably separately knows.
    /// </summary>
    [Fact]
    public async Task StandaloneVexDocument_FullInventoryRenderedAlwaysFalse()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cov-vex-{Guid.NewGuid():N}"[..20]);
        var (projectId, versionId) = await SeedProjectVersionAsync(orgId, "app");
        await InsertComponentAsync(orgId, versionId, "pkg");

        string json = (await _export.BuildVexDocumentAsync(orgId, projectId, versionId, "1.7", CancellationToken.None))!;
        using var doc = JsonDocument.Parse(json);
        Assert.False(doc.RootElement.TryGetProperty("components", out _));
        var props = MetadataPropsOf(doc);

        Assert.Equal("all", props[DependablyExportProperties.ComponentFilter]);
        Assert.Equal("false", props[DependablyExportProperties.FullInventoryRendered]);
    }
}
