using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Sbom;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;
using NJsonSchema;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Validates a rendered document against the OFFICIAL CycloneDX JSON schema — the ground truth no
/// other test in this suite checks. An `alg` spelling, an enum value, or a field shape can be
/// wrong in a way that every hand-written string assertion in <see cref="SbomExportFidelityTests"/>
/// still agrees with (because the assertion was written to match the same bug the implementation
/// has), and 9,780 passing unit tests said nothing about it: exporting `"alg": "sha-256"` — not a
/// member of CycloneDX's closed <c>hash-alg</c> enum — passed the full suite until this file
/// existed. Schema validation is what catches that class of defect independently of what any one
/// test author expected the output to look like.
///
/// <para>The two schema files are the real CycloneDX 1.6/1.7 schemas, extracted from the
/// <c>CycloneDX</c> NuGet package's embedded resources — see
/// <c>Fixtures/cyclonedx-schema/README.md</c> for exactly how and why.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomExportSchemaValidationTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly SbomExportService _export;

    public SbomExportSchemaValidationTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        var tracker = new InstanceVulnTrackerConfig((_, _) => Task.FromResult<string?>(null), _clock);
        _export = new SbomExportService(_fixture.Store, _clock, new ProjectRepository(_fixture.Store, _clock), tracker, Dependably.Tests.Infrastructure.TestSbomAuthorSigner.Unconfigured(_fixture.Store, _clock));
    }

    // Schema parsing (including resolving the cryptography-defs/jsf/spdx external $refs) costs
    // real wall-clock time, and every case in this file validates against one of exactly two
    // schemas — loaded once each and shared across the whole test class rather than once per case.
    private static readonly Lazy<Task<JsonSchema>> Schema16 = new(() => JsonSchema.FromFileAsync(
        Path.Combine(FixtureManifest.CycloneDxSchemaFixturesRoot, "bom-1.6.schema.json")));
    private static readonly Lazy<Task<JsonSchema>> Schema17 = new(() => JsonSchema.FromFileAsync(
        Path.Combine(FixtureManifest.CycloneDxSchemaFixturesRoot, "bom-1.7.schema.json")));

    private static Task<JsonSchema> SchemaForAsync(string specVersion) => specVersion switch
    {
        "1.6" => Schema16.Value,
        "1.7" => Schema17.Value,
        _ => throw new ArgumentOutOfRangeException(nameof(specVersion), specVersion, "no fixture schema for this spec version"),
    };

    private static async Task AssertValidCycloneDxAsync(string json, string specVersion)
    {
        var schema = await SchemaForAsync(specVersion);
        var errors = schema.Validate(json);
        Assert.True(
            errors.Count == 0,
            $"CycloneDX {specVersion} schema validation failed:\n" + string.Join('\n', errors));
    }

    /// <summary>
    /// CISA D2 (SBOM Author Signature): a signed export still validates against both spec
    /// versions' official schema — which itself $refs jsf-0.82.schema.json#/definitions/signature,
    /// so this is the one place a JSF wire-shape mistake (a stray <c>publicKey</c>, a malformed
    /// <c>value</c>, an <c>algorithm</c> outside JWA's enum) would actually be caught, rather than
    /// only by a hand-written assertion that agrees with whatever the implementation happens to
    /// emit. Also pins that <c>dependably:signature-state</c> reads "signed" — the property this
    /// element's own honesty duty requires — and that no <c>publicKey</c> is embedded, per the
    /// ADR's "an embedded key turns a signature into a checksum" rule.
    /// </summary>
    [Theory]
    [InlineData("1.6")]
    [InlineData("1.7")]
    public async Task SignedExport_StillValidatesAgainstTheOfficialSchema_AndDeclaresSignedState(string specVersion)
    {
        string orgId = await OrgSeeder.InsertAsync(
            _fixture.Store, $"schema-sig-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedOneComponentAsync(orgId, "library", componentHashesJson: null);

        var tracker = new InstanceVulnTrackerConfig((_, _) => Task.FromResult<string?>(null), _clock);
        var signedExport = new SbomExportService(
            _fixture.Store, _clock, new ProjectRepository(_fixture.Store, _clock), tracker,
            TestSbomAuthorSigner.Configured(_fixture.Store, _clock));

        string json = (await signedExport.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default with { SpecVersion = specVersion },
            CancellationToken.None))!;

        await AssertValidCycloneDxAsync(json, specVersion);

        using var doc = JsonDocument.Parse(json);
        var signature = doc.RootElement.GetProperty("signature");
        Assert.Equal("ES256", signature.GetProperty("algorithm").GetString());
        Assert.Equal(64, signature.GetProperty("keyId").GetString()!.Length);
        Assert.True(signature.GetProperty("value").GetString()!.Length > 0);
        Assert.False(signature.TryGetProperty("publicKey", out _));

        var properties = doc.RootElement.GetProperty("metadata").GetProperty("properties");
        bool sawSignedState = false;
        foreach (var prop in properties.EnumerateArray())
        {
            if (prop.GetProperty("name").GetString() == "dependably:signature-state")
            {
                Assert.Equal("signed", prop.GetProperty("value").GetString());
                sawSignedState = true;
            }
        }

        Assert.True(sawSignedState, "dependably:signature-state property was not emitted");
    }

    /// <summary>
    /// The adversarial twin: an install with no <c>DEPENDABLY_MASTER_KEY</c> renders no
    /// <c>signature</c> member at all — carrying <c>unsigned-no-master-key</c> instead of silently
    /// omitting the statement, per ADR-sbom-author-signature's "an export without a key is
    /// unsigned, not refused" decision.
    /// </summary>
    [Fact]
    public async Task UnconfiguredExport_CarriesNoSignatureMember_AndDeclaresUnsignedState()
    {
        string orgId = await OrgSeeder.InsertAsync(
            _fixture.Store, $"schema-unsig-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedOneComponentAsync(orgId, "library", componentHashesJson: null);

        string json = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default with { SpecVersion = "1.6" },
            CancellationToken.None))!;

        await AssertValidCycloneDxAsync(json, "1.6");

        using var doc = JsonDocument.Parse(json);
        Assert.False(doc.RootElement.TryGetProperty("signature", out _));

        var properties = doc.RootElement.GetProperty("metadata").GetProperty("properties");
        bool sawUnsignedState = false;
        foreach (var prop in properties.EnumerateArray())
        {
            if (prop.GetProperty("name").GetString() == "dependably:signature-state")
            {
                Assert.Equal("unsigned-no-master-key", prop.GetProperty("value").GetString());
                sawUnsignedState = true;
            }
        }

        Assert.True(sawUnsignedState, "dependably:signature-state property was not emitted");
    }

    /// <summary>
    /// The genuine interaction gap: signature, additional identifiers (native <c>cpe</c>/
    /// <c>swhid</c>/<c>omniborId</c>), a name-only licence, and the X4 absence properties (no
    /// producer, no version, no hash) each validate individually elsewhere in this suite — but
    /// never together, on the same component, in the same document. A mutant that reorders
    /// <c>BuildComponentObject</c>'s optional branches (e.g. attaching the signature before the
    /// identifier/absence properties are appended, so the signed content differs from what a
    /// consumer re-hashes) or that lets two of these optional shapes clobber each other's JSON key
    /// would still pass every single-concern fixture in this suite and only show up here.
    /// </summary>
    [Theory]
    [InlineData("1.6")]
    [InlineData("1.7")]
    public async Task CombinedFixture_SignatureIdentifiersNameOnlyLicenseAndAbsenceProperties_ValidatesAgainstTheOfficialSchema(string specVersion)
    {
        const string cpe = "cpe:2.3:a:acme:combo_widget:1.0:*:*:*:*:*:*:*";
        const string swhid = "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2";
        const string omniborId = "gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";

        string orgId = await OrgSeeder.InsertAsync(
            _fixture.Store, $"schema-combo-{specVersion.Replace('.', '-')}-{Guid.NewGuid():N}"[..30]);
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO projects (id, org_id, kind, name, classifier, created_at)
                VALUES (@projectId, @orgId, 'project', 'combo-app', 'application', @now)
                """,
                new { projectId, orgId, now = _clock.GetUtcNow().ToUtcIso() });
            await conn.ExecuteAsync(
                """
                INSERT INTO project_versions (id, org_id, project_id, version, is_latest, created_at)
                VALUES (@versionId, @orgId, @projectId, '1.0.0', 1, @now)
                """,
                new { versionId, orgId, projectId, now = _clock.GetUtcNow().ToUtcIso() });
            await conn.ExecuteAsync(
                """
                INSERT INTO sbom_components
                    (id, org_id, project_version_id, purl, ecosystem, purl_name, name,
                     component_type, sbom_scope, dependency_kind, dependency_path,
                     license_spdx, license_is_named, additional_identifiers, created_at)
                VALUES
                    (@id, @orgId, @versionId, 'pkg:npm/combo-widget', 'npm', 'combo-widget', 'combo-widget',
                     'library', 'required', 'direct', '["pkg:npm/combo-widget"]',
                     'Acme Custom License', 1, @additionalIdentifiers, @now)
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId,
                    versionId,
                    additionalIdentifiers = JsonSerializer.Serialize(new[]
                    {
                        new { kind = "cpe", value = cpe },
                        new { kind = "swhid", value = swhid },
                        new { kind = "omnibor", value = omniborId },
                    }),
                    now = _clock.GetUtcNow().ToUtcIso(),
                });
        }

        var tracker = new InstanceVulnTrackerConfig((_, _) => Task.FromResult<string?>(null), _clock);
        var signedExport = new SbomExportService(
            _fixture.Store, _clock, new ProjectRepository(_fixture.Store, _clock), tracker,
            TestSbomAuthorSigner.Configured(_fixture.Store, _clock));

        string json = (await signedExport.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default with { SpecVersion = specVersion },
            CancellationToken.None))!;

        await AssertValidCycloneDxAsync(json, specVersion);

        using var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("signature", out _), "signature member was not emitted");

        var component = doc.RootElement.GetProperty("components").EnumerateArray().Single();
        Assert.Equal(cpe, component.GetProperty("cpe").GetString());
        Assert.Equal([swhid], component.GetProperty("swhid").EnumerateArray().Select(e => e.GetString()).ToList());
        Assert.Equal([omniborId], component.GetProperty("omniborId").EnumerateArray().Select(e => e.GetString()).ToList());

        var license = Assert.Single(component.GetProperty("licenses").EnumerateArray());
        Assert.Equal("Acme Custom License", license.GetProperty("license").GetProperty("name").GetString());
        Assert.False(license.GetProperty("license").TryGetProperty("id", out _));

        var props = component.TryGetProperty("properties", out var propsEl)
            ? propsEl.EnumerateArray().Select(p => p.GetProperty("name").GetString()).ToList()
            : [];
        // No producer/version/hash was ever asserted for this component — all three absence
        // markers fire alongside the signature and the native identifiers above.
        Assert.Contains(DependablyExportProperties.ProducerStatus, props);
        Assert.Contains(DependablyExportProperties.VersionStatus, props);
        Assert.Contains(DependablyExportProperties.HashStatus, props);
        // The component DOES carry an identifier (cpe/swhid/omniborId) and a licence — those two
        // absence markers must NOT also fire.
        Assert.DoesNotContain(DependablyExportProperties.IdentifierStatus, props);
        Assert.DoesNotContain(DependablyExportProperties.LicenseStatus, props);
    }

    /// <summary>
    /// One project version carrying everything this issue's fields touch: a hosted component
    /// (dependably's own digest wins natively, the document's own asserted hash is disclosed
    /// separately), a third-party component (its own asserted hash, in two algorithms, is
    /// emitted natively), a declared producer distinct from nothing dependably invents, and one
    /// advisory linked for the VDR variant — a genuinely realistic document, not a one-field
    /// smoke fixture.
    /// </summary>
    private async Task<(string ProjectId, string VersionId)> SeedRealisticDocumentAsync(string orgId)
    {
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO projects (id, org_id, kind, name, classifier, created_at)
            VALUES (@projectId, @orgId, 'project', 'schema-check-app', 'application', @now)
            """,
            new { projectId, orgId, now = _clock.GetUtcNow().ToUtcIso() });
        await conn.ExecuteAsync(
            """
            INSERT INTO project_versions (id, org_id, project_id, version, is_latest, created_at)
            VALUES (@versionId, @orgId, @projectId, '1.0.0', 1, @now)
            """,
            new { versionId, orgId, projectId, now = _clock.GetUtcNow().ToUtcIso() });

        string hostedId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                 component_type, sbom_scope, dependency_kind, dependency_path, license_spdx,
                 component_producer, component_hashes, created_at)
            VALUES
                (@id, @orgId, @versionId, 'pkg:npm/hosted-pkg@1.0.0', 'npm', 'hosted-pkg', '1.0.0', 'hosted-pkg',
                 'library', 'required', 'direct', '["pkg:npm/hosted-pkg@1.0.0"]', 'MIT',
                 'Acme Corp', @componentHashes, @now)
            """,
            new
            {
                id = hostedId,
                orgId,
                versionId,
                // A 64-hex-char SHA-256 asserted value, deliberately different from the hosted
                // package's own checksum below — this is the value that must end up disclosed
                // via dependably:asserted-hashes, never in the native hashes[] field.
                componentHashes = """[{"alg":"SHA-256","content":"cafebabedeadbeef00112233cafebabedeadbeef00112233cafebabedeadbeef"}]""",
                now = _clock.GetUtcNow().ToUtcIso(),
            });
        string packageId = Guid.NewGuid().ToString("N");
        string packageVersionId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, created_at) VALUES (@packageId, @orgId, 'npm', 'hosted-pkg', 'hosted-pkg', @now)",
            new { packageId, orgId, now = _clock.GetUtcNow().ToUtcIso() });
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, checksum_sha256, origin, created_at)
            VALUES (@packageVersionId, @packageId, '1.0.0', 'pkg:npm/hosted-pkg@1.0.0', 'registry/npm/hosted-pkg/1.0.0',
                    @checksumSha256, 'uploaded', @now)
            """,
            new
            {
                packageVersionId,
                packageId,
                // A full 64-hex-char SHA-256 — dependably's own claim, which wins natively.
                checksumSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                now = _clock.GetUtcNow().ToUtcIso(),
            });

        string thirdPartyId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                 component_type, sbom_scope, dependency_kind, dependency_path, license_spdx,
                 component_hashes, created_at)
            VALUES
                (@id, @orgId, @versionId, 'pkg:npm/third-party@2.0.0', 'npm', 'third-party', '2.0.0', 'third-party',
                 'library', 'required', 'direct', '["pkg:npm/third-party@2.0.0"]', 'Apache-2.0',
                 @componentHashes, @now)
            """,
            new
            {
                id = thirdPartyId,
                orgId,
                versionId,
                // A 64-hex-char SHA-256 and a 40-hex-char SHA-1, both correctly sized for their
                // declared algorithm — this component has no own-digest match, so both are
                // emitted natively, verbatim, in components[].hashes.
                componentHashes =
                    """[{"alg":"SHA-256","content":"deadbeefcafebabe0011223344556677deadbeefcafebabe0011223344556677"},{"alg":"SHA-1","content":"deadbeefcafebabe0011223344556677deadbeef"}]""",
                now = _clock.GetUtcNow().ToUtcIso(),
            });

        string vulnId = Guid.NewGuid().ToString("N");
        // osv_id is globally unique and this fixture is shared across every case in the [Theory]
        // below (one InMemoryDbFixture per test class, not per case), so each seed needs its own.
        string osvId = $"CVE-2100-{Guid.NewGuid():N}"[..18];
        await conn.ExecuteAsync(
            """
            INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name, severity, cvss_score, fetched_at)
            VALUES (@vulnId, @osvId, 'npm', 'third-party', 'HIGH', 7.5, @now)
            """,
            new { vulnId, osvId, now = _clock.GetUtcNow().ToUtcIso() });
        await conn.ExecuteAsync(
            "INSERT INTO sbom_component_vulns (id, component_id, vuln_id, checked_at) VALUES (@id, @thirdPartyId, @vulnId, @now)",
            new { id = Guid.NewGuid().ToString("N"), thirdPartyId, vulnId, now = _clock.GetUtcNow().ToUtcIso() });

        return (projectId, versionId);
    }

    [Theory]
    [InlineData("inventory", "1.6")]
    [InlineData("inventory", "1.7")]
    [InlineData("vdr", "1.6")]
    [InlineData("vdr", "1.7")]
    public async Task ExportedDocument_ValidatesAgainstTheOfficialCycloneDxSchema(string variant, string specVersion)
    {
        string orgId = await OrgSeeder.InsertAsync(
            _fixture.Store, $"schema-{variant}-{specVersion.Replace('.', '-')}-{Guid.NewGuid():N}"[..30]);
        var (projectId, versionId) = await SeedRealisticDocumentAsync(orgId);

        string json = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId,
            SbomExportOptions.Default with { Variant = variant, SpecVersion = specVersion },
            CancellationToken.None))!;

        await AssertValidCycloneDxAsync(json, specVersion);
    }

    /// <summary>
    /// D9d (RFC 9562): every renderer's <c>serialNumber</c> must validate against the schema's own
    /// UUID pattern — including the persisted, re-used-across-renders serial D6/D9 introduced,
    /// never only a freshly minted <c>Guid.NewGuid()</c> a hand-written string assertion would
    /// happen to agree with. Rendering twice under the SAME spec version pins that a repeat render
    /// is idempotent; rendering the SAME seeded project version again under the OTHER spec version
    /// (same org, same project, same version id — not a second seed) pins that a spec-version
    /// switch alone does not disturb the stored revision identity, which is the actual claim
    /// "shares one revision line" makes — two <c>[Theory]</c> cases each seeding their own org
    /// would never touch the same <c>sbom_export_revisions</c> row and would prove nothing about
    /// that claim.
    /// </summary>
    [Fact]
    public async Task RenderedDocument_SerialNumberValidatesAgainstTheSchemasUuidPattern_AndSurvivesASpecVersionSwitch()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"schema-serial-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedRealisticDocumentAsync(orgId);

        string json16 = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default with { SpecVersion = "1.6" },
            CancellationToken.None))!;
        await AssertValidCycloneDxAsync(json16, "1.6");

        string json16Again = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default with { SpecVersion = "1.6" },
            CancellationToken.None))!;
        await AssertValidCycloneDxAsync(json16Again, "1.6");

        string json17 = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default with { SpecVersion = "1.7" },
            CancellationToken.None))!;
        await AssertValidCycloneDxAsync(json17, "1.7");

        using var doc16 = JsonDocument.Parse(json16);
        using var doc16Again = JsonDocument.Parse(json16Again);
        using var doc17 = JsonDocument.Parse(json17);

        string serial16 = doc16.RootElement.GetProperty("serialNumber").GetString()!;
        Assert.Matches("^urn:uuid:[0-9a-f-]{36}$", serial16);
        Assert.Equal(serial16, doc16Again.RootElement.GetProperty("serialNumber").GetString());
        Assert.Equal(serial16, doc17.RootElement.GetProperty("serialNumber").GetString());
        Assert.Equal(
            doc16.RootElement.GetProperty("version").GetInt32(),
            doc16Again.RootElement.GetProperty("version").GetInt32());
        Assert.Equal(
            doc16.RootElement.GetProperty("version").GetInt32(),
            doc17.RootElement.GetProperty("version").GetInt32());
    }

    /// <summary>
    /// The finding this pins: an uploaded document's asserted <c>alg</c> is not validated against
    /// any vocabulary at ingest, so a real document can assert a spelling the TARGET render's spec
    /// version does not admit — CISA's own suggested lowercase form (<c>sha-256</c>), or a 1.7-only
    /// algorithm (<c>Streebog-256</c>) re-rendered under 1.6. Both must still produce a
    /// schema-valid document: the non-member entry is excluded from the native <c>hashes[]</c>
    /// field rather than emitted invalid.
    /// </summary>
    [Theory]
    [InlineData("sha-256", "1.6")]
    [InlineData("sha-256", "1.7")]
    [InlineData("Streebog-256", "1.6")]
    [InlineData("Streebog-256", "1.7")]
    public async Task AssertedAlgOutsideTargetEnum_StillValidatesAgainstTheOfficialSchema(string alg, string specVersion)
    {
        string orgId = await OrgSeeder.InsertAsync(
            _fixture.Store, $"schema-alg-{Guid.NewGuid():N}"[..24]);
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO projects (id, org_id, kind, name, classifier, created_at)
                VALUES (@projectId, @orgId, 'project', 'alg-check-app', 'application', @now)
                """,
                new { projectId, orgId, now = _clock.GetUtcNow().ToUtcIso() });
            await conn.ExecuteAsync(
                """
                INSERT INTO project_versions (id, org_id, project_id, version, is_latest, created_at)
                VALUES (@versionId, @orgId, @projectId, '1.0.0', 1, @now)
                """,
                new { versionId, orgId, projectId, now = _clock.GetUtcNow().ToUtcIso() });
            await conn.ExecuteAsync(
                """
                INSERT INTO sbom_components
                    (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                     component_type, sbom_scope, dependency_kind, dependency_path, component_hashes, created_at)
                VALUES
                    (@id, @orgId, @versionId, 'pkg:npm/alg-check@1.0.0', 'npm', 'alg-check', '1.0.0', 'alg-check',
                     'library', 'required', 'direct', '["pkg:npm/alg-check@1.0.0"]', @componentHashes, @now)
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId,
                    versionId,
                    componentHashes = JsonSerializer.Serialize(new[]
                    {
                        new { alg, content = "deadbeefcafebabe0011223344556677deadbeefcafebabe0011223344556677" },
                    }),
                    now = _clock.GetUtcNow().ToUtcIso(),
                });
        }

        string json = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default with { SpecVersion = specVersion }, CancellationToken.None))!;

        await AssertValidCycloneDxAsync(json, specVersion);
    }

    /// <summary>
    /// D16c/D16d: a component whose licence has no SPDX identifier (both the name+url form and
    /// the equally legal name-ONLY form, with no url at all) and a component whose licence
    /// carries an SPDX <c>LicenseRef-</c> token all still validate, under both spec versions —
    /// the shapes <see cref="SbomExportService"/> switches to are native CycloneDX
    /// <c>licenseChoice</c> forms, not properties[] disclosures.
    /// </summary>
    [Theory]
    [InlineData("1.6")]
    [InlineData("1.7")]
    public async Task LicenseUrlFallbackAndProprietaryMarker_StillValidateAgainstTheOfficialSchema(string specVersion)
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"schema-lic-{specVersion.Replace('.', '-')}-{Guid.NewGuid():N}"[..30]);
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO projects (id, org_id, kind, name, classifier, created_at)
                VALUES (@projectId, @orgId, 'project', 'lic-check-app', 'application', @now)
                """,
                new { projectId, orgId, now = _clock.GetUtcNow().ToUtcIso() });
            await conn.ExecuteAsync(
                """
                INSERT INTO project_versions (id, org_id, project_id, version, is_latest, created_at)
                VALUES (@versionId, @orgId, @projectId, '1.0.0', 1, @now)
                """,
                new { versionId, orgId, projectId, now = _clock.GetUtcNow().ToUtcIso() });
            await conn.ExecuteAsync(
                """
                INSERT INTO sbom_components
                    (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                     component_type, sbom_scope, dependency_kind, dependency_path,
                     license_spdx, license_url, license_is_named, created_at)
                VALUES
                    (@id, @orgId, @versionId, 'pkg:npm/named-license@1.0.0', 'npm', 'named-license', '1.0.0', 'named-license',
                     'library', 'required', 'direct', '["pkg:npm/named-license@1.0.0"]',
                     'Acme Software License', 'https://acme.example/license.txt', 1, @now)
                """,
                new { id = Guid.NewGuid().ToString("N"), orgId, versionId, now = _clock.GetUtcNow().ToUtcIso() });
            // The no-URL name-only shape — legal CycloneDX, and the one the url-presence-only
            // discriminator used to misrender as a bare SPDX expression.
            await conn.ExecuteAsync(
                """
                INSERT INTO sbom_components
                    (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                     component_type, sbom_scope, dependency_kind, dependency_path,
                     license_spdx, license_is_named, created_at)
                VALUES
                    (@id, @orgId, @versionId, 'pkg:npm/named-no-url@1.0.0', 'npm', 'named-no-url', '1.0.0', 'named-no-url',
                     'library', 'required', 'direct', '["pkg:npm/named-no-url@1.0.0"]',
                     'Apache License 2.0 (custom notice)', 1, @now)
                """,
                new { id = Guid.NewGuid().ToString("N"), orgId, versionId, now = _clock.GetUtcNow().ToUtcIso() });
            await conn.ExecuteAsync(
                """
                INSERT INTO sbom_components
                    (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                     component_type, sbom_scope, dependency_kind, dependency_path,
                     license_spdx, created_at)
                VALUES
                    (@id, @orgId, @versionId, 'pkg:npm/custom-license@1.0.0', 'npm', 'custom-license', '1.0.0', 'custom-license',
                     'library', 'required', 'direct', '["pkg:npm/custom-license@1.0.0"]',
                     'LicenseRef-Acme-Custom', @now)
                """,
                new { id = Guid.NewGuid().ToString("N"), orgId, versionId, now = _clock.GetUtcNow().ToUtcIso() });
        }

        string json = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default with { SpecVersion = specVersion }, CancellationToken.None))!;

        await AssertValidCycloneDxAsync(json, specVersion);
    }

    // Seeds one project version holding exactly one component, for the two SPDX-specific findings
    // below — neither needs the richer multi-component fixture SeedRealisticDocumentAsync builds.
    private async Task<(string ProjectId, string VersionId)> SeedOneComponentAsync(
        string orgId, string? componentType, string? componentHashesJson)
    {
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO projects (id, org_id, kind, name, classifier, created_at)
            VALUES (@projectId, @orgId, 'project', 'spdx-check-app', 'application', @now)
            """,
            new { projectId, orgId, now = _clock.GetUtcNow().ToUtcIso() });
        await conn.ExecuteAsync(
            """
            INSERT INTO project_versions (id, org_id, project_id, version, is_latest, created_at)
            VALUES (@versionId, @orgId, @projectId, '1.0.0', 1, @now)
            """,
            new { versionId, orgId, projectId, now = _clock.GetUtcNow().ToUtcIso() });
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                 component_type, sbom_scope, dependency_kind, dependency_path, component_hashes, created_at)
            VALUES
                (@id, @orgId, @versionId, 'pkg:npm/spdx-check@1.0.0', 'npm', 'spdx-check', '1.0.0', 'spdx-check',
                 @componentType, 'required', 'direct', '["pkg:npm/spdx-check@1.0.0"]', @componentHashesJson, @now)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId,
                versionId,
                componentType,
                componentHashesJson,
                now = _clock.GetUtcNow().ToUtcIso(),
            });

        return (projectId, versionId);
    }

    /// <summary>
    /// The finding this pins: <see cref="SpdxParser"/> stores an asserted checksum's algorithm
    /// verbatim in SPDX's own spelling (<c>SHA1</c>/<c>SHA256</c>/<c>SHA512</c>), which is not a
    /// member of CycloneDX's closed <c>hash-alg</c> enum (<c>SHA-1</c>/<c>SHA-256</c>/
    /// <c>SHA-512</c>). Without <c>SbomExportService.AssertedAlgAliases</c> translating it first,
    /// the native filter recognises none of it, <c>hashesArr</c> stays null, and the component
    /// exports with no <c>hashes</c> field at all — a silent D14/D15 downgrade an
    /// absence-tolerant schema would not otherwise reveal, which is why this asserts the
    /// translated entry explicitly rather than schema-validating alone.
    /// </summary>
    [Theory]
    [InlineData("SHA1", "SHA-1")]
    [InlineData("SHA256", "SHA-256")]
    [InlineData("SHA512", "SHA-512")]
    public async Task SpdxAssertedAlg_TranslatesOntoTheCycloneDxEnumSpelling_AndExportSchemaValidates(
        string spdxAlg, string expectedCycloneDxAlg)
    {
        const string content = "deadbeefcafebabe0011223344556677deadbeefcafebabe0011223344556677";
        string document = $$"""
            {
              "spdxVersion": "SPDX-2.3",
              "SPDXID": "SPDXRef-DOCUMENT",
              "name": "doc",
              "creationInfo": { "creators": [], "created": "2026-08-01T10:10:00Z" },
              "packages": [
                { "name": "spdx-check", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION",
                  "checksums": [ { "algorithm": "{{spdxAlg}}", "checksumValue": "{{content}}" } ] }
              ]
            }
            """;
        var parsed = SpdxParser.Parse(JsonDocument.Parse(document).RootElement);
        string? hashesJson = Assert.Single(parsed.Components).HashesJson;
        Assert.NotNull(hashesJson);

        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"spdx-alg-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedOneComponentAsync(
            orgId, componentType: null, componentHashesJson: hashesJson);

        string json = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;

        await AssertValidCycloneDxAsync(json, "1.7");

        using var doc = JsonDocument.Parse(json);
        var component = doc.RootElement.GetProperty("components").EnumerateArray()
            .Single(c => c.GetProperty("name").GetString() == "spdx-check");
        var hash = Assert.Single(component.GetProperty("hashes").EnumerateArray());
        Assert.Equal(expectedCycloneDxAlg, hash.GetProperty("alg").GetString());
        Assert.Equal(content, hash.GetProperty("content").GetString());
    }

    /// <summary>
    /// The finding this pins: SPDX 2.3's <c>primaryPackagePurpose</c> admits four values
    /// (SOURCE/ARCHIVE/INSTALL/OTHER) CycloneDX's closed <c>component.type</c> enum has no member
    /// for. <c>component_type</c> is exported verbatim with no enum guard of its own
    /// (<c>c.ComponentType ?? "library"</c>), so a mapping that passes an unmapped purpose through
    /// — even lower-cased — makes every subsequent export of the project version invalid
    /// CycloneDX. <see cref="SpdxParser"/>'s own mapping is asserted directly first (so the mutant
    /// this exists to catch — passing the raw purpose through — fails immediately rather than
    /// only inside the schema validator), then the resulting export is schema-validated.
    /// </summary>
    [Theory]
    [InlineData("LIBRARY", "library")]
    [InlineData("OPERATING-SYSTEM", "operating-system")]
    [InlineData("OTHER", null)]
    [InlineData("SOURCE", null)]
    public async Task SpdxPrimaryPackagePurpose_MapsOntoAValidCycloneDxTypeOrNull_AndExportSchemaValidates(
        string purpose, string? expectedType)
    {
        string document = $$"""
            {
              "spdxVersion": "SPDX-2.3",
              "SPDXID": "SPDXRef-DOCUMENT",
              "name": "doc",
              "creationInfo": { "creators": [], "created": "2026-08-01T10:10:00Z" },
              "packages": [
                { "name": "spdx-check", "SPDXID": "SPDXRef-Package-x", "downloadLocation": "NOASSERTION",
                  "primaryPackagePurpose": "{{purpose}}" }
              ]
            }
            """;
        var parsed = SpdxParser.Parse(JsonDocument.Parse(document).RootElement);
        var component = Assert.Single(parsed.Components);
        Assert.Equal(expectedType, component.Type);

        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"spdx-purpose-{Guid.NewGuid():N}"[..24]);
        var (projectId, versionId) = await SeedOneComponentAsync(
            orgId, componentType: component.Type, componentHashesJson: null);

        string json = (await _export.BuildSbomDocumentAsync(
            orgId, projectId, versionId, SbomExportOptions.Default, CancellationToken.None))!;

        await AssertValidCycloneDxAsync(json, "1.7");
    }

    // ── collection export ────────────────────────────────────────────────────

    /// <summary>
    /// The finding this pins: <c>BuildCollectionSbomDocumentAsync</c> is the one export path this
    /// whole file never schema-validated, despite carrying its own genuinely different rendering
    /// rules — nested <c>components[]</c> (one entry per subtree project, each holding its OWN
    /// nested component array), native <c>cpe</c>/<c>swhid</c>/<c>omniborId</c> inside that nested
    /// array, and a root-level <c>signature</c> that covers the WHOLE aggregate document rather
    /// than one project's own. This epic shipped three defects where a rendered document was
    /// invalid CycloneDX; the collection renderer is exactly the shape none of those defects were
    /// ever checked against.
    /// </summary>
    [Theory]
    [InlineData("1.6")]
    [InlineData("1.7")]
    public async Task CollectionExport_WithNestedIdentifiersAndRootSignature_ValidatesAgainstTheOfficialSchema(string specVersion)
    {
        const string cpe = "cpe:2.3:a:acme:coll_widget:1.0:*:*:*:*:*:*:*";
        const string swhid = "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2";
        const string omniborId = "gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";

        string orgId = await OrgSeeder.InsertAsync(
            _fixture.Store, $"schema-coll-{specVersion.Replace('.', '-')}-{Guid.NewGuid():N}"[..30]);
        string collectionId = Guid.NewGuid().ToString("N");
        string projectId = Guid.NewGuid().ToString("N");
        string versionId = Guid.NewGuid().ToString("N");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO projects (id, org_id, kind, name, classifier, created_at)
                VALUES (@collectionId, @orgId, 'collection', 'schema-coll-folder', 'application', @now)
                """,
                new { collectionId, orgId, now = _clock.GetUtcNow().ToUtcIso() });
            await conn.ExecuteAsync(
                """
                INSERT INTO projects (id, org_id, parent_id, kind, name, classifier, created_at)
                VALUES (@projectId, @orgId, @collectionId, 'project', 'schema-coll-app', 'application', @now)
                """,
                new { projectId, orgId, collectionId, now = _clock.GetUtcNow().ToUtcIso() });
            await conn.ExecuteAsync(
                """
                INSERT INTO project_versions (id, org_id, project_id, version, is_latest, created_at)
                VALUES (@versionId, @orgId, @projectId, '1.0.0', 1, @now)
                """,
                new { versionId, orgId, projectId, now = _clock.GetUtcNow().ToUtcIso() });
            await conn.ExecuteAsync(
                """
                INSERT INTO sbom_components
                    (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                     component_type, sbom_scope, dependency_kind, dependency_path, additional_identifiers, created_at)
                VALUES
                    (@id, @orgId, @versionId, 'pkg:npm/coll-widget@1.0.0', 'npm', 'coll-widget', '1.0.0', 'coll-widget',
                     'library', 'required', 'direct', '["pkg:npm/coll-widget@1.0.0"]', @additionalIdentifiers, @now)
                """,
                new
                {
                    id = Guid.NewGuid().ToString("N"),
                    orgId,
                    versionId,
                    additionalIdentifiers = JsonSerializer.Serialize(new[]
                    {
                        new { kind = "cpe", value = cpe },
                        new { kind = "swhid", value = swhid },
                        new { kind = "omnibor", value = omniborId },
                    }),
                    now = _clock.GetUtcNow().ToUtcIso(),
                });
        }

        var tracker = new InstanceVulnTrackerConfig((_, _) => Task.FromResult<string?>(null), _clock);
        var signedExport = new SbomExportService(
            _fixture.Store, _clock, new ProjectRepository(_fixture.Store, _clock), tracker,
            TestSbomAuthorSigner.Configured(_fixture.Store, _clock));

        string json = (await signedExport.BuildCollectionSbomDocumentAsync(
            orgId, collectionId, SbomExportOptions.Default with { SpecVersion = specVersion }, CancellationToken.None))!;

        await AssertValidCycloneDxAsync(json, specVersion);

        using var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("signature", out _), "root signature member was not emitted");

        var projectEntry = Assert.Single(doc.RootElement.GetProperty("components").EnumerateArray());
        var nested = Assert.Single(projectEntry.GetProperty("components").EnumerateArray());
        Assert.Equal(cpe, nested.GetProperty("cpe").GetString());
        Assert.Equal([swhid], nested.GetProperty("swhid").EnumerateArray().Select(e => e.GetString()).ToList());
        Assert.Equal([omniborId], nested.GetProperty("omniborId").EnumerateArray().Select(e => e.GetString()).ToList());
    }
}
