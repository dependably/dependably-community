using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Sbom;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// Reader parity for <c>project_vuln_analysis.vuln_key</c> case, driven through the real ingest
/// writer and the real policy/export services rather than a hand-inserted row.
///
/// <para>An advisory id from an OSV feed is stored under its own canonical case
/// (<c>vulnerabilities.osv_id</c>) — uppercase for a CVE id, a lowercase alphanumeric suffix for a
/// GHSA id — and a third-party VEX document is free to spell the same advisory any way its author
/// chose. <see cref="SbomVulnKeyComparer"/> matches the two case-insensitively wherever
/// <c>vuln_key</c> is compared, without ever rewriting the stored spelling: the policy evaluator
/// resolving whether a finding is suppressed, and the CycloneDX VDR export deciding whether a
/// vulnerability carries an <c>analysis</c> block — the same way it already was in the analysis
/// view's case-insensitive lookup. A divergence here is not cosmetic: it is an operator seeing an
/// advisory read "suppressed" while the policy gate still fires a violation for it, and the
/// exported document silently drops the analysis that explains why.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomVulnKeyParityTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly SbomIngestRepository _ingest;
    private readonly SbomMergeService _merge;
    private readonly SbomPolicyEvaluationService _policy;
    private readonly SbomExportService _export;

    public SbomVulnKeyParityTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        var db = _fixture.Store;
        var time = TestTime.Frozen();

        _ingest = new SbomIngestRepository(db);
        _merge = new SbomMergeService(_ingest);
        var tracker = new Dependably.Infrastructure.VulnTracker.InstanceVulnTrackerConfig(
            (_, _) => Task.FromResult<string?>(null), time);
        _export = new SbomExportService(db, time, new ProjectRepository(db, time), tracker, Dependably.Tests.Infrastructure.TestSbomAuthorSigner.Unconfigured(db, time));

        var licenses = new LicenseRepository(db, time, new LicenseNormalizer(db, NullLogger<LicenseNormalizer>.Instance));
        var alerts = new AlertService(
            new AlertRepository(db, time), new NoOpAlertNotifier(), NullLogger<AlertService>.Instance);
        _policy = new SbomPolicyEvaluationService(
            new SbomPolicyRepository(db, time),
            new OrgRepository(db),
            licenses,
            alerts,
            new AuditRepository(db, activityWriter: null, time),
            NullLogger<SbomPolicyEvaluationService>.Instance);
    }

    // ── fixtures ──────────────────────────────────────────────────────────────

    private const string ComponentPurl = "pkg:npm/left-pad@1.0.0";

    private static string InventoryJson() => """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "metadata": { "component": { "type": "application", "name": "app", "version": "1.0.0" } },
          "components": [
            { "type": "library", "name": "left-pad", "version": "1.0.0", "purl": "pkg:npm/left-pad@1.0.0" }
          ]
        }
        """;

    // The VEX cites the advisory in lowercase — a spelling a real OpenVEX/CycloneDX producer is
    // free to choose, and distinct from the uppercase form vulnerabilities.osv_id stores it under.
    // osv_id is globally unique, so each test in this shared-fixture class links its own id.
    private static string LowercaseVexJson(string lowercaseAdvisoryId) => $$"""
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "vulnerabilities": [
            {
              "id": "{{lowercaseAdvisoryId}}",
              "affects": [ { "ref": "pkg:npm/left-pad@1.0.0" } ],
              "analysis": { "state": "not_affected", "justification": "code_not_reachable" }
            }
          ]
        }
        """;

    // The adversarial twin: a VEX citing an id that genuinely does not name the linked advisory
    // must not suppress it — proving the fix folds case, not "matches loosely".
    private static string UnrelatedVexJson(string unrelatedAdvisoryId) => $$"""
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "vulnerabilities": [
            {
              "id": "{{unrelatedAdvisoryId}}",
              "affects": [ { "ref": "pkg:npm/left-pad@1.0.0" } ],
              "analysis": { "state": "not_affected", "justification": "code_not_reachable" }
            }
          ]
        }
        """;

    private static CycloneDxDocument Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return CycloneDxParser.Parse(doc.RootElement);
    }

    private async Task<(string ProjectId, string VersionId)> InsertProjectVersionAsync(string orgId)
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
        return (projectId, versionId);
    }

    private async Task SetCvssToleranceAsync(string orgId, double tolerance)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET max_osv_score_tolerance = @tolerance WHERE org_id = @orgId",
            new { orgId, tolerance });
    }

    private async Task LinkAdvisoryAsync(string orgId, string versionId, string osvId)
    {
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, osvId, ecosystem: "npm", packageName: "left-pad", cvssScore: 9.1);

        await using var conn = await _fixture.Store.OpenAsync();
        string componentId = (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM sbom_components WHERE org_id = @orgId AND project_version_id = @versionId AND purl = @purl",
            new { orgId, versionId, purl = ComponentPurl }))!;
        await conn.ExecuteAsync(
            "INSERT INTO sbom_component_vulns (id, component_id, vuln_id) VALUES (@id, @componentId, @vulnId)",
            new { id = Guid.NewGuid().ToString("N"), componentId, vulnId });
        await conn.ExecuteAsync(
            "UPDATE sbom_components SET vuln_checked_at = @now WHERE id = @componentId",
            new { componentId, now = TestTime.KnownNow.ToUtcIso() });
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task LowercaseVexId_SuppressesThePolicyFinding_NotJustTheAnalysisView()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"vulnkey-a-{Guid.NewGuid():N}");
        await SetCvssToleranceAsync(orgId, 5.0);
        var (_, versionId) = await InsertProjectVersionAsync(orgId);
        var now = TestTime.KnownNow;

        await _merge.MergeComponentsAsync(orgId, versionId, Parse(InventoryJson()), now);
        await LinkAdvisoryAsync(orgId, versionId, "CVE-2100-0009");

        // Without the VEX this is a violation — the control that proves the suppression below is
        // doing the work, not an evaluator that never flagged the advisory in the first place.
        var beforeVex = await _policy.EvaluateAndPersistAsync(orgId, versionId);
        Assert.Equal("violation", beforeVex.PolicyStatus);
        Assert.Equal(1, beforeVex.FindingCount);

        await _merge.ApplyCycloneDxStatementsAsync(
            orgId, versionId, Parse(LowercaseVexJson("cve-2100-0009")).Statements, actorId: null, now);

        var afterVex = await _policy.EvaluateAndPersistAsync(orgId, versionId);

        Assert.Equal("pass", afterVex.PolicyStatus);
        Assert.Equal(0, afterVex.FindingCount);
    }

    [Fact]
    public async Task LowercaseVexId_CarriesAnAnalysisBlockInTheVdrExport()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"vulnkey-b-{Guid.NewGuid():N}");
        var (projectId, versionId) = await InsertProjectVersionAsync(orgId);
        var now = TestTime.KnownNow;

        await _merge.MergeComponentsAsync(orgId, versionId, Parse(InventoryJson()), now);
        await LinkAdvisoryAsync(orgId, versionId, "CVE-2100-0010");
        await _merge.ApplyCycloneDxStatementsAsync(
            orgId, versionId, Parse(LowercaseVexJson("cve-2100-0010")).Statements, actorId: null, now);

        string json = (await _export.BuildSbomDocumentAsync(orgId, projectId, versionId, SbomExportOptions.Default with { Variant = "vdr" }, CancellationToken.None))!;
        using var doc = JsonDocument.Parse(json);
        var entry = doc.RootElement.GetProperty("vulnerabilities").EnumerateArray()
            .Single(v => string.Equals(v.GetProperty("id").GetString(), "CVE-2100-0010", StringComparison.Ordinal));

        Assert.True(entry.TryGetProperty("analysis", out var analysis));
        Assert.Equal("not_affected", analysis.GetProperty("state").GetString());
    }

    [Fact]
    public async Task VexCitingAnUnrelatedId_SuppressesNeitherThePolicyFindingNorTheExportAnalysis()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"vulnkey-c-{Guid.NewGuid():N}");
        await SetCvssToleranceAsync(orgId, 5.0);
        var (projectId, versionId) = await InsertProjectVersionAsync(orgId);
        var now = TestTime.KnownNow;

        await _merge.MergeComponentsAsync(orgId, versionId, Parse(InventoryJson()), now);
        await LinkAdvisoryAsync(orgId, versionId, "CVE-2100-0011");
        await _merge.ApplyCycloneDxStatementsAsync(
            orgId, versionId, Parse(UnrelatedVexJson("cve-2100-9999")).Statements, actorId: null, now);

        var result = await _policy.EvaluateAndPersistAsync(orgId, versionId);
        Assert.Equal("violation", result.PolicyStatus);
        Assert.Equal(1, result.FindingCount);

        string json = (await _export.BuildSbomDocumentAsync(orgId, projectId, versionId, SbomExportOptions.Default with { Variant = "vdr" }, CancellationToken.None))!;
        using var doc = JsonDocument.Parse(json);
        var entry = doc.RootElement.GetProperty("vulnerabilities").EnumerateArray()
            .Single(v => string.Equals(v.GetProperty("id").GetString(), "CVE-2100-0011", StringComparison.Ordinal));

        Assert.False(entry.TryGetProperty("analysis", out _));
    }

    // The fix is a comparison rule, not a value rewrite: a GHSA id's alphanumeric suffix is
    // conventionally lowercase (unlike a CVE id's all-uppercase form), so canonicalizing every
    // vuln_key to one case at write time would corrupt whichever id spelling disagreed with the
    // chosen case — in storage, in the analysis view, and in the exported VEX document. The writer
    // must store the document's own spelling verbatim; matching happens case-insensitively at read
    // time instead.
    [Fact]
    public async Task WriterPreservesTheDocumentsOwnSpelling_NeverRewritesItToOneCase()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"vulnkey-d-{Guid.NewGuid():N}");
        var (_, versionId) = await InsertProjectVersionAsync(orgId);
        var now = TestTime.KnownNow;

        await _merge.MergeComponentsAsync(orgId, versionId, Parse(InventoryJson()), now);
        await _merge.ApplyCycloneDxStatementsAsync(
            orgId, versionId, Parse(LowercaseVexJson("cve-2100-0012")).Statements, actorId: null, now);

        await using var conn = await _fixture.Store.OpenAsync();
        string? storedVulnKey = await conn.ExecuteScalarAsync<string?>(
            "SELECT vuln_key FROM project_vuln_analysis WHERE org_id = @orgId AND project_version_id = @versionId",
            new { orgId, versionId });

        // Stored exactly as the VEX spelled it — a blind uppercase fold would turn a real GHSA id's
        // lowercase suffix (GHSA-mh6f-8j2x-4483) into a spelling that id never actually has.
        Assert.Equal("cve-2100-0012", storedVulnKey);
    }
}
