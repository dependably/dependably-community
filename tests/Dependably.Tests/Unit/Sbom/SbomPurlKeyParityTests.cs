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
/// Writer/reader parity for <c>project_vuln_analysis.purl_key</c>, driven through the real ingest
/// writer rather than a hand-inserted key.
///
/// <para>The key is canonicalized on the way in — <c>%40</c> decoded, PEP-503 folding for PyPI,
/// lowercasing for npm/NuGet/RPM/OCI. Any reader that re-derives it by cutting the verbatim purl
/// at an <c>@</c> agrees with the writer only for the spellings where canonicalization is the
/// identity function, which is exactly the shape a convenient fixture (<c>pkg:pypi/requests</c>)
/// has. These fixtures deliberately use the shapes where the two disagree: a scoped npm name
/// spelled <c>%40</c>, an underscored mixed-case PyPI name, and a mixed-case NuGet id. A
/// divergence here is not cosmetic — it is a VEX suppression that never applies, so a
/// <c>not_affected</c> statement stops retiring its finding and the policy alert re-fires.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomPurlKeyParityTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly SbomIngestRepository _ingest;
    private readonly SbomMergeService _merge;
    private readonly SbomPolicyEvaluationService _policy;

    public SbomPurlKeyParityTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        var db = _fixture.Store;
        var time = TestTime.Frozen();

        _ingest = new SbomIngestRepository(db);
        _merge = new SbomMergeService(_ingest);

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

    // A scoped npm name spelled the way a purl spells it (%40), an underscored mixed-case PyPI
    // name, and a mixed-case NuGet id: the three shapes canonicalization actually changes.
    private const string ScopedNpmPurl = "pkg:npm/%40angular/core@16.2.0";
    private const string MixedPyPiPurl = "pkg:pypi/Django_Rest@3.0.0";
    private const string MixedNuGetPurl = "pkg:nuget/Newtonsoft.Json@12.0.1";

    private static string InventoryJson() => """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "metadata": { "component": { "type": "application", "name": "app", "version": "1.0.0" } },
          "components": [
            { "type": "library", "name": "@angular/core", "version": "16.2.0", "purl": "pkg:npm/%40angular/core@16.2.0" },
            { "type": "library", "name": "Django_Rest", "version": "3.0.0", "purl": "pkg:pypi/Django_Rest@3.0.0" },
            { "type": "library", "name": "Newtonsoft.Json", "version": "12.0.1", "purl": "pkg:nuget/Newtonsoft.Json@12.0.1" }
          ]
        }
        """;

    private static string VexJson() => """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.6",
          "vulnerabilities": [
            {
              "id": "CVE-2100-0001",
              "affects": [ { "ref": "pkg:npm/%40angular/core@16.2.0" } ],
              "analysis": { "state": "not_affected", "justification": "code_not_reachable" }
            },
            {
              "id": "CVE-2100-0002",
              "affects": [ { "ref": "pkg:pypi/Django_Rest@3.0.0" } ],
              "analysis": { "state": "not_affected", "justification": "code_not_reachable" }
            },
            {
              "id": "CVE-2100-0003",
              "affects": [ { "ref": "pkg:nuget/Newtonsoft.Json@12.0.1" } ],
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

    private async Task SetCvssToleranceAsync(string orgId, double tolerance)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE org_settings SET max_osv_score_tolerance = @tolerance WHERE org_id = @orgId",
            new { orgId, tolerance });
    }

    private async Task LinkAdvisoryAsync(
        string orgId, string versionId, string purl, string osvId, string ecosystem, string packageName)
    {
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, osvId, ecosystem: ecosystem, packageName: packageName, cvssScore: 9.1);

        await using var conn = await _fixture.Store.OpenAsync();
        string componentId = (await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM sbom_components WHERE org_id = @orgId AND project_version_id = @versionId AND purl = @purl",
            new { orgId, versionId, purl }))!;
        await conn.ExecuteAsync(
            "INSERT INTO sbom_component_vulns (id, component_id, vuln_id) VALUES (@id, @componentId, @vulnId)",
            new { id = Guid.NewGuid().ToString("N"), componentId, vulnId });
        await conn.ExecuteAsync(
            "UPDATE sbom_components SET vuln_checked_at = @now WHERE id = @componentId",
            new { componentId, now = TestTime.KnownNow.ToUtcIso() });
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task UploadedVex_OnCanonicalizedPurls_SuppressesEveryFinding()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"purlkey-a-{Guid.NewGuid():N}");
        await SetCvssToleranceAsync(orgId, 5.0);
        string versionId = await InsertProjectVersionAsync(orgId);
        var now = TestTime.KnownNow;

        await _merge.MergeComponentsAsync(orgId, versionId, Parse(InventoryJson()), now);
        await LinkAdvisoryAsync(orgId, versionId, ScopedNpmPurl, "CVE-2100-0001", "npm", "@angular/core");
        await LinkAdvisoryAsync(orgId, versionId, MixedPyPiPurl, "CVE-2100-0002", "pypi", "django-rest");
        await LinkAdvisoryAsync(orgId, versionId, MixedNuGetPurl, "CVE-2100-0003", "nuget", "newtonsoft.json");

        // Without the VEX the three advisories are three violations — the control that proves the
        // suppression below is doing the work.
        var beforeVex = await _policy.EvaluateAndPersistAsync(orgId, versionId);
        Assert.Equal("violation", beforeVex.PolicyStatus);
        Assert.Equal(3, beforeVex.FindingCount);

        await _merge.ApplyCycloneDxStatementsAsync(
            orgId, versionId, Parse(VexJson()).Statements, actorId: null, now);

        var result = await _policy.EvaluateAndPersistAsync(orgId, versionId);

        Assert.Equal("pass", result.PolicyStatus);
        Assert.Equal(0, result.FindingCount);
    }

    [Fact]
    public async Task WriterAndReader_DeriveTheSameKey_ForEveryCanonicalizedShape()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"purlkey-b-{Guid.NewGuid():N}");
        string versionId = await InsertProjectVersionAsync(orgId);

        await _merge.MergeComponentsAsync(orgId, versionId, Parse(InventoryJson()), TestTime.KnownNow);
        await _merge.ApplyCycloneDxStatementsAsync(
            orgId, versionId, Parse(VexJson()).Statements, actorId: null, TestTime.KnownNow);

        await using var conn = await _fixture.Store.OpenAsync();
        var componentKeys = (await conn.QueryAsync<(string Ecosystem, string PurlName, string Purl)>(
            "SELECT ecosystem, purl_name, purl FROM sbom_components WHERE org_id = @orgId AND project_version_id = @versionId",
            new { orgId, versionId }))
            .Select(c => SbomPurlKey.ForComponent(c.Ecosystem, c.PurlName, c.Purl)!)
            .OrderBy(k => k, StringComparer.Ordinal)
            .ToList();

        var storedKeys = (await conn.QueryAsync<string>(
            "SELECT purl_key FROM project_vuln_analysis WHERE org_id = @orgId AND project_version_id = @versionId",
            new { orgId, versionId }))
            .OrderBy(k => k, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(
            new[] { "pkg:npm/@angular/core", "pkg:nuget/newtonsoft.json", "pkg:pypi/django-rest" },
            storedKeys);
        Assert.Equal(storedKeys, componentKeys);
    }
}
