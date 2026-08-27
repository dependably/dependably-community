using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// End-to-end (in-memory SQLite) coverage of <see cref="SbomPolicyEvaluationService"/>: reads real
/// component/vuln/VEX rows, writes real <c>sbom_policy_findings</c> rows and the
/// <c>project_versions.policy_status</c> rollup, and raises the alert exactly once across repeated
/// evaluations of the same project version.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomPolicyEvaluationServiceTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly SbomPolicyEvaluationService _service;
    private readonly SbomPolicyRepository _repo;
    private readonly AlertRepository _alertRepo;
    private readonly OrgRepository _orgs;

    public SbomPolicyEvaluationServiceTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        var db = _fixture.Store;
        var time = TimeProvider.System;

        _repo = new SbomPolicyRepository(db, time);
        _orgs = new OrgRepository(db);
        var licenses = new LicenseRepository(db, time, new LicenseNormalizer(db, NullLogger<LicenseNormalizer>.Instance));
        _alertRepo = new AlertRepository(db, time);
        var alerts = new AlertService(_alertRepo, new NoOpAlertNotifier(), NullLogger<AlertService>.Instance);
        var audit = new AuditRepository(db, activityWriter: null, time);

        _service = new SbomPolicyEvaluationService(
            _repo, _orgs, licenses, alerts, audit, NullLogger<SbomPolicyEvaluationService>.Instance);
    }

    // ── local seed helpers (kept private to this file: no shared SBOM seeder exists yet on this branch) ──

    private async Task<string> InsertProjectAsync(string orgId, string name)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO projects (id, org_id, name) VALUES (@id, @orgId, @name)",
            new { id, orgId, name });
        return id;
    }

    private async Task<string> InsertProjectVersionAsync(string orgId, string projectId, string version)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO project_versions (id, org_id, project_id, version) VALUES (@id, @orgId, @projectId, @version)",
            new { id, orgId, projectId, version });
        return id;
    }

    private async Task<string> InsertComponentAsync(
        string orgId, string projectVersionId, string name, string? purl = null,
        string? ecosystem = null, string? licenseSpdx = null, DateTimeOffset? vulnCheckedAt = null)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, name, license_spdx, vuln_checked_at)
            VALUES (@id, @orgId, @projectVersionId, @purl, @ecosystem, @name, @licenseSpdx, @vulnCheckedAt)
            """,
            new
            {
                id,
                orgId,
                projectVersionId,
                purl,
                ecosystem,
                name,
                licenseSpdx,
                vulnCheckedAt = vulnCheckedAt?.ToUtcIso(),
            });
        return id;
    }

    private async Task LinkVulnAsync(string componentId, string vulnId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO sbom_component_vulns (id, component_id, vuln_id) VALUES (@id, @componentId, @vulnId)",
            new { id = Guid.NewGuid().ToString("N"), componentId, vulnId });
    }

    private async Task InsertVexAsync(string orgId, string projectVersionId, string purlKey, string vulnKey, string vexState)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO project_vuln_analysis (id, org_id, project_version_id, purl_key, vuln_key, vex_state, vex_source)
            VALUES (@id, @orgId, @projectVersionId, @purlKey, @vulnKey, @vexState, 'upload')
            """,
            new { id = Guid.NewGuid().ToString("N"), orgId, projectVersionId, purlKey, vulnKey, vexState });
    }

    private async Task SetPolicyAsync(
        string orgId, string? blockKev = null, string? blockMalicious = null,
        double? maxEpss = null, double? maxOsvScore = null, string? licenseMode = null)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            UPDATE org_settings SET
                block_kev = COALESCE(@blockKev, block_kev),
                block_malicious = COALESCE(@blockMalicious, block_malicious),
                max_epss_tolerance = COALESCE(@maxEpss, max_epss_tolerance),
                max_osv_score_tolerance = COALESCE(@maxOsvScore, max_osv_score_tolerance),
                license_enforcement_mode = COALESCE(@licenseMode, license_enforcement_mode)
            WHERE org_id = @orgId
            """,
            new { orgId, blockKev, blockMalicious, maxEpss, maxOsvScore, licenseMode });
    }

    private async Task<string?> ReadPolicyStatusAsync(string projectVersionId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.QuerySingleAsync<string?>(
            "SELECT policy_status FROM project_versions WHERE id = @projectVersionId",
            new { projectVersionId });
    }

    // ── tests ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task FlippingBlockKev_ProducesFindingRollupAndAlert_OnceAcrossReEvaluation()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sbom-a-{Guid.NewGuid():N}");
        await SetPolicyAsync(orgId, blockKev: "block");
        string projectId = await InsertProjectAsync(orgId, "checkout-service");
        string versionId = await InsertProjectVersionAsync(orgId, projectId, "1.0.0");
        string componentId = await InsertComponentAsync(
            orgId, versionId, "minimist", purl: "pkg:npm/minimist@1.2.0", ecosystem: "npm",
            vulnCheckedAt: TestTime.KnownNow);
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, "CVE-2021-44906", ecosystem: "npm", packageName: "minimist", isKev: true);
        await LinkVulnAsync(componentId, vulnId);

        var result = await _service.EvaluateAndPersistAsync(orgId, versionId);

        Assert.Equal("violation", result.PolicyStatus);
        Assert.Equal(1, result.FindingCount);
        Assert.Equal("violation", await ReadPolicyStatusAsync(versionId));

        var (alerts, alertTotal) = await _alertRepo.ListAsync(orgId, null, 10, 0);
        Assert.Equal(1, alertTotal);
        Assert.Equal(AlertTypes.SbomPolicyViolation, alerts[0].Type);
        Assert.Equal(versionId, alerts[0].SourceRef);

        // Re-evaluation with no change: findings replace 1-for-1 (no accumulation), and the
        // alert dedups permanently on (org_id, type, source_ref) — no second alert row.
        var second = await _service.EvaluateAndPersistAsync(orgId, versionId);
        Assert.Equal(1, second.FindingCount);
        var (_, secondAlertTotal) = await _alertRepo.ListAsync(orgId, null, 10, 0);
        Assert.Equal(1, secondAlertTotal);
    }

    [Fact]
    public async Task MixedComponents_OneViolatingOneClean_RollsUpToViolation_FindingsOnlyForOffender()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sbom-b-{Guid.NewGuid():N}");
        await SetPolicyAsync(orgId, blockKev: "block");
        string projectId = await InsertProjectAsync(orgId, "web-app");
        string versionId = await InsertProjectVersionAsync(orgId, projectId, "2.0.0");

        string bad = await InsertComponentAsync(
            orgId, versionId, "qs", purl: "pkg:npm/qs@6.5.2", ecosystem: "npm", vulnCheckedAt: TestTime.KnownNow);
        string badVuln = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, "CVE-2022-24999", ecosystem: "npm", packageName: "qs", isKev: true);
        await LinkVulnAsync(bad, badVuln);

        await InsertComponentAsync(
            orgId, versionId, "lodash", purl: "pkg:npm/lodash@4.17.21", ecosystem: "npm", vulnCheckedAt: TestTime.KnownNow);

        var result = await _service.EvaluateAndPersistAsync(orgId, versionId);

        Assert.Equal("violation", result.PolicyStatus);
        Assert.Equal(1, result.FindingCount);

        await using var conn = await _fixture.Store.OpenAsync();
        var componentIds = (await conn.QueryAsync<string>(
            "SELECT component_id FROM sbom_policy_findings WHERE project_version_id = @versionId",
            new { versionId })).ToList();
        Assert.Equal([bad], componentIds);
    }

    /// <summary>
    /// The security-critical half of the scannable/unscannable distinction: a component an
    /// advisory query could answer for, whose scan has not landed yet (queued, or deferred
    /// because the source was unreachable), is an open question and must hold the version at
    /// <c>warn</c>. Only a component no pass can ever answer for is excused.
    /// </summary>
    [Fact]
    public async Task DeferredScanOnScannableComponent_WithNoOtherViolations_RollsUpToWarn_NotPass()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sbom-c-{Guid.NewGuid():N}");
        string projectId = await InsertProjectAsync(orgId, "batch-job");
        string versionId = await InsertProjectVersionAsync(orgId, projectId, "0.1.0");
        await InsertComponentAsync(
            orgId, versionId, "unscanned-pkg", purl: "pkg:npm/unscanned-pkg@1.0.0",
            ecosystem: "npm", vulnCheckedAt: null);

        var result = await _service.EvaluateAndPersistAsync(orgId, versionId);

        Assert.Equal("warn", result.PolicyStatus);
        Assert.Equal(0, result.FindingCount);
        Assert.Equal("warn", await ReadPolicyStatusAsync(versionId));
    }

    /// <summary>
    /// A component with no parseable purl is unscannable, not unscanned: no scan pass will ever
    /// stamp it, so folding it into the unscanned arm would pin the version at <c>warn</c>
    /// forever and drain the status of meaning.
    /// </summary>
    [Fact]
    public async Task PurllessComponent_NeverStampable_DoesNotHoldTheVersionAtWarn()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sbom-c2-{Guid.NewGuid():N}");
        string projectId = await InsertProjectAsync(orgId, "file-inventory");
        string versionId = await InsertProjectVersionAsync(orgId, projectId, "0.1.0");
        await InsertComponentAsync(orgId, versionId, "vendored-blob.so", vulnCheckedAt: null);
        await InsertComponentAsync(
            orgId, versionId, "left-pad", purl: "pkg:npm/left-pad@1.3.0", ecosystem: "npm",
            vulnCheckedAt: TestTime.KnownNow);

        var result = await _service.EvaluateAndPersistAsync(orgId, versionId);

        Assert.Equal("pass", result.PolicyStatus);
        Assert.Equal(0, result.FindingCount);
        Assert.Equal("pass", await ReadPolicyStatusAsync(versionId));
    }

    /// <summary>
    /// The same ruling for a no-feed ecosystem: OSV publishes nothing a <c>pkg:oci</c> component
    /// could match, so neither scan path stamps one and it is unscannable by construction.
    /// </summary>
    [Fact]
    public async Task NoFeedEcosystemComponent_NeverStampable_DoesNotHoldTheVersionAtWarn()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sbom-c3-{Guid.NewGuid():N}");
        string projectId = await InsertProjectAsync(orgId, "container-image");
        string versionId = await InsertProjectVersionAsync(orgId, projectId, "0.1.0");
        await InsertComponentAsync(
            orgId, versionId, "base-image", purl: "pkg:oci/base-image@sha256%3Aabc",
            ecosystem: "oci", vulnCheckedAt: null);
        await InsertComponentAsync(
            orgId, versionId, "left-pad", purl: "pkg:npm/left-pad@1.3.0", ecosystem: "npm",
            vulnCheckedAt: TestTime.KnownNow);

        var result = await _service.EvaluateAndPersistAsync(orgId, versionId);

        Assert.Equal("pass", result.PolicyStatus);
        Assert.Equal("pass", await ReadPolicyStatusAsync(versionId));
    }

    /// <summary>
    /// Mixed partial state in one evaluation: an unscannable component, a genuinely deferred
    /// scannable one, and a cleanly scanned one. The deferred row alone must decide the verdict —
    /// excusing the unscannable row must not also excuse the deferred one.
    /// </summary>
    [Fact]
    public async Task UnscannableAndDeferredComponentsTogether_StillRollUpToWarn()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sbom-c4-{Guid.NewGuid():N}");
        string projectId = await InsertProjectAsync(orgId, "mixed-inventory");
        string versionId = await InsertProjectVersionAsync(orgId, projectId, "0.1.0");
        await InsertComponentAsync(orgId, versionId, "vendored-blob.so", vulnCheckedAt: null);
        await InsertComponentAsync(
            orgId, versionId, "requests", purl: "pkg:pypi/requests@2.28.1", ecosystem: "pypi",
            licenseSpdx: "Apache-2.0", vulnCheckedAt: null);
        await InsertComponentAsync(
            orgId, versionId, "left-pad", purl: "pkg:npm/left-pad@1.3.0", ecosystem: "npm",
            vulnCheckedAt: TestTime.KnownNow);

        var result = await _service.EvaluateAndPersistAsync(orgId, versionId);

        Assert.Equal("warn", result.PolicyStatus);
        Assert.Equal(0, result.FindingCount);
    }

    /// <summary>
    /// The licence arm is independent of advisory coverage: an unscannable component still
    /// carries a declared licence, and a tenant running <c>license_enforcement_mode=block</c>
    /// configured that gate for the whole inventory.
    /// </summary>
    [Fact]
    public async Task UnscannableComponent_WithBlockedLicense_StillProducesALicenceFinding()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sbom-c5-{Guid.NewGuid():N}");
        await SetPolicyAsync(orgId, licenseMode: "block");
        string projectId = await InsertProjectAsync(orgId, "licence-inventory");
        string versionId = await InsertProjectVersionAsync(orgId, projectId, "0.1.0");
        await InsertComponentAsync(
            orgId, versionId, "vendored-blob.so", licenseSpdx: "GPL-3.0-only", vulnCheckedAt: null);

        var result = await _service.EvaluateAndPersistAsync(orgId, versionId);

        Assert.Equal("violation", result.PolicyStatus);
        Assert.Equal(1, result.FindingCount);

        await using var conn = await _fixture.Store.OpenAsync();
        string arm = await conn.QuerySingleAsync<string>(
            "SELECT arm FROM sbom_policy_findings WHERE project_version_id = @versionId",
            new { versionId });
        Assert.Equal("license", arm);
    }

    [Fact]
    public async Task EveryComponentScannedAndClean_RollsUpToPass()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sbom-d-{Guid.NewGuid():N}");
        string projectId = await InsertProjectAsync(orgId, "clean-service");
        string versionId = await InsertProjectVersionAsync(orgId, projectId, "3.0.0");
        await InsertComponentAsync(orgId, versionId, "clean-pkg", vulnCheckedAt: TestTime.KnownNow);

        var result = await _service.EvaluateAndPersistAsync(orgId, versionId);

        Assert.Equal("pass", result.PolicyStatus);
        Assert.Equal(0, result.FindingCount);
    }

    [Fact]
    public async Task DeclaredLicenseEcosystem_NoLicenseSpdx_BlocksAsUnknownLicense()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sbom-e-{Guid.NewGuid():N}");
        await SetPolicyAsync(orgId, licenseMode: "block");
        string projectId = await InsertProjectAsync(orgId, "py-service");
        string versionId = await InsertProjectVersionAsync(orgId, projectId, "1.0.0");
        // pypi is a DeclaredLicenseEcosystems member: no recorded SPDX is an unknown licence, not
        // "no problem" — mirrors the serve-path posture in BlockGateService.
        await InsertComponentAsync(
            orgId, versionId, "charset-normalizer", purl: "pkg:pypi/charset-normalizer@2.1.1",
            ecosystem: "pypi", licenseSpdx: null, vulnCheckedAt: TestTime.KnownNow);

        var result = await _service.EvaluateAndPersistAsync(orgId, versionId);

        Assert.Equal("violation", result.PolicyStatus);
        Assert.Equal(1, result.FindingCount);

        await using var conn = await _fixture.Store.OpenAsync();
        var finding = await conn.QuerySingleAsync(
            "SELECT arm AS Arm, license_spdx AS LicenseSpdx FROM sbom_policy_findings WHERE project_version_id = @versionId",
            new { versionId });
        Assert.Equal("license", (string)finding.Arm);
        Assert.Equal(BlockGateService.NoLicenseAssertion, (string)finding.LicenseSpdx);
    }

    [Fact]
    public async Task NonDeclaredLicenseEcosystem_NoLicenseSpdx_PassesThrough()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sbom-f-{Guid.NewGuid():N}");
        await SetPolicyAsync(orgId, licenseMode: "block");
        string projectId = await InsertProjectAsync(orgId, "go-service");
        string versionId = await InsertProjectVersionAsync(orgId, projectId, "1.0.0");
        // go is not a DeclaredLicenseEcosystems member: it routinely records nothing, so an
        // absent licence must not deny.
        await InsertComponentAsync(
            orgId, versionId, "golang.org/x/text", purl: "pkg:golang/golang.org/x/text@0.9.0",
            ecosystem: "go", licenseSpdx: null, vulnCheckedAt: TestTime.KnownNow);

        var result = await _service.EvaluateAndPersistAsync(orgId, versionId);

        Assert.Equal("pass", result.PolicyStatus);
        Assert.Equal(0, result.FindingCount);
    }

    [Fact]
    public async Task VexNotAffected_SuppressesTheCvssArm_EndToEnd()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sbom-g-{Guid.NewGuid():N}");
        await SetPolicyAsync(orgId, maxOsvScore: 5.0);
        string projectId = await InsertProjectAsync(orgId, "requests-consumer");
        string versionId = await InsertProjectVersionAsync(orgId, projectId, "1.0.0");
        string componentId = await InsertComponentAsync(
            orgId, versionId, "requests", purl: "pkg:pypi/requests@2.28.1", ecosystem: "pypi",
            vulnCheckedAt: TestTime.KnownNow);
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, "CVE-2023-32681", ecosystem: "pypi", packageName: "requests", cvssScore: 9.1);
        await LinkVulnAsync(componentId, vulnId);
        await InsertVexAsync(orgId, versionId, "pkg:pypi/requests", "CVE-2023-32681", "not_affected");

        var result = await _service.EvaluateAndPersistAsync(orgId, versionId);

        Assert.Equal("pass", result.PolicyStatus);
        Assert.Equal(0, result.FindingCount);
    }

    [Fact]
    public async Task NoVexStatement_TheSameAdvisory_StillTriggersTheCvssArm()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sbom-h-{Guid.NewGuid():N}");
        await SetPolicyAsync(orgId, maxOsvScore: 5.0);
        string projectId = await InsertProjectAsync(orgId, "requests-consumer-2");
        string versionId = await InsertProjectVersionAsync(orgId, projectId, "1.0.0");
        string componentId = await InsertComponentAsync(
            orgId, versionId, "requests", purl: "pkg:pypi/requests@2.28.1", ecosystem: "pypi",
            vulnCheckedAt: TestTime.KnownNow);
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, "CVE-2023-32682", ecosystem: "pypi", packageName: "requests", cvssScore: 9.1);
        await LinkVulnAsync(componentId, vulnId);

        var result = await _service.EvaluateAndPersistAsync(orgId, versionId);

        Assert.Equal("violation", result.PolicyStatus);
        Assert.Equal(1, result.FindingCount);
    }

    [Fact]
    public async Task VexMatchedByAlias_NotOsvId_StillSuppresses()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"sbom-i-{Guid.NewGuid():N}");
        await SetPolicyAsync(orgId, blockKev: "block");
        string projectId = await InsertProjectAsync(orgId, "aliased-consumer");
        string versionId = await InsertProjectVersionAsync(orgId, projectId, "1.0.0");
        string componentId = await InsertComponentAsync(
            orgId, versionId, "newtonsoft-json", purl: "pkg:nuget/Newtonsoft.Json@12.0.1", ecosystem: "nuget",
            vulnCheckedAt: TestTime.KnownNow);
        // The vulnerabilities row is fetched under its OSV (CVE) id, but the VEX statement cites
        // the GHSA alias instead — a legitimate mismatch a VEX document can carry.
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, "CVE-2024-9999", ecosystem: "nuget", packageName: "Newtonsoft.Json",
            isKev: true, aliases: """["GHSA-5crp-9r3c-p9vr"]""");
        await LinkVulnAsync(componentId, vulnId);
        // The key is the canonical one the ingest writer produces: NuGet ids fold to lowercase,
        // so a statement about "Newtonsoft.Json" is stored under "newtonsoft.json".
        await InsertVexAsync(orgId, versionId, "pkg:nuget/newtonsoft.json", "GHSA-5crp-9r3c-p9vr", "resolved");

        var result = await _service.EvaluateAndPersistAsync(orgId, versionId);

        Assert.Equal("pass", result.PolicyStatus);
        Assert.Equal(0, result.FindingCount);
    }
}
