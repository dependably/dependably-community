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
/// The boot pass that folds stored <c>project_vuln_analysis.purl_key</c> values onto the canonical
/// form <see cref="SbomPurlKey"/> derives.
///
/// <para>Fixing the write path leaves the rows already at rest keyed on whatever a client sent, and
/// nothing else rewrites them — so an operator who triaged an advisory before the upgrade keeps a
/// row the evaluator cannot see, keeps getting the alert, and has no way to tell why. The first
/// case therefore asserts the suppression through the real evaluator rather than only asserting
/// the stored string.</para>
///
/// <para>The rows are seeded by hand because no writer produces them any more; the shape is what a
/// deployment holds after triaging through an endpoint that stored the caller's own spelling.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class VulnAnalysisPurlKeyMigrationTests : IAsyncLifetime
{
    private const string MixedNuGetPurl = "pkg:nuget/Newtonsoft.Json@12.0.1";
    private const string StaleKey = "pkg:nuget/Newtonsoft.Json";
    private const string CanonicalKey = "pkg:nuget/newtonsoft.json";
    private const string Advisory = "CVE-2100-0003";

    private static readonly DateTimeOffset Now = TestTime.KnownNow;

    private readonly TestMetadataStore _db = new();
    private string _orgId = "";
    private string _versionId = "";
    private SbomPolicyEvaluationService _policy = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgId = await OrgSeeder.InsertAsync(_db, $"purlmig-{Guid.NewGuid():N}");
        string projectId = Guid.NewGuid().ToString("N");
        _versionId = Guid.NewGuid().ToString("N");

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO projects (id, org_id, name) VALUES (@projectId, @orgId, 'storefront')",
                new { projectId, orgId = _orgId });
            await conn.ExecuteAsync(
                """
                INSERT INTO project_versions (id, org_id, project_id, version, is_latest)
                VALUES (@versionId, @orgId, @projectId, '1.0.0', 1)
                """,
                new { versionId = _versionId, orgId = _orgId, projectId });
            await conn.ExecuteAsync(
                "UPDATE org_settings SET max_osv_score_tolerance = 5.0 WHERE org_id = @orgId",
                new { orgId = _orgId });
        }

        var clock = new Microsoft.Extensions.Time.Testing.FakeTimeProvider(Now);
        _policy = new SbomPolicyEvaluationService(
            new SbomPolicyRepository(_db, clock),
            new OrgRepository(_db),
            new LicenseRepository(_db, clock, new LicenseNormalizer(_db, NullLogger<LicenseNormalizer>.Instance)),
            new AlertService(
                new AlertRepository(_db, clock), new NoOpAlertNotifier(), NullLogger<AlertService>.Instance),
            new AuditRepository(_db, activityWriter: null, clock),
            NullLogger<SbomPolicyEvaluationService>.Instance);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    /// <summary>Re-applying the schema is what runs the pass on a real boot.</summary>
    private Task RebootAsync() => new SchemaInitializer(_db).InitializeAsync();

    [Fact]
    public async Task RebootMakesAStoredNonCanonicalSuppressionApplyAgain()
    {
        await SeedComponentAndAdvisoryAsync();
        await SeedAnalysisAsync(StaleKey, vexState: "not_affected", vexSource: "manual");

        // The operator's decision is on the row and doing nothing: the evaluator derives the
        // canonical key and finds no statement there.
        var before = await _policy.EvaluateAndPersistAsync(_orgId, _versionId);
        Assert.Equal("violation", before.PolicyStatus);
        Assert.Equal(1, before.FindingCount);

        await RebootAsync();

        var after = await _policy.EvaluateAndPersistAsync(_orgId, _versionId);

        // The consequence first: whatever the column now holds, the operator's suppression has to
        // be the thing the evaluator acts on again.
        Assert.Equal("pass", after.PolicyStatus);
        Assert.Equal(0, after.FindingCount);
        Assert.Equal([CanonicalKey], await StoredKeysAsync());
    }

    /// <summary>
    /// Folding a key can land it on a row that already holds the canonical one, which the
    /// byte-exact UNIQUE refuses. The established rule decides it rather than the constraint: the
    /// canonical row survives and the manual arm outranks the uploaded one wherever it sat.
    /// </summary>
    [Fact]
    public async Task ACollisionMergesRatherThanThrowing_AndManualTriageWins()
    {
        await SeedComponentAndAdvisoryAsync();
        await SeedAnalysisAsync(
            CanonicalKey, vexState: "exploitable", vexSource: "upload",
            reachability: "reachable", updatedAt: "2026-02-01T00:00:00Z");
        await SeedAnalysisAsync(
            StaleKey, vexState: "not_affected", vexSource: "manual",
            vexDetail: "edge is behind the WAF", updatedAt: "2026-01-01T00:00:00Z");

        await RebootAsync();

        Assert.Equal([CanonicalKey], await StoredKeysAsync());

        await using var conn = await _db.OpenAsync();
        var (state, source, detail, reach) = await conn.QuerySingleAsync<(string, string, string, string)>(
            """
            SELECT vex_state, vex_source, vex_detail, reachability
            FROM project_vuln_analysis
            WHERE org_id = @orgId AND project_version_id = @versionId
            """,
            new { orgId = _orgId, versionId = _versionId });

        // The manual arm wins whole, even though the uploaded row is newer and is the survivor.
        Assert.Equal("not_affected", state);
        Assert.Equal("manual", source);
        Assert.Equal("edge is behind the WAF", detail);

        // The survivor's SARIF arm is kept: the merge fills gaps, it never drops a fact.
        Assert.Equal("reachable", reach);

        var after = await _policy.EvaluateAndPersistAsync(_orgId, _versionId);
        Assert.Equal("pass", after.PolicyStatus);
    }

    [Fact]
    public async Task AlreadyCanonicalAndNonPurlKeysAreLeftAlone()
    {
        await SeedAnalysisAsync(CanonicalKey, vexState: "exploitable", vexSource: "upload");
        await SeedAnalysisAsync(
            "RUSTSEC-2100-0001", vexState: "exploitable", vexSource: "manual",
            vulnKey: "RUSTSEC-2100-0001");

        await RebootAsync();

        Assert.Equal(["RUSTSEC-2100-0001", CanonicalKey], await StoredKeysAsync());
    }

    /// <summary>
    /// Two different stored spellings can fold onto the same key with no canonical row present, so
    /// the second rename has to see the first one's result rather than collide with it.
    /// </summary>
    [Fact]
    public async Task TwoStaleSpellingsFoldingOntoOneKeyCollapseToOneRow()
    {
        await SeedAnalysisAsync("pkg:pypi/My_Package", vexState: "in_triage", vexSource: "upload");
        await SeedAnalysisAsync("pkg:pypi/MY.PACKAGE", vexState: "not_affected", vexSource: "manual");

        await RebootAsync();

        Assert.Equal(["pkg:pypi/my-package"], await StoredKeysAsync());

        await using var conn = await _db.OpenAsync();
        var (state, source) = await conn.QuerySingleAsync<(string, string)>(
            """
            SELECT vex_state, vex_source FROM project_vuln_analysis
            WHERE org_id = @orgId AND project_version_id = @versionId
            """,
            new { orgId = _orgId, versionId = _versionId });
        Assert.Equal("not_affected", state);
        Assert.Equal("manual", source);
    }

    // ── harness ───────────────────────────────────────────────────────────────

    private async Task SeedComponentAndAdvisoryAsync()
    {
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _db, Advisory, ecosystem: "nuget", packageName: "newtonsoft.json", cvssScore: 9.1);

        await using var conn = await _db.OpenAsync();
        string componentId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                 component_type, dependency_scope, vuln_checked_at)
            VALUES (@componentId, @orgId, @versionId, @purl, 'nuget', 'Newtonsoft.Json', '12.0.1',
                    'Newtonsoft.Json', 'library', 'runtime', @now)
            """,
            new
            {
                componentId,
                orgId = _orgId,
                versionId = _versionId,
                purl = MixedNuGetPurl,
                now = Now.ToUtcIso(),
            });
        await conn.ExecuteAsync(
            "INSERT INTO sbom_component_vulns (id, component_id, vuln_id) VALUES (@id, @componentId, @vulnId)",
            new { id = Guid.NewGuid().ToString("N"), componentId, vulnId });
    }

    private async Task SeedAnalysisAsync(
        string purlKey,
        string vexState,
        string vexSource,
        string? vexDetail = null,
        string? reachability = null,
        string? vulnKey = null,
        string updatedAt = "2026-01-01T00:00:00Z")
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO project_vuln_analysis (
                id, org_id, project_version_id, purl_key, vuln_key,
                vex_state, vex_detail, vex_source, reachability, updated_at)
            VALUES (
                @id, @orgId, @versionId, @purlKey, @vulnKey,
                @vexState, @vexDetail, @vexSource, @reachability, @updatedAt)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId = _orgId,
                versionId = _versionId,
                purlKey,
                vulnKey = vulnKey ?? Advisory,
                vexState,
                vexDetail,
                vexSource,
                reachability,
                updatedAt,
            });
    }

    private async Task<IReadOnlyList<string>> StoredKeysAsync()
    {
        await using var conn = await _db.OpenAsync();
        return (await conn.QueryAsync<string>(
            """
            SELECT purl_key FROM project_vuln_analysis
            WHERE org_id = @orgId AND project_version_id = @versionId
            ORDER BY purl_key
            """,
            new { orgId = _orgId, versionId = _versionId })).ToList();
    }
}
