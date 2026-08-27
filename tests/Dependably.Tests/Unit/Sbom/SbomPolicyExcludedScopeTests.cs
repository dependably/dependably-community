using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// The <c>sbom_scope = 'excluded'</c> exemption, read from the column through the real evaluation
/// service rather than asserted on the pure evaluator alone — the column has to reach the arms
/// for the exemption to exist at all.
///
/// <para>An excluded component is one the SBOM's own producer says is not in the assembled
/// deliverable. Scoring an advisory against it sets the version to <c>violation</c> and, through
/// the folder rollup's worst-of fold, reds every ancestor — with nothing an operator can do about
/// it, because the inventory is correct to keep declaring the component and no re-upload retires
/// the finding.</para>
///
/// <para>The two controls are the point of the pair: <c>dependency_scope</c> stays fully scored,
/// including its <c>'unknown'</c> default. Exempting on that column instead would let every
/// component the reachability scanner has not classified escape policy, which is the opposite
/// posture — a gate degrading to allow because its input is missing.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomPolicyExcludedScopeTests : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = TestTime.KnownNow;

    private readonly TestMetadataStore _db = new();
    private string _orgId = "";
    private string _versionId = "";
    private SbomPolicyEvaluationService _policy = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgId = await OrgSeeder.InsertAsync(_db, $"scope-{Guid.NewGuid():N}");
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
                "UPDATE org_settings SET block_kev = 'block' WHERE org_id = @orgId",
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

    [Fact]
    public async Task AnExcludedComponentCarryingAKevAdvisoryProducesNoFinding()
    {
        await SeedComponentAsync("left-pad", "pkg:npm/left-pad@1.3.0", sbomScope: "excluded", dependencyScope: "runtime");
        await LinkKevAsync("left-pad", "CVE-2100-9001");

        var result = await _policy.EvaluateAndPersistAsync(_orgId, _versionId);

        Assert.Equal("pass", result.PolicyStatus);
        Assert.Equal(0, result.FindingCount);
        Assert.Empty(await FindingArmsAsync());
    }

    [Theory]
    [InlineData("dev")]
    [InlineData("unknown")]
    [InlineData("runtime")]
    public async Task EveryDependencyScopeIsStillScored(string dependencyScope)
    {
        await SeedComponentAsync("qs", "pkg:npm/qs@6.10.2", sbomScope: null, dependencyScope: dependencyScope);
        await LinkKevAsync("qs", "CVE-2100-9002");

        var result = await _policy.EvaluateAndPersistAsync(_orgId, _versionId);

        Assert.Equal("violation", result.PolicyStatus);
        Assert.Equal(1, result.FindingCount);
        Assert.Equal(["kev"], await FindingArmsAsync());
    }

    [Fact]
    public async Task OnlyTheExcludedComponentIsExemptedWhenBothAreInTheSameInventory()
    {
        await SeedComponentAsync("left-pad", "pkg:npm/left-pad@1.3.0", sbomScope: "excluded", dependencyScope: "runtime");
        await LinkKevAsync("left-pad", "CVE-2100-9001");
        await SeedComponentAsync("qs", "pkg:npm/qs@6.10.2", sbomScope: "required", dependencyScope: "dev");
        await LinkKevAsync("qs", "CVE-2100-9002");

        var result = await _policy.EvaluateAndPersistAsync(_orgId, _versionId);

        Assert.Equal("violation", result.PolicyStatus);
        Assert.Equal(1, result.FindingCount);
        Assert.Equal(["CVE-2100-9002"], await FindingVulnKeysAsync());
    }

    // ── harness ───────────────────────────────────────────────────────────────

    private async Task SeedComponentAsync(
        string name, string purl, string? sbomScope, string dependencyScope)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO sbom_components
                (id, org_id, project_version_id, purl, ecosystem, purl_name, version, name,
                 component_type, sbom_scope, dependency_scope, vuln_checked_at)
            VALUES (@id, @orgId, @versionId, @purl, 'npm', @name, @version, @name,
                    'library', @sbomScope, @dependencyScope, @now)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId = _orgId,
                versionId = _versionId,
                purl,
                name,
                version = purl[(purl.LastIndexOf('@') + 1)..],
                sbomScope,
                dependencyScope,
                now = Now.ToUtcIso(),
            });
    }

    private async Task LinkKevAsync(string componentName, string osvId)
    {
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _db, osvId, ecosystem: "npm", packageName: componentName, cvssScore: null, isKev: true);

        await using var conn = await _db.OpenAsync();
        string componentId = (await conn.ExecuteScalarAsync<string>(
            """
            SELECT id FROM sbom_components
            WHERE org_id = @orgId AND project_version_id = @versionId AND name = @componentName
            """,
            new { orgId = _orgId, versionId = _versionId, componentName }))!;
        await conn.ExecuteAsync(
            "INSERT INTO sbom_component_vulns (id, component_id, vuln_id) VALUES (@id, @componentId, @vulnId)",
            new { id = Guid.NewGuid().ToString("N"), componentId, vulnId });
    }

    private async Task<IReadOnlyList<string>> FindingArmsAsync()
    {
        await using var conn = await _db.OpenAsync();
        return (await conn.QueryAsync<string>(
            """
            SELECT arm FROM sbom_policy_findings
            WHERE org_id = @orgId AND project_version_id = @versionId ORDER BY arm
            """,
            new { orgId = _orgId, versionId = _versionId })).ToList();
    }

    private async Task<IReadOnlyList<string>> FindingVulnKeysAsync()
    {
        await using var conn = await _db.OpenAsync();
        return (await conn.QueryAsync<string>(
            """
            SELECT vuln_key FROM sbom_policy_findings
            WHERE org_id = @orgId AND project_version_id = @versionId ORDER BY vuln_key
            """,
            new { orgId = _orgId, versionId = _versionId })).ToList();
    }
}
