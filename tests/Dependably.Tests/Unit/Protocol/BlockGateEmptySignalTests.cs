using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Protocol;
using Dependably.Protocol.Provenance;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The two block-gate arms whose input signal can legitimately be <em>absent</em>, and which
/// therefore have to decide what absence means:
///
/// <list type="number">
///   <item>The license arm, when an artifact has zero recorded SPDX entries. For an ecosystem
///         whose manifest carries a declared license field, "nothing recorded" is a missing
///         signal, not a licence-free package — omitting or malforming the manifest field would
///         otherwise be a way around a tenant's <c>license_enforcement_mode=block</c> allowlist.
///         For go/apk/oci, which routinely record nothing, absence keeps passing through.</item>
///   <item>The provenance arm, when <c>verify_*_signatures='block'</c> but the org's trust-anchor
///         set is empty. Nothing can then reach a <c>verified</c> verdict, so the policy must deny
///         rather than degrade to allow-all.</item>
/// </list>
///
/// Each fail-closed assertion is paired with the adversarial twin proving the arm did not simply
/// start denying everything.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BlockGateEmptySignalTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly StubPerOrgTrustAnchorStore _anchors = new();
    private readonly BlockGateService _sut;

    public BlockGateEmptySignalTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _sut = new BlockGateService(
            new VulnerabilityRepository(_fixture.Store, _clock),
            new AuditRepository(_fixture.Store),
            new QuarantineRepository(_fixture.Store, _clock),
            new AlertService(new AlertRepository(_fixture.Store, _clock), new NoOpAlertNotifier(),
                NullLogger<AlertService>.Instance),
            new InstallScriptAllowlistService(_fixture.Store, new MemoryCache(new MemoryCacheOptions()), _clock),
            new LicenseRepository(_fixture.Store, _clock,
                new LicenseNormalizer(_fixture.Store, NullLogger<LicenseNormalizer>.Instance)),
            _anchors,
            NullLogger<BlockGateService>.Instance,
            _clock);
    }

    // ── License arm: empty SPDX set ───────────────────────────────────────────

    [Fact]
    public async Task LicenseArm_BlockMode_NoRecordedLicenses_DeclaredLicenseEcosystem_Blocks()
    {
        // npm manifests carry a declared license field, so zero recorded entries means the signal
        // is missing — under an enforcing policy that is an unknown licence, not a free pass.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"lic-none-npm-{Guid.NewGuid():N}");
        await LicensePolicySeeder.AddAllowlistEntryAsync(_fixture.Store, orgId, "MIT");
        var req = BaseRequest(orgId) with { Ecosystem = "npm", LicenseEnforcementMode = "block" };

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_license"));

        // The activity detail names the absence explicitly rather than a concrete licence.
        await using var conn = await _fixture.Store.OpenAsync();
        string? detail = await conn.ExecuteScalarAsync<string?>(
            "SELECT detail FROM activity WHERE org_id = @orgId AND event_type = 'blocked_license'",
            new { orgId });
        Assert.Contains("NOASSERTION", detail);
    }

    [Fact]
    public async Task LicenseArm_BlockMode_NoRecordedLicenses_NonDeclaringEcosystem_Allows()
    {
        // Adversarial twin: go modules publish no declared licence field (proxy-side capture is
        // LICENSE-text classification only), so an empty entry set is the normal state. Denying
        // it would refuse every Go module under an enforcing policy.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"lic-none-go-{Guid.NewGuid():N}");
        await LicensePolicySeeder.AddAllowlistEntryAsync(_fixture.Store, orgId, "MIT");
        var req = BaseRequest(orgId) with
        {
            Ecosystem = "go",
            Purl = "pkg:golang/example.com/mod@v1.0.0",
            LicenseEnforcementMode = "block",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_license"));
    }

    [Fact]
    public async Task LicenseArm_BlockMode_RecordedAllowlistedLicense_Allows()
    {
        // Adversarial twin: the arm still passes an artifact whose recorded licence is allowed —
        // the new branch only fires on an absent signal, not on a present-and-permitted one.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"lic-mit-{Guid.NewGuid():N}");
        await LicensePolicySeeder.AddAllowlistEntryAsync(_fixture.Store, orgId, "MIT");
        string versionId = await SeedVersionAsync(orgId, "npm", "mit-pkg");
        await new LicenseRepository(_fixture.Store, _clock,
                new LicenseNormalizer(_fixture.Store, NullLogger<LicenseNormalizer>.Instance))
            .SetLicensesAsync(versionId, ["MIT"], "upstream");

        var req = BaseRequest(orgId) with
        {
            Ecosystem = "npm",
            VersionId = versionId,
            LicenseEnforcementMode = "block",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_license"));
    }

    [Fact]
    public async Task LicenseArm_WarnMode_NoRecordedLicenses_Allows()
    {
        // Adversarial twin: only 'block' enforces. An observe-only tenant keeps serving.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"lic-warn-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with { Ecosystem = "npm", LicenseEnforcementMode = "warn" };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_license"));
    }

    [Fact]
    public async Task LicenseArm_BlockMode_NoRecordedLicenses_ManualAllowOverrides()
    {
        // Adversarial twin: the operator override still wins over the unknown-licence denial,
        // matching every other arm's precedence.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"lic-manual-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            Ecosystem = "npm",
            LicenseEnforcementMode = "block",
            ManualState = "allowed",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_license"));
    }

    // ── Provenance arm: empty trust-anchor set under 'block' ──────────────────

    [Fact]
    public async Task ProvenanceArm_BlockMode_NoTrustAnchors_Blocks()
    {
        // The org enforces NuGet signature verification but has no anchor (deleted, expired and
        // not renewed, or never migrated). Nothing can produce a 'verified' verdict, so the
        // stored status is NULL for every artifact — which must deny, not pass.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"prov-none-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            Ecosystem = "nuget",
            Purl = "pkg:nuget/Some.Package@1.0.0",
            ProvenanceStatus = null,
            VerifyProvenanceMode = "block",
        };

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_provenance"));

        // The audit detail distinguishes "no anchor to verify against" from a real bad verdict.
        await using var conn = await _fixture.Store.OpenAsync();
        string? detail = await conn.ExecuteScalarAsync<string?>(
            "SELECT detail FROM activity WHERE org_id = @orgId AND event_type = 'blocked_provenance'",
            new { orgId });
        Assert.Contains(ProvenanceStatuses.Unverifiable, detail);
    }

    [Fact]
    public async Task ProvenanceArm_BlockMode_WithTrustAnchor_VerifiedStatus_Allows()
    {
        // Adversarial twin: once the org has an anchor the arm judges each artifact on its own
        // verdict again — a verified package is served.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"prov-ok-{Guid.NewGuid():N}");
        _anchors.AddPresenceAnchor(orgId, "nuget", "x509");
        var req = BaseRequest(orgId) with
        {
            Ecosystem = "nuget",
            Purl = "pkg:nuget/Some.Package@1.0.0",
            ProvenanceStatus = ProvenanceStatuses.Verified,
            VerifyProvenanceMode = "block",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_provenance"));
    }

    [Fact]
    public async Task ProvenanceArm_WarnMode_NoTrustAnchors_Allows()
    {
        // Adversarial twin: an unbacked policy only denies under 'block'. 'warn' is an
        // observe-only posture and must keep serving even with no anchors at all.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"prov-warn-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            Ecosystem = "nuget",
            Purl = "pkg:nuget/Some.Package@1.0.0",
            VerifyProvenanceMode = "warn",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_provenance"));
    }

    [Fact]
    public async Task ProvenanceArm_BlockMode_NoTrustAnchors_OtherEcosystemUnaffected()
    {
        // Adversarial twin: the check is per-ecosystem. An org holding an npm anchor but no NuGet
        // one is backed for npm; the npm artifact is not collateral damage of the NuGet gap.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"prov-eco-{Guid.NewGuid():N}");
        _anchors.AddPresenceAnchor(orgId, "npm");
        var req = BaseRequest(orgId) with
        {
            Ecosystem = "npm",
            ProvenanceStatus = ProvenanceStatuses.Verified,
            VerifyProvenanceMode = "block",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_provenance"));
    }

    [Fact]
    public void PureCore_UnverifiableStatus_IsNeverPersisted()
    {
        // The marker is synthesized at evaluation time from live anchor state; writing it to
        // provenance_status would let a stale row outlive the condition that produced it.
        Assert.Null(ProvenanceStatuses.ToColumn(ProvenanceStatus.NotApplicable));
        Assert.DoesNotContain(
            ProvenanceStatuses.Unverifiable,
            Enum.GetValues<ProvenanceStatus>().Select(ProvenanceStatuses.ToColumn).Where(c => c is not null)!);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private async Task<string> SeedVersionAsync(string orgId, string ecosystem, string name)
    {
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, ecosystem, name);
        return await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId, "1.0.0", $"pkg:{ecosystem}/{name}@1.0.0", origin: "proxy");
    }

    private static BlockGateRequest BaseRequest(string orgId) => new(
        OrgId: orgId,
        Ecosystem: "npm",
        Purl: "pkg:npm/test@1.0.0",
        VersionId: Guid.NewGuid().ToString("N"),
        ManualState: null,
        VulnCheckedAt: null,
        AuditActorId: null,
        MaxOsvScoreTolerance: 10.0,
        SourceIp: null);

    private async Task<long> CountActivityAsync(string orgId, string eventType)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM activity WHERE org_id = @orgId AND event_type = @eventType",
            new { orgId, eventType });
    }
}
