using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The OCI scan-enforcement arms in the block gate: the new <c>unscanned</c> arm (pure core and
/// its side effects), the posture's <c>warn</c> downgrade, the arm-scoped quarantine approval and
/// its reopen-on-a-later-advisory exception, and partial results as positive-only evidence. Each
/// enforcing assertion is paired with the twin showing what the arm must not do.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciScanGateArmTests : IClassFixture<InMemoryDbFixture>
{
    private static readonly DateTimeOffset Now = TestTime.KnownNow;

    private readonly InMemoryDbFixture _fixture;
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly BlockGateService _sut;

    public OciScanGateArmTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _sut = TestBlockGate.Create(_fixture.Store, _clock);
    }

    // ── Pure core ──────────────────────────────────────────────────────────────

    private static VersionFacts Facts(bool required, bool complete, bool scanned = false, VulnFacts? vuln = null)
        => new(
            ManualState: null, Deprecated: null, PublishedAt: null, Scanned: scanned,
            Vulnerability: vuln ?? VulnFacts.None,
            ScanRequired: required, ScanComplete: complete);

    private static BlockPolicy Policy(string? oci, string? kev = "off") => new(
        MinReleaseAgeHours: null, BlockDeprecatedMode: "off", BlockMaliciousMode: "off", BlockKevMode: kev,
        MaxEpssTolerance: null, MaxOsvScoreTolerance: 10.0, OciScanEnforcementMode: oci);

    [Fact]
    public void Unscanned_Refuses_WhenAScanIsRequiredAndAbsent_UnderBlock()
    {
        var verdict = BlockGateService.Evaluate(Facts(required: true, complete: false), Policy("block"), Now);

        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.Unscanned, verdict.Arm);
        Assert.Equal("unscanned", new BlockOutcome(BlockDecision.Blocked, verdict.Arm).ReasonToken);
    }

    [Fact]
    public void Unscanned_DoesNotFire_ForAnyOtherEcosystemsUnscannedWindow()
    {
        // Twin: the arm keys on ScanRequired, never on !Scanned. A non-OCI version that has not
        // been scanned yet stays fail-open even with the OCI posture at block.
        var verdict = BlockGateService.Evaluate(Facts(required: false, complete: false), Policy("block"), Now);

        Assert.True(verdict.Servable);
        Assert.Equal(BlockArm.None, verdict.WarnArm);
    }

    [Fact]
    public void Unscanned_Passes_ForACompleteResult()
    {
        var verdict = BlockGateService.Evaluate(
            Facts(required: true, complete: true, scanned: true), Policy("block"), Now);

        Assert.True(verdict.Servable);
    }

    [Fact]
    public void Unscanned_Warns_UnderWarn_AndServes()
    {
        var verdict = BlockGateService.Evaluate(Facts(required: true, complete: false), Policy("warn"), Now);

        Assert.True(verdict.Servable);
        Assert.Equal(BlockArm.Unscanned, verdict.WarnArm);
    }

    [Fact]
    public void AnAdvisoryArm_OutranksUnscanned_OnAPartialResult()
    {
        // A partial result enforces every advisory it did find: a KEV hit reports kev.
        var verdict = BlockGateService.Evaluate(
            Facts(required: true, complete: false, scanned: true, vuln: VulnFacts.None with { IsKev = true }),
            Policy("block", kev: "block"), Now);

        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.Kev, verdict.Arm);
    }

    [Fact]
    public void AManualAllow_ShortCircuitsUnscanned()
    {
        var verdict = BlockGateService.Evaluate(
            Facts(required: true, complete: false) with { ManualState = "allowed" }, Policy("block"), Now);

        Assert.True(verdict.Servable);
        Assert.Equal(BlockArm.None, verdict.WarnArm);
    }

    // ── EvaluateAsync through ForOciImage ───────────────────────────────────────

    private static OrgSettings Settings(string posture, string kev = "off") => new()
    {
        OciScanEnforcement = posture,
        BlockKev = kev,
        BlockMalicious = "block",
        MaxOsvScoreTolerance = 10.0,
    };

    private static OciGateFacts Partial(VulnFacts vuln, int gaps = 1) =>
        new(HasResult: true, GapCount: gaps, Signals: new VulnGateSignals(vuln)) { KevOsvIds = ["DSA-1-1"] };

    private static BlockGateRequest Request(string orgId, string purl, OciGateFacts facts, OrgSettings settings, string? manual = null)
        => BlockGateRequest.ForOciImage(orgId, purl, facts, manual, token: null, settings, "203.0.113.9", []);

    [Fact]
    public async Task APartialResult_WithAWarnModeKev_IsRefusedAsUnscanned_AndRecordsTheWarnedArm()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"oci-partial-{Guid.NewGuid():N}");
        string purl = PurlNormalizer.Oci("team/app", "sha256:" + new string('a', 64));
        var request = Request(orgId, purl, Partial(VulnFacts.None with { IsKev = true }), Settings("block", kev: "warn"));

        var outcome = await _sut.EvaluateAsync(request);

        Assert.Equal(BlockArm.Unscanned, outcome.Arm);
        string? detail = await ScalarAsync<string?>(
            "SELECT detail FROM activity WHERE org_id = @orgId AND event_type = 'blocked_unscanned'", new { orgId });
        Assert.Contains("\"sub_reason\":\"partial\"", detail);
        Assert.Contains("\"warned_arms\":[\"kev\"]", detail);
        // A refusal subsumes the warning: no separate gate_warned row.
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM activity WHERE org_id = @orgId AND event_type = 'gate_warned'", new { orgId }));
        Assert.Equal("unscanned", await ScalarAsync<string?>(
            "SELECT gate FROM quarantine WHERE org_id = @orgId AND purl = @purl AND state = 'pending'", new { orgId, purl }));
    }

    [Theory]
    [InlineData(false, true, "absent")]
    [InlineData(false, false, "no_scanner")]
    public async Task AnAbsentResult_RecordsItsSubReason(bool hasResult, bool scannerLive, string expected)
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"oci-absent-{Guid.NewGuid():N}");
        string purl = PurlNormalizer.Oci("team/app", "sha256:" + new string('b', 64));
        var facts = hasResult ? Partial(VulnFacts.None) : OciGateFacts.Absent(scannerLive);

        var outcome = await _sut.EvaluateAsync(Request(orgId, purl, facts, Settings("block")));

        Assert.Equal(BlockArm.Unscanned, outcome.Arm);
        Assert.Contains($"\"sub_reason\":\"{expected}\"", await ScalarAsync<string?>(
            "SELECT detail FROM activity WHERE org_id = @orgId AND event_type = 'blocked_unscanned'", new { orgId }));
    }

    [Fact]
    public async Task WarnPosture_ServesAnUnscannedImage_AndRecordsGateWarned()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"oci-warn-{Guid.NewGuid():N}");
        string purl = PurlNormalizer.Oci("team/app", "sha256:" + new string('c', 64));

        var outcome = await _sut.EvaluateAsync(Request(orgId, purl, OciGateFacts.Absent(true), Settings("warn")));

        Assert.Equal(BlockDecision.Allowed, outcome.Decision);
        Assert.Contains("\"arm\":\"unscanned\"", await ScalarAsync<string?>(
            "SELECT detail FROM activity WHERE org_id = @orgId AND event_type = 'gate_warned'", new { orgId }));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM quarantine WHERE org_id = @orgId", new { orgId }));
    }

    [Fact]
    public async Task WarnPosture_DowngradesABlockModeAdvisoryArm_ToAWarning()
    {
        // 'warn' writes gate_warned naming the arm 'block' would have refused with, so a fleet can
        // learn what the switch would do before it breaks any build.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"oci-warn-kev-{Guid.NewGuid():N}");
        string purl = PurlNormalizer.Oci("team/app", "sha256:" + new string('d', 64));
        var facts = new OciGateFacts(true, 0, new VulnGateSignals(VulnFacts.None with { IsKev = true }));

        var outcome = await _sut.EvaluateAsync(Request(orgId, purl, facts, Settings("warn", kev: "block")));

        Assert.Equal(BlockDecision.Allowed, outcome.Decision);
        Assert.Contains("\"arm\":\"kev\"", await ScalarAsync<string?>(
            "SELECT detail FROM activity WHERE org_id = @orgId AND event_type = 'gate_warned'", new { orgId }));
    }

    [Fact]
    public async Task BlockPosture_RefusesTheSameKev()
    {
        // Twin of the warn downgrade above.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"oci-block-kev-{Guid.NewGuid():N}");
        string purl = PurlNormalizer.Oci("team/app", "sha256:" + new string('e', 64));
        var facts = new OciGateFacts(true, 0, new VulnGateSignals(VulnFacts.None with { IsKev = true })) { KevOsvIds = ["CVE-X"] };

        var outcome = await _sut.EvaluateAsync(Request(orgId, purl, facts, Settings("block", kev: "block")));

        Assert.Equal(BlockArm.Kev, outcome.Arm);
        // The detail names the advisory from the org's own scan, not a shared-plane lookup.
        Assert.Contains("CVE-X", await ScalarAsync<string?>(
            "SELECT detail FROM activity WHERE org_id = @orgId AND event_type = 'blocked_kev'", new { orgId }));
    }

    [Fact]
    public async Task AnApprovalPastUnscanned_WaivesThatArmOnly_AndALaterKevReopensTheRow()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"oci-approve-{Guid.NewGuid():N}");
        string purl = PurlNormalizer.Oci("team/app", "sha256:" + new string('f', 64));
        var settings = Settings("block", kev: "block");

        Assert.Equal(BlockArm.Unscanned,
            (await _sut.EvaluateAsync(Request(orgId, purl, OciGateFacts.Absent(true), settings))).Arm);

        var quarantine = new QuarantineRepository(_fixture.Store, _clock);
        string rowId = (await ScalarAsync<string?>("SELECT id FROM quarantine WHERE org_id = @orgId AND purl = @purl", new { orgId, purl }))!;
        Assert.True(await quarantine.DecideAsync(orgId, rowId, "approved", null, "ok to pull", default));

        // Approved past the missing scan: served.
        Assert.Equal(BlockDecision.Allowed,
            (await _sut.EvaluateAsync(Request(orgId, purl, OciGateFacts.Absent(true), settings))).Decision);

        // A KEV finding lands on the same digest: the approval was about a different arm.
        var kev = new OciGateFacts(true, 0, new VulnGateSignals(VulnFacts.None with { IsKev = true }));
        Assert.Equal(BlockArm.Kev, (await _sut.EvaluateAsync(Request(orgId, purl, kev, settings))).Arm);

        var row = await _fixture.Store.OpenAsync();
        await using (row)
        {
            var (gate, state, decidedAt, note) = await row.QuerySingleAsync<(string Gate, string State, string? DecidedAt, string? Note)>(
                "SELECT gate AS Gate, state AS State, decided_at AS DecidedAt, note AS Note FROM quarantine WHERE id = @rowId",
                new { rowId });
            Assert.Equal("kev", gate);
            Assert.Equal("pending", state);
            Assert.Null(decidedAt);
            Assert.Null(note);
        }

        // And the reopened row no longer waives the unscanned arm either.
        Assert.False(await quarantine.HasApprovedForGateAsync(orgId, purl, BlockGateService.UnscannedGate));
    }

    [Fact]
    public async Task AnApprovalUnderAnotherGate_DoesNotWaiveUnscanned()
    {
        // Twin: the approval is read back by gate. An approved licence row on the same purl is not
        // an approval past the missing scan.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"oci-other-gate-{Guid.NewGuid():N}");
        string purl = PurlNormalizer.Oci("team/app", "sha256:" + new string('1', 64));
        var quarantine = new QuarantineRepository(_fixture.Store, _clock);
        var up = await quarantine.UpsertPendingAsync(orgId, "oci", purl, "license", null, null);
        Assert.True(await quarantine.DecideAsync(orgId, up.RowId, "approved", null, null, default));

        var outcome = await _sut.EvaluateAsync(Request(orgId, purl, OciGateFacts.Absent(true), Settings("block")));

        Assert.Equal(BlockArm.Unscanned, outcome.Arm);
    }

    [Fact]
    public async Task ADecidedRowOfAnotherGate_IsNotReopened()
    {
        // Twin of the reopen: only a decided 'unscanned' row is reopened, never any other decision.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"oci-no-reopen-{Guid.NewGuid():N}");
        string purl = PurlNormalizer.Oci("team/app", "sha256:" + new string('2', 64));
        var quarantine = new QuarantineRepository(_fixture.Store, _clock);
        var up = await quarantine.UpsertPendingAsync(orgId, "oci", purl, "license", null, null);
        Assert.True(await quarantine.DecideAsync(orgId, up.RowId, "denied", null, null, default));

        var kev = new OciGateFacts(true, 0, new VulnGateSignals(VulnFacts.None with { IsKev = true }));
        Assert.Equal(BlockArm.Kev, (await _sut.EvaluateAsync(Request(orgId, purl, kev, Settings("block", kev: "block")))).Arm);

        Assert.Equal("denied", await ScalarAsync<string?>("SELECT state FROM quarantine WHERE id = @id", new { id = up.RowId }));
    }

    [Fact]
    public async Task AManualAllow_ShortCircuitsEveryArm_ForAnOciImage()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"oci-manual-{Guid.NewGuid():N}");
        string purl = PurlNormalizer.Oci("team/app", "sha256:" + new string('3', 64));
        var kev = new OciGateFacts(true, 0, new VulnGateSignals(VulnFacts.None with { IsKev = true }));

        var outcome = await _sut.EvaluateAsync(Request(orgId, purl, kev, Settings("block", kev: "block"), manual: "allowed"));

        Assert.Equal(BlockDecision.Allowed, outcome.Decision);
    }

    private async Task<T?> ScalarAsync<T>(string sql, object args)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<T>(sql, args);
    }

    private async Task<int> CountAsync(string sql, object args) => await ScalarAsync<int>(sql, args);
}
