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
/// Pins the behaviour that makes a suspect trust anchor an operator decision rather than a
/// cleanup script's.
///
/// <para>
/// A row whose <c>(ecosystem, anchor_kind)</c> pair has no registered material validator holds
/// bytes nothing ever parsed. For rpm, maven, npm, nuget and apk,
/// <see cref="PerOrgTrustAnchorStore.IsConfiguredForAsync"/> tests only whether <em>any</em> row
/// exists for the ecosystem — not its kind, not whether the material parses — so such a row makes
/// <c>verify_*_signatures='block'</c> read as backed. Every artifact of that ecosystem then
/// resolves to a not-applicable verdict (NULL <c>provenance_status</c>), which is not in the
/// blocking set, so the policy silently passes everything.
/// </para>
///
/// <para>
/// Deleting that row — when it is the org's only anchor for the ecosystem — flips
/// <see cref="BlockGateService.IsProvenanceEnforcementUnbackedAsync"/> to true on the very next
/// check, which synthesizes the blocking <see cref="ProvenanceStatuses.Unverifiable"/> marker and
/// denies 100% of that ecosystem's traffic. There is no intermediate state. That step change is
/// why no migration, schema step, or background job touches <c>signature_trust_anchor</c>: the
/// audit surfaces the row and an operator decides.
/// </para>
///
/// <para>
/// PyPI is exempt from the first half: its <see cref="PyPiTrustMaterial.IsConfigured"/> is
/// computed from actually-parsed roots and publishers, so a suspect PyPI row was never counted as
/// configured and enforcement was denying all along.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SuspectTrustAnchorDeletionFlipTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public SuspectTrustAnchorDeletionFlipTests(InMemoryDbFixture fixture) => _fixture = fixture;

    // Real repository + real store (no IMemoryCache, so a delete is visible on the next read
    // rather than up to the cache TTL later). Nothing here is a test double: the whole point is
    // to exercise the production presence-only IsConfiguredFor semantics.
    private TrustAnchorRepository NewRepo() => new(_fixture.Store, _clock);

    private PerOrgTrustAnchorStore NewStore() =>
        new(NewRepo(), NullLogger<PerOrgTrustAnchorStore>.Instance);

    private BlockGateService NewGate(IPerOrgTrustAnchorStore anchors) => new(
        new VulnerabilityRepository(_fixture.Store, _clock),
        new AuditRepository(_fixture.Store),
        new QuarantineRepository(_fixture.Store, _clock),
        new AlertService(new AlertRepository(_fixture.Store, _clock), new NoOpAlertNotifier(),
            NullLogger<AlertService>.Instance),
        new InstallScriptAllowlistService(_fixture.Store, new MemoryCache(new MemoryCacheOptions()), _clock),
        new LicenseRepository(_fixture.Store, _clock,
            new LicenseNormalizer(_fixture.Store, NullLogger<LicenseNormalizer>.Instance)),
        anchors,
        NullLogger<BlockGateService>.Instance,
        _clock);

    // The pure policy core under a 'block' provenance policy, with every other arm neutral, so
    // the verdict isolates the provenance arm.
    private BlockVerdict EvaluateProvenanceArm(string? provenanceStatus) =>
        BlockGateService.Evaluate(
            new VersionFacts(
                ManualState: null,
                Deprecated: null,
                PublishedAt: null,
                Scanned: false,
                HasMalicious: false,
                HasKev: false,
                MaxEpss: null,
                MaxCvss: null,
                ProvenanceStatus: provenanceStatus),
            new BlockPolicy(
                MinReleaseAgeHours: null,
                BlockDeprecatedMode: null,
                BlockMaliciousMode: null,
                BlockKevMode: null,
                MaxEpssTolerance: null,
                MaxOsvScoreTolerance: 10.0,
                VerifyProvenanceMode: "block"),
            _clock.GetUtcNow());

    // ── The deletion flip ─────────────────────────────────────────────────────

    /// <summary>
    /// The full trace, for each of the five ecosystems whose IsConfiguredFor is presence-only.
    /// Seeds one garbage row under an unregistered pair — exactly the shape a pre-validation
    /// insert produced — with verify mode 'block', then deletes it.
    /// </summary>
    [Theory]
    [InlineData("rpm", "spki")]
    [InlineData("maven", "x509")]
    [InlineData("npm", "pgp")]
    [InlineData("nuget", "rsa")]
    [InlineData("apk", "pgp")]
    public async Task SuspectAnchor_IsPhantomBacking_AndItsDeletionFlipsTheEcosystemToDenyAll(
        string ecosystem, string unregisteredKind)
    {
        Assert.False(TrustAnchorPairs.IsRegistered(ecosystem, unregisteredKind),
            "the seeded pair must be one the add path rejects, or the test proves nothing");

        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"flip-{ecosystem}-{Guid.NewGuid():N}");
        var repo = NewRepo();
        var gate = NewGate(NewStore());

        // Bypasses the controller's validator on purpose: the repository is the only way to
        // reproduce a row that predates the insert-time pair gate.
        var seeded = await repo.AddAsync(orgId, new NewTrustAnchor(
            Ecosystem: ecosystem,
            AnchorKind: unregisteredKind,
            Material: "this is not key material of any kind",
            KeyId: null,
            Label: "pre-validation paste",
            CreatedBy: "operator-1"));

        // ── Before: the org LOOKS backed, so enforcement does nothing ──────────
        Assert.False(
            await gate.IsProvenanceEnforcementUnbackedAsync(orgId, ecosystem, "block"),
            "presence-only IsConfiguredFor counts the garbage row as a configured anchor");

        // No verifier can produce a verdict from that material, so the stored status is NULL
        // (NotApplicable) — and NULL is not in the blocking set, so the artifact serves.
        var before = EvaluateProvenanceArm(null);
        Assert.True(before.Servable);
        Assert.Equal(BlockArm.None, before.Arm);

        // ── After: deleting the row denies every artifact of that ecosystem ────
        await repo.DeleteAsync(orgId, seeded.Id);

        Assert.True(
            await gate.IsProvenanceEnforcementUnbackedAsync(orgId, ecosystem, "block"),
            "with the only anchor gone, enforcement is unbacked and must deny");

        // Which is what the gate synthesizes 'unverifiable' for — and 'unverifiable' blocks.
        var after = EvaluateProvenanceArm(ProvenanceStatuses.Unverifiable);
        Assert.False(after.Servable);
        Assert.Equal(BlockArm.Provenance, after.Arm);
    }

    /// <summary>
    /// The same trace through the real <see cref="BlockGateService.EvaluateAsync"/> entry point,
    /// so the flip is pinned end to end and not only through the pure core.
    /// </summary>
    [Fact]
    public async Task DeletionFlip_ShowsThroughTheLiveEvaluateAsyncPath()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"flip-live-{Guid.NewGuid():N}");
        var repo = NewRepo();
        var gate = NewGate(NewStore());

        var seeded = await repo.AddAsync(orgId, new NewTrustAnchor(
            "npm", "pgp", "not key material", null, null, null));

        var request = new BlockGateRequest(
            OrgId: orgId,
            Ecosystem: "npm",
            Purl: "pkg:npm/flip@1.0.0",
            VersionId: Guid.NewGuid().ToString("N"),
            ManualState: null,
            VulnCheckedAt: null,
            AuditActorId: null,
            MaxOsvScoreTolerance: 10.0,
            SourceIp: null) with
        { VerifyProvenanceMode = "block" };

        Assert.Equal(BlockDecision.Allowed, await gate.EvaluateAsync(request));

        await repo.DeleteAsync(orgId, seeded.Id);

        Assert.Equal(BlockDecision.Blocked, await gate.EvaluateAsync(request));
    }

    // ── PyPI: immune, because IsConfigured is computed from parsed material ───

    /// <summary>
    /// Contrast case. A PyPI row under a valid ecosystem but an unregistered kind never counts as
    /// configured, so enforcement was denying before the delete and denies after it — the same
    /// verdict on both sides, no flip.
    /// </summary>
    [Fact]
    public async Task PyPi_SuspectAnchor_NeverCountsAsConfigured_SoThereIsNoFlip()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"flip-pypi-{Guid.NewGuid():N}");
        var repo = NewRepo();
        var store = NewStore();
        var gate = NewGate(store);

        // 'spki' is a real anchor_kind value but is not registered for pypi.
        Assert.False(TrustAnchorPairs.IsRegistered("pypi", "spki"));
        var seeded = await repo.AddAsync(orgId, new NewTrustAnchor(
            "pypi", "spki", "this is not key material of any kind", null, null, null));

        // The generic presence test is fooled exactly as it is for the other five...
        Assert.True(await store.IsConfiguredForAsync(orgId, "pypi"));

        // ...but the gate does not use it for pypi: PyPiTrustMaterial.IsConfigured counts parsed
        // roots and publishers, and a garbage row contributes neither.
        Assert.False((await store.GetPyPiTrustAsync(orgId)).IsConfigured);
        Assert.True(await gate.IsProvenanceEnforcementUnbackedAsync(orgId, "pypi", "block"));

        await repo.DeleteAsync(orgId, seeded.Id);

        // Same verdict after the delete — the state never changed.
        Assert.False((await store.GetPyPiTrustAsync(orgId)).IsConfigured);
        Assert.True(await gate.IsProvenanceEnforcementUnbackedAsync(orgId, "pypi", "block"));
    }

    // ── Class B: a mislabelled row that is a live, working anchor ─────────────

    /// <summary>
    /// The reason "delete every unregistered pair" is wrong even where the flip is acceptable.
    /// npm's SPKI map keys on <c>key_id</c> and parse success, never on <c>anchor_kind</c>, so a
    /// row stored under the wrong kind label whose material is a well-formed npm SPKI is a real
    /// trust anchor that is verifying signatures right now.
    /// </summary>
    [Fact]
    public async Task Npm_MislabelledRow_WithParseableMaterial_IsStillALiveAnchor()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"flip-classb-{Guid.NewGuid():N}");
        var repo = NewRepo();
        var store = NewStore();

        // A genuine base64 SPKI DER for an ECDSA P-256 key — what an operator pastes from the
        // npm registry's /-/npm/v1/keys response.
        using var ecdsa = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        string spki = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
        const string KeyId = "SHA256:mislabelled-but-working";

        Assert.False(TrustAnchorPairs.IsRegistered("npm", "pgp"));
        await repo.AddAsync(orgId, new NewTrustAnchor("npm", "pgp", spki, KeyId, null, null));

        var keys = await store.GetNpmKeysAsync(orgId);
        Assert.True(keys.ContainsKey(KeyId),
            "BuildSpkiMap never filters on anchor_kind, so a mislabelled but parseable row verifies");
        Assert.Equal(ecdsa.ExportSubjectPublicKeyInfo(), keys[KeyId]);

        // And it is reported as suspect all the same — the audit reports, it does not judge.
        var suspects = await repo.ListSuspectAsync();
        Assert.Contains(suspects, s => s.OrgId == orgId && s.KeyId == KeyId);
    }

    // ── Adversarial twin: a registered pair is untouched by any of this ───────

    /// <summary>
    /// Proves the audit and the flip trace are not simply firing on every row: a properly
    /// registered npm/spki anchor is neither reported suspect nor treated as unbacked.
    /// </summary>
    [Fact]
    public async Task RegisteredPair_IsNeitherSuspectNorUnbacked()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"flip-ok-{Guid.NewGuid():N}");
        var repo = NewRepo();
        var gate = NewGate(NewStore());

        using var ecdsa = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        string spki = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());

        await repo.AddAsync(orgId, new NewTrustAnchor("npm", "spki", spki, "SHA256:good", null, null));

        Assert.False(await gate.IsProvenanceEnforcementUnbackedAsync(orgId, "npm", "block"));
        Assert.DoesNotContain(await repo.ListSuspectAsync(), s => s.OrgId == orgId);
    }
}
