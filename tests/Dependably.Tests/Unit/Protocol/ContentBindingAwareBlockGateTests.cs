using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Protocol;
using Dependably.Protocol.Provenance;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// A proxy tenant whose content binding diverges from the shared <c>cache_artifact</c> row must
/// never be gated on findings computed against another tenant's bytes (#545, the vuln-scanning
/// follow-up to #542's per-tenant content binding). Each test pairs a divergent coordinate with
/// its adversarial twin — the SAME shared-row facts, but a tenant whose binding matches the
/// shared row — to prove the fix does not accidentally treat every proxy artifact as unscanned.
///
/// The four byte-derived facts get different treatments, chosen by whether they are actually
/// derived from bytes at all:
///   - vuln_checked_at (and the malicious/KEV/EPSS/CVSS arms it gates): read UNMASKED. OSV
///     findings are keyed by package coordinate (ecosystem/name/version) — OsvClient/LocalOsvSource
///     query by PURL, never by hash — so a MAL- advisory, a KEV entry, an EPSS score, and a CVSS
///     score are facts about "lodash 4.17.21", identical for every tenant regardless of whose
///     upstream served the bytes. Content divergence does not invalidate them.
///   - has_install_script: forced true (fail-closed) on divergence, but only for the ecosystems
///     <see cref="ScriptDetectionService"/> actually computes it for (npm/pypi/nuget/rpm) — every
///     other ecosystem's value is <see langword="false"/> by construction, not by absent evidence,
///     so forcing it there would fabricate a signal that ecosystem structurally cannot carry.
///   - provenance_status: forced to the existing `unverifiable` marker (fail-closed under
///     'block') on the cache-hit path; the first-fetch path prefers this tenant's own
///     just-computed verdict over the masked shared-row value when it has one.
///   - license entries: read as empty, which resolves through the existing per-ecosystem
///     zero-entries posture (block for DeclaredLicenseEcosystems, pass-through otherwise).
/// </summary>
[Trait("Category", "Unit")]
public sealed class ContentBindingAwareBlockGateTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly BlockGateService _sut;
    private readonly CacheArtifactRepository _cacheArtifacts;
    private readonly TenantArtifactAccessRepository _access;
    private readonly VulnerabilityRepository _vulns;
    private readonly StubPerOrgTrustAnchorStore _anchors = new();

    public ContentBindingAwareBlockGateTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _cacheArtifacts = new CacheArtifactRepository(_fixture.Store);
        _access = new TenantArtifactAccessRepository(_fixture.Store);
        _vulns = new VulnerabilityRepository(_fixture.Store, _clock);
        _sut = new BlockGateService(
            _vulns,
            new AuditRepository(_fixture.Store),
            new QuarantineRepository(_fixture.Store, _clock),
            new AlertService(new AlertRepository(_fixture.Store, _clock), new NoOpAlertNotifier(), Microsoft.Extensions.Logging.Abstractions.NullLogger<AlertService>.Instance),
            new InstallScriptAllowlistService(_fixture.Store, new Microsoft.Extensions.Caching.Memory.MemoryCache(new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()), _clock),
            new LicenseRepository(_fixture.Store, _clock, new LicenseNormalizer(_fixture.Store, Microsoft.Extensions.Logging.Abstractions.NullLogger<LicenseNormalizer>.Instance)),
            _anchors,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<BlockGateService>.Instance,
            _clock);
    }

    // ── install-script arm: fail-closed on divergence, scoped to detecting ecosystems ──

    [Fact]
    public async Task Divergent_Npm_InstallScriptGate_StillBlocks()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cba-is-div-{Guid.NewGuid():N}");
        var caFacts = await SeedCacheFactsAsync(
            orgId, "npm", Coordinate(), divergent: true, hasInstallScript: false);

        var req = BlockGateRequest.ForProxyCacheFacts(orgId, "npm", caFacts, token: null, settings: null, sourceIp: null)
            with
        { BlockInstallScriptsMode = "block" };

        // The shared row genuinely has no install script — on the pre-#545 code this reads
        // HasInstallScript=false straight off the shared row and serves. Post-fix, a diverging
        // npm tenant carries no evidence of its own and is denied.
        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_install_script"));
    }

    [Fact]
    public async Task NonDivergent_Npm_InstallScriptGate_Serves()
    {
        // Adversarial twin: identical shared-row facts, but this tenant's binding matches the
        // shared row (no divergence) — the real "no install script" fact must still apply.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cba-is-ok-{Guid.NewGuid():N}");
        var caFacts = await SeedCacheFactsAsync(
            orgId, "npm", Coordinate(), divergent: false, hasInstallScript: false);

        var req = BlockGateRequest.ForProxyCacheFacts(orgId, "npm", caFacts, token: null, settings: null, sourceIp: null)
            with
        { BlockInstallScriptsMode = "block" };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_install_script"));
    }

    [Fact]
    public async Task Divergent_Cargo_InstallScriptGate_NotForced_BecauseCargoNeverComputesIt()
    {
        // Cargo is outside ScriptDetectionService.SupportedEcosystems — its HasInstallScript is
        // false by construction, not by absent evidence (CargoController.Serve.cs always passes
        // hasInstallScript: false; the detector never runs for this ecosystem at all). Forcing it
        // true on divergence would force-block every diverging Cargo fetch under a 'block' policy
        // over a concept Cargo cannot carry — the interaction the ecosystem scoping exists to
        // prevent.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cba-is-cargo-{Guid.NewGuid():N}");
        var caFacts = await SeedCacheFactsAsync(
            orgId, "cargo", Coordinate(), divergent: true, hasInstallScript: false);

        var req = BlockGateRequest.ForProxyCacheFacts(orgId, "cargo", caFacts, token: null, settings: null, sourceIp: null)
            with
        { BlockInstallScriptsMode = "block" };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_install_script"));
    }

    // ── provenance arm: fail-closed on divergence (cache-hit path) ──────────────

    [Fact]
    public async Task Divergent_SharedRowVerified_ProvenanceGate_StillBlocks()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cba-prov-div-{Guid.NewGuid():N}");
        // A configured trust anchor isolates the divergence-specific behaviour under test from
        // IsProvenanceEnforcementUnbackedAsync's separate (and separately tested) "no anchor at
        // all" denial — without it every 'block' assertion here would pass for the wrong reason.
        _anchors.AddPresenceAnchor(orgId, "npm");
        var caFacts = await SeedCacheFactsAsync(
            orgId, "npm", Coordinate(), divergent: true, provenanceStatus: "verified");

        var req = BlockGateRequest.ForProxyCacheFacts(orgId, "npm", caFacts, token: null, settings: null, sourceIp: null)
            with
        { VerifyProvenanceMode = "block" };

        // The shared row's signature genuinely verified — pre-#545 that "verified" status would
        // read straight through and serve. Post-fix, a diverging tenant's provenance is unknown on
        // the cache-hit path (forced to the same "unverifiable" marker unbacked enforcement
        // already uses) and denied — there is no fresher evidence available at cache-hit time.
        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_provenance"));
    }

    [Fact]
    public async Task NonDivergent_SharedRowVerified_ProvenanceGate_Serves()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cba-prov-ok-{Guid.NewGuid():N}");
        _anchors.AddPresenceAnchor(orgId, "npm");
        var caFacts = await SeedCacheFactsAsync(
            orgId, "npm", Coordinate(), divergent: false, provenanceStatus: "verified");

        var req = BlockGateRequest.ForProxyCacheFacts(orgId, "npm", caFacts, token: null, settings: null, sourceIp: null)
            with
        { VerifyProvenanceMode = "block" };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_provenance"));
    }

    [Fact]
    public async Task ForProxyFirstFetch_Divergent_PrefersOwnFreshProvenanceVerdict_OverMaskedSharedRow()
    {
        // First-fetch has strictly better evidence than the cache-hit path: this tenant's OWN
        // provenance verdict, computed moments ago over the bytes it just staged. The shared row
        // may carry an earlier tenant's status (UpdateGlobalFactsAsync's COALESCE keeps whichever
        // arrived first) and EffectiveProvenanceStatus would mask it to Unverifiable on divergence
        // regardless — ForProxyFirstFetch's ownProvenanceStatus parameter must not discard that.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cba-prov-ff-{Guid.NewGuid():N}");
        _anchors.AddPresenceAnchor(orgId, "npm");
        // Shared row carries a foreign 'failed' verdict (an earlier tenant's) so the masked value
        // (Unverifiable) and the raw shared value (Failed) would both wrongly deny this tenant,
        // proving the fix reads the passed-in verdict rather than falling through to either.
        var caFacts = await SeedCacheFactsAsync(
            orgId, "npm", Coordinate(), divergent: true, provenanceStatus: "failed");

        var req = BlockGateRequest.ForProxyFirstFetch(
            orgId, "npm", caFacts,
            userId: null, actorKind: null, sourceIp: null,
            maxOsvScoreTolerance: 10.0,
            minReleaseAgeHours: null,
            blockDeprecatedMode: null,
            blockMaliciousMode: null,
            blockKevMode: null,
            maxEpssTolerance: null,
            blockInstallScriptsMode: null,
            verifyProvenanceMode: "block",
            blockRevokedMode: null,
            licenseEnforcementMode: null,
            ownProvenanceStatus: "verified");

        Assert.Equal("verified", req.ProvenanceStatus);
        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_provenance"));
    }

    [Fact]
    public async Task ForProxyFirstFetch_Divergent_NoOwnVerdict_FallsBackToMaskedSharedRow()
    {
        // Adversarial twin: when the caller has no fresh verdict of its own (ownProvenanceStatus
        // null — the ecosystem does not verify provenance on this path, or verification was not
        // attempted), the existing masked-on-divergence behaviour still applies. This must not
        // regress into always trusting the shared row.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cba-prov-ff-fallback-{Guid.NewGuid():N}");
        _anchors.AddPresenceAnchor(orgId, "npm");
        var caFacts = await SeedCacheFactsAsync(
            orgId, "npm", Coordinate(), divergent: true, provenanceStatus: "verified");

        var req = BlockGateRequest.ForProxyFirstFetch(
            orgId, "npm", caFacts,
            userId: null, actorKind: null, sourceIp: null,
            maxOsvScoreTolerance: 10.0,
            minReleaseAgeHours: null,
            blockDeprecatedMode: null,
            blockMaliciousMode: null,
            blockKevMode: null,
            maxEpssTolerance: null,
            blockInstallScriptsMode: null,
            verifyProvenanceMode: "block",
            blockRevokedMode: null,
            licenseEnforcementMode: null,
            ownProvenanceStatus: null);

        Assert.Equal(ProvenanceStatuses.Unverifiable, req.ProvenanceStatus);
        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
    }

    // ── vuln/malicious arm: unmasked — OSV findings are coordinate-keyed, not byte-keyed ─

    [Fact]
    public async Task Divergent_SharedRowScannedAndMalicious_VulnGate_StillBlocks()
    {
        // OsvClient/LocalOsvSource query by PURL (ecosystem/name/version), never by content hash —
        // a MAL- advisory is a fact about the coordinate, so it applies identically to a diverging
        // tenant. #545 does NOT mask vuln_checked_at/HasMalicious on divergence; masking it would
        // turn a real "block" into an "allow" for a coordinate an org has explicitly configured to
        // block on malicious advisories (the F1 regression this test pins).
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cba-mal-div-{Guid.NewGuid():N}");
        var caFacts = await SeedCacheFactsAsync(
            orgId, "cargo", Coordinate(), divergent: true, scanned: true);
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"MAL-2026-{Guid.NewGuid():N}", severity: null, cvssScore: null);
        await VulnerabilitySeeder.LinkToCacheArtifactAsync(_fixture.Store, caFacts.Id, vulnId);

        var req = BlockGateRequest.ForProxyCacheFacts(orgId, "cargo", caFacts, token: null, settings: null, sourceIp: null)
            with
        { BlockMaliciousMode = "block" };

        Assert.NotNull(req.VulnCheckedAt);
        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_malicious"));
    }

    [Fact]
    public async Task NonDivergent_SharedRowScannedAndMalicious_VulnGate_StillBlocks()
    {
        // Adversarial twin: the same malicious finding on the same shared row, for a tenant whose
        // binding matches it — must block identically to the diverging tenant above (parity, not
        // "everything proxy is unscanned").
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cba-mal-ok-{Guid.NewGuid():N}");
        var caFacts = await SeedCacheFactsAsync(
            orgId, "cargo", Coordinate(), divergent: false, scanned: true);
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"MAL-2026-{Guid.NewGuid():N}", severity: null, cvssScore: null);
        await VulnerabilitySeeder.LinkToCacheArtifactAsync(_fixture.Store, caFacts.Id, vulnId);

        var req = BlockGateRequest.ForProxyCacheFacts(orgId, "cargo", caFacts, token: null, settings: null, sourceIp: null)
            with
        { BlockMaliciousMode = "block" };

        Assert.NotNull(req.VulnCheckedAt);
        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_malicious"));
    }

    [Fact]
    public async Task Divergent_SharedRowScannedAndClean_VulnGate_StillServes()
    {
        // Symmetric case: a genuinely clean, scanned coordinate serves a diverging tenant exactly
        // as it serves a non-diverging one — divergence changes nothing about a coordinate-level
        // fact either way.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cba-clean-div-{Guid.NewGuid():N}");
        var caFacts = await SeedCacheFactsAsync(
            orgId, "cargo", Coordinate(), divergent: true, scanned: true);

        var req = BlockGateRequest.ForProxyCacheFacts(orgId, "cargo", caFacts, token: null, settings: null, sourceIp: null)
            with
        { BlockMaliciousMode = "block", MaxOsvScoreTolerance = 7.0 };

        Assert.NotNull(req.VulnCheckedAt);
        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
    }

    // ── license arm: unknown-license posture on divergence (existing precedent) ─

    [Fact]
    public async Task Divergent_SharedRowAllowlistedLicense_LicenseGate_StillBlocksAsUnknown()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cba-lic-div-{Guid.NewGuid():N}");
        // MIT is explicitly allowlisted, so the shared row's real entry would pass under 'block'
        // — isolating this from a "nothing is allowlisted" case (which blocks identically whether
        // or not #545 shipped, and so proves nothing about this change).
        await LicensePolicySeeder.AddAllowlistEntryAsync(_fixture.Store, orgId, "MIT");
        var caFacts = await SeedCacheFactsAsync(orgId, "npm", Coordinate(), divergent: true);
        await SeedLicenseAsync(caFacts.Id, "MIT");

        var req = BlockGateRequest.ForProxyCacheFacts(orgId, "npm", caFacts, token: null, settings: null, sourceIp: null)
            with
        { LicenseEnforcementMode = "block" };

        // Pre-#545 this reads the shared row's real (allowlisted) MIT entry and serves — the
        // false-clean shape the acceptance criteria calls out: a diverging tenant vouched for by
        // another tenant's license evidence. Post-fix the diverging tenant has no license
        // evidence of its own, which npm (a DeclaredLicenseEcosystems member) treats as an
        // unknown license under 'block' — the existing zero-entries posture, unchanged by #545.
        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_license"));
    }

    [Fact]
    public async Task NonDivergent_SharedRowAllowlistedLicense_LicenseGate_Serves()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cba-lic-ok-{Guid.NewGuid():N}");
        await LicensePolicySeeder.AddAllowlistEntryAsync(_fixture.Store, orgId, "MIT");
        var caFacts = await SeedCacheFactsAsync(orgId, "npm", Coordinate(), divergent: false);
        await SeedLicenseAsync(caFacts.Id, "MIT");

        var req = BlockGateRequest.ForProxyCacheFacts(orgId, "npm", caFacts, token: null, settings: null, sourceIp: null)
            with
        { LicenseEnforcementMode = "block" };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_license"));
    }

    // ── visibility: divergence itself is queued for review, regardless of outcome ─

    [Fact]
    public async Task Divergent_QueuesContentDivergenceForReview()
    {
        // Every policy left permissive, so nothing else would queue a review row — isolates the
        // divergence-visibility hook (BlockGateService.QueueDivergenceReviewAsync) from every
        // other arm's own QueueForReviewAsync call.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cba-div-review-{Guid.NewGuid():N}");
        var caFacts = await SeedCacheFactsAsync(orgId, "cargo", Coordinate(), divergent: true);

        var req = BlockGateRequest.ForProxyCacheFacts(orgId, "cargo", caFacts, token: null, settings: null, sourceIp: null);

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        var (gate, state) = await GetQuarantineRowAsync(orgId, req.Purl);
        Assert.Equal("content_divergence", gate);
        Assert.Equal("pending", state);
    }

    [Fact]
    public async Task NonDivergent_DoesNotQueueContentDivergenceForReview()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cba-div-review-ok-{Guid.NewGuid():N}");
        var caFacts = await SeedCacheFactsAsync(orgId, "cargo", Coordinate(), divergent: false);

        var req = BlockGateRequest.ForProxyCacheFacts(orgId, "cargo", caFacts, token: null, settings: null, sourceIp: null);

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Null((await GetQuarantineRowAsync(orgId, req.Purl)).Gate);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static (string Name, string Version, string Filename) Coordinate()
    {
        string name = $"pkg-{Guid.NewGuid():N}"[..20];
        return (name, "1.0.0", $"{name}-1.0.0.tgz");
    }

    // package_version_licenses has no seeder helper of its own (LicenseEnforcementTests inlines
    // the same INSERT); this mirrors that shape for the cache_artifact-owned arm.
    private async Task SeedLicenseAsync(string cacheArtifactId, string spdx)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_licenses (id, cache_artifact_id, owner_kind, license_spdx, source)
            VALUES (@id, @caId, 'cache_artifact', @spdx, 'upstream')
            """,
            new { id = Guid.NewGuid().ToString("N"), caId = cacheArtifactId, spdx });
    }

    // Seeds a cache_artifact row through the real repository writers (InsertAsync,
    // UpdateGlobalFactsAsync, MarkCacheArtifactCheckedAsync) plus a tenant_artifact_access row via
    // TenantArtifactAccessRepository.UpsertAsync — the same production code every proxy fetch path
    // runs through — rather than hand-built SQL, so the divergence this test exercises is the real
    // ContentDivergesFromSharedFacts computation, not an assumption about it.
    private async Task<CacheArtifactServeFacts> SeedCacheFactsAsync(
        string orgId, string ecosystem, (string Name, string Version, string Filename) coordinate,
        bool divergent, bool hasInstallScript = false, string? provenanceStatus = null, bool scanned = false)
    {
        var now = _clock.GetUtcNow();
        var inserted = await _cacheArtifacts.InsertAsync(new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = ecosystem,
            Name = coordinate.Name,
            Version = coordinate.Version,
            Filename = coordinate.Filename,
            BlobKey = $"proxy/{ecosystem}/{coordinate.Name}/{Guid.NewGuid():N}",
            ContentHash = $"shared-hash-{Guid.NewGuid():N}",
            SizeBytes = 100,
            FirstCachedAt = now,
            LastAccessedAt = now,
        });

        await _cacheArtifacts.UpdateGlobalFactsAsync(
            inserted.Id,
            purl: $"pkg:{ecosystem}/{coordinate.Name}@{coordinate.Version}",
            checksumSha1: null,
            publishedAt: null,
            deprecated: null,
            hasInstallScript: hasInstallScript,
            installScriptKind: hasInstallScript ? $"{ecosystem}:postinstall" : null,
            provenanceStatus: provenanceStatus,
            provenanceSigner: provenanceStatus is null ? null : "trusted-signer",
            upstreamIntegrityValue: null,
            upstreamIntegrityAlgorithm: null);

        if (scanned)
        {
            await _vulns.MarkCacheArtifactCheckedAsync(inserted.Id);
        }

        var binding = divergent
            ? new TenantContentBinding(
                ContentHash: $"tenant-hash-{Guid.NewGuid():N}",
                BlobKey: $"proxy/{ecosystem}/{coordinate.Name}/{Guid.NewGuid():N}",
                SizeBytes: 200)
            : TenantContentBinding.None;
        await _access.UpsertAsync(orgId, inserted.Id, now, binding);

        var caFacts = await _cacheArtifacts.GetServeFactsByCoordinateAsync(
            orgId, ecosystem, coordinate.Name, coordinate.Version, coordinate.Filename);
        Assert.NotNull(caFacts);
        Assert.Equal(divergent, caFacts!.ContentDivergesFromSharedFacts);
        return caFacts;
    }

    private async Task<long> CountActivityAsync(string orgId, string eventType)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM activity WHERE org_id = @orgId AND event_type = @eventType",
            new { orgId, eventType });
    }

    private async Task<(string? Gate, string? State)> GetQuarantineRowAsync(string orgId, string purl)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.QuerySingleOrDefaultAsync<(string? Gate, string? State)>(
            "SELECT gate, state FROM quarantine WHERE org_id = @orgId AND purl = @purl",
            new { orgId, purl });
    }
}
