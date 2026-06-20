using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Polymorphic-read capability tests. Verifies that:
/// 1. <see cref="VulnerabilityRepository.GetGateSignalsAsync"/> returns correct signals when
///    vulns are attached via <c>cache_artifact_id</c> + <c>owner_kind='cache_artifact'</c>.
/// 2. <see cref="VulnerabilityRepository.GetGateSignalsForVersionAsync"/> still returns
///    correct signals for the legacy <c>package_version</c> arm (parity guarantee).
/// 3. <see cref="LicenseRepository.GetSpdxForCacheArtifactsAsync"/> returns license SPDX
///    identifiers attached to global <c>cache_artifact</c> rows.
/// 4. <see cref="BlockGateService.EvaluateAsync"/> routes the vuln-signal lookup through
///    the cache-artifact arm when <c>BlockGateRequest.CacheArtifactId</c> is set.
/// 5. All existing call sites (null <c>CacheArtifactId</c>) are unaffected (behaviour
///    equivalent to the pre-global-plane baseline).
///
/// Uses a per-class <see cref="TestMetadataStore"/>. The <c>package_version_id</c> column
/// in <c>package_version_vulns</c> is nullable after the P3
/// <c>make_pvv_package_version_id_nullable</c> migration — no sentinel or FK workaround needed.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PolymorphicReadCapabilityTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private BlockGateService _blockGate = null!;

    public async Task InitializeAsync()
    {
        var init = new SchemaInitializer(_db);
        await init.InitializeAsync();

        _blockGate = new BlockGateService(
            new VulnerabilityRepository(_db, _clock),
            new AuditRepository(_db),
            new QuarantineRepository(_db, _clock),
            new InstallScriptAllowlistService(_db, new Microsoft.Extensions.Caching.Memory.MemoryCache(new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()), _clock),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<BlockGateService>.Instance,
            _clock);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── VulnerabilityRepository — cache_artifact arm ──────────────────────────

    [Fact]
    public async Task GetGateSignals_CacheArtifactArm_ReturnsMaxCvss()
    {
        // Vuln linked to a cache_artifact — the polymorphic read must surface the CVSS score.
        string caId = await InsertCacheArtifactAsync("npm", "lodash", "4.17.21");
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _db, $"GHSA-{Guid.NewGuid():N}", cvssScore: 8.1);
        await LinkVulnToCacheArtifactAsync(caId, vulnId);

        var repo = new VulnerabilityRepository(_db, _clock);
        var signals = await repo.GetGateSignalsAsync("cache_artifact", caId);

        Assert.Equal(8.1, signals.MaxCvss);
        Assert.False(signals.HasMalicious);
        Assert.False(signals.HasKev);
        Assert.Null(signals.MaxEpss);
    }

    [Fact]
    public async Task GetGateSignals_CacheArtifactArm_DetectsMaliciousAdvisory()
    {
        string caId = await InsertCacheArtifactAsync("npm", "evil-pkg", "1.0.0");
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _db, $"MAL-2026-{Guid.NewGuid():N}", severity: null, cvssScore: null);
        await LinkVulnToCacheArtifactAsync(caId, vulnId);

        var repo = new VulnerabilityRepository(_db, _clock);
        var signals = await repo.GetGateSignalsAsync("cache_artifact", caId);

        Assert.True(signals.HasMalicious);
        Assert.Null(signals.MaxCvss);
    }

    [Fact]
    public async Task GetGateSignals_CacheArtifactArm_DetectsKev()
    {
        string caId = await InsertCacheArtifactAsync("npm", "kev-pkg", "2.0.0");
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _db, $"CVE-2026-{Guid.NewGuid():N}", isKev: true, cvssScore: 9.0);
        await LinkVulnToCacheArtifactAsync(caId, vulnId);

        var repo = new VulnerabilityRepository(_db, _clock);
        var signals = await repo.GetGateSignalsAsync("cache_artifact", caId);

        Assert.True(signals.HasKev);
        Assert.Equal(9.0, signals.MaxCvss);
    }

    [Fact]
    public async Task GetGateSignals_CacheArtifactArm_DetectsEpss()
    {
        string caId = await InsertCacheArtifactAsync("npm", "epss-pkg", "3.0.0");
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _db, $"CVE-2026-epss-{Guid.NewGuid():N}", cvssScore: 5.5, epssScore: 0.87);
        await LinkVulnToCacheArtifactAsync(caId, vulnId);

        var repo = new VulnerabilityRepository(_db, _clock);
        var signals = await repo.GetGateSignalsAsync("cache_artifact", caId);

        Assert.Equal(0.87, signals.MaxEpss);
    }

    [Fact]
    public async Task GetGateSignals_CacheArtifactArm_NoVulns_ReturnsAllClear()
    {
        // An artifact with no linked vulns must return an all-clear signals record.
        string caId = await InsertCacheArtifactAsync("pypi", "safe-lib", "1.0.0");

        var repo = new VulnerabilityRepository(_db, _clock);
        var signals = await repo.GetGateSignalsAsync("cache_artifact", caId);

        Assert.Null(signals.MaxCvss);
        Assert.False(signals.HasMalicious);
        Assert.False(signals.HasKev);
        Assert.Null(signals.MaxEpss);
    }

    // ── VulnerabilityRepository — package_version arm (parity) ───────────────

    [Fact]
    public async Task GetGateSignals_PackageVersionArm_ParityWithLegacyMethod()
    {
        // GetGateSignalsAsync('package_version', id) and GetGateSignalsForVersionAsync(id)
        // must return identical results.
        string orgId = await OrgSeeder.InsertAsync(_db, $"parity-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_db, orgId, "npm", "parity-pkg");
        string verId = await PackageSeeder.InsertVersionAsync(
            _db, pkgId, "1.0.0", "pkg:npm/parity-pkg@1.0.0");
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _db, $"GHSA-parity-{Guid.NewGuid():N}", cvssScore: 7.2, isKev: true);
        await VulnerabilitySeeder.LinkAsync(_db, verId, vulnId);

        var repo = new VulnerabilityRepository(_db, _clock);
        var viaNew = await repo.GetGateSignalsAsync("package_version", verId);
        var viaLegacy = await repo.GetGateSignalsForVersionAsync(verId);

        Assert.Equal(viaLegacy.MaxCvss, viaNew.MaxCvss);
        Assert.Equal(viaLegacy.HasMalicious, viaNew.HasMalicious);
        Assert.Equal(viaLegacy.HasKev, viaNew.HasKev);
        Assert.Equal(viaLegacy.MaxEpss, viaNew.MaxEpss);
    }

    // ── Cross-arm isolation ───────────────────────────────────────────────────

    [Fact]
    public async Task GetGateSignals_CacheArtifactArm_DoesNotSeeVersionVulns()
    {
        // A vuln linked via package_version_id must NOT appear in the cache_artifact arm query.
        string orgId = await OrgSeeder.InsertAsync(_db, $"iso-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_db, orgId, "npm", "iso-pkg");
        string verId = await PackageSeeder.InsertVersionAsync(
            _db, pkgId, "1.0.0", "pkg:npm/iso-pkg@1.0.0");
        string caId = await InsertCacheArtifactAsync("npm", "iso-pkg", "1.0.0");

        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _db, $"GHSA-iso-{Guid.NewGuid():N}", cvssScore: 9.9);
        // Link only to package_version — cache_artifact arm must see no vulns.
        await VulnerabilitySeeder.LinkAsync(_db, verId, vulnId);

        var repo = new VulnerabilityRepository(_db, _clock);
        var signals = await repo.GetGateSignalsAsync("cache_artifact", caId);

        Assert.Null(signals.MaxCvss);
        Assert.False(signals.HasMalicious);
    }

    // ── LicenseRepository — cache_artifact read ───────────────────────────────

    [Fact]
    public async Task GetSpdxForCacheArtifacts_ReturnsSpdxForLinkedArtifacts()
    {
        string caId = await InsertCacheArtifactAsync("pypi", "requests", "2.31.0");
        var licenseRepo = new LicenseRepository(_db, _clock);
        await licenseRepo.SetLicensesForCacheArtifactAsync(caId, ["MIT", "Apache-2.0"], "upstream");

        var lookup = await licenseRepo.GetSpdxForCacheArtifactsAsync([caId]);

        var spdxList = lookup[caId].OrderBy(s => s).ToList();
        Assert.Equal(["Apache-2.0", "MIT"], spdxList);
    }

    [Fact]
    public async Task GetSpdxForCacheArtifacts_EmptyInput_ReturnsEmptyLookup()
    {
        var licenseRepo = new LicenseRepository(_db, _clock);
        var lookup = await licenseRepo.GetSpdxForCacheArtifactsAsync([]);
        Assert.Empty(lookup);
    }

    [Fact]
    public async Task GetSpdxForCacheArtifacts_ArtifactWithNoLicenses_AbsentFromLookup()
    {
        string caId = await InsertCacheArtifactAsync("npm", "no-license-pkg", "1.0.0");
        var licenseRepo = new LicenseRepository(_db, _clock);

        var lookup = await licenseRepo.GetSpdxForCacheArtifactsAsync([caId]);

        Assert.Empty(lookup[caId]);
    }

    [Fact]
    public async Task GetSpdxForCacheArtifacts_DoesNotReturnVersionOwnedLicenses()
    {
        // package_version_id-owned licenses must NOT bleed into the cache_artifact read.
        string orgId = await OrgSeeder.InsertAsync(_db, $"lic-iso-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_db, orgId, "npm", "lic-pkg");
        string verId = await PackageSeeder.InsertVersionAsync(
            _db, pkgId, "1.0.0", "pkg:npm/lic-pkg@1.0.0");
        string caId = await InsertCacheArtifactAsync("npm", "lic-pkg", "1.0.0");

        var licenseRepo = new LicenseRepository(_db, _clock);
        // Attach GPL-3.0 to the package_version row only.
        await licenseRepo.SetLicensesAsync(verId, ["GPL-3.0"], "upstream");

        var lookup = await licenseRepo.GetSpdxForCacheArtifactsAsync([caId]);

        // cache_artifact arm should see no licenses (GPL-3.0 is on the version arm).
        Assert.Empty(lookup[caId]);
    }

    // ── BlockGateService — CacheArtifactId routing ───────────────────────────

    [Fact]
    public async Task BlockGate_CacheArtifactId_Set_RoutesVulnSignalsThroughCacheArtifactArm()
    {
        // A high-CVSS vuln linked via cache_artifact_id must cause a score-block when
        // BlockGateRequest.CacheArtifactId is set.
        string orgId = await OrgSeeder.InsertAsync(_db, $"bgs-ca-{Guid.NewGuid():N}");
        string caId = await InsertCacheArtifactAsync("npm", "blocked-ca-pkg", "1.0.0");
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _db, $"GHSA-bgs-{Guid.NewGuid():N}", cvssScore: 9.5);
        await LinkVulnToCacheArtifactAsync(caId, vulnId);

        // BlockGateRequest with CacheArtifactId set, VulnCheckedAt non-null, tight tolerance.
        var req = new BlockGateRequest(
            OrgId: orgId,
            Ecosystem: "npm",
            Purl: "pkg:npm/blocked-ca-pkg@1.0.0",
            VersionId: "",               // empty — no package_versions row yet
            ManualState: null,
            VulnCheckedAt: _clock.GetUtcNow(),
            UserId: null,
            MaxOsvScoreTolerance: 5.0,  // threshold below the 9.5 score
            CacheArtifactId: caId);

        var decision = await _blockGate.EvaluateAsync(req);

        Assert.Equal(BlockDecision.Blocked, decision);
    }

    [Fact]
    public async Task BlockGate_CacheArtifactId_Set_NullVulnCheckedAt_AllowsThrough()
    {
        // Unscanned cache artifact: VulnCheckedAt is null, so the signal lookup is skipped
        // and the gate allows through (same fail-open behaviour as the version arm).
        string orgId = await OrgSeeder.InsertAsync(_db, $"bgs-ns-{Guid.NewGuid():N}");
        string caId = await InsertCacheArtifactAsync("npm", "unscanned-ca-pkg", "2.0.0");
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _db, $"GHSA-unscanned-{Guid.NewGuid():N}", cvssScore: 9.9);
        await LinkVulnToCacheArtifactAsync(caId, vulnId);

        var req = new BlockGateRequest(
            OrgId: orgId,
            Ecosystem: "npm",
            Purl: "pkg:npm/unscanned-ca-pkg@2.0.0",
            VersionId: "",
            ManualState: null,
            VulnCheckedAt: null,         // not yet scanned — must fail open
            UserId: null,
            MaxOsvScoreTolerance: 0.0,  // extremely tight
            CacheArtifactId: caId);

        var decision = await _blockGate.EvaluateAsync(req);

        Assert.Equal(BlockDecision.Allowed, decision);
    }

    [Fact]
    public async Task BlockGate_CacheArtifactId_Null_UsesVersionArm_UnchangedBehaviour()
    {
        // All existing call sites leave CacheArtifactId null — they must route through the
        // package_version arm unchanged, producing exactly the same result as before P2.
        string orgId = await OrgSeeder.InsertAsync(_db, $"bgs-null-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_db, orgId, "npm", "legacy-pkg");
        string verId = await PackageSeeder.InsertVersionAsync(
            _db, pkgId, "1.0.0", "pkg:npm/legacy-pkg@1.0.0");
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _db, $"GHSA-legacy-{Guid.NewGuid():N}", cvssScore: 8.0);
        await VulnerabilitySeeder.LinkAsync(_db, verId, vulnId);

        var req = new BlockGateRequest(
            OrgId: orgId,
            Ecosystem: "npm",
            Purl: "pkg:npm/legacy-pkg@1.0.0",
            VersionId: verId,
            ManualState: null,
            VulnCheckedAt: _clock.GetUtcNow(),
            UserId: null,
            MaxOsvScoreTolerance: 5.0,
            CacheArtifactId: null);       // legacy path

        var decision = await _blockGate.EvaluateAsync(req);

        // 8.0 > 5.0 tolerance — must be blocked via the version arm.
        Assert.Equal(BlockDecision.Blocked, decision);
    }

    // ── Mixed partial-failure scenario ───────────────────────────────────────

    [Fact]
    public async Task GetGateSignals_MixedBatch_SomeArtifactsHaveVulns_SomeDoNot()
    {
        // Three cache artifacts: one with a scored vuln, one clean, one with a malicious vuln.
        // Verifies partial-result correctness across the batch.
        string caWithCvss = await InsertCacheArtifactAsync("npm", "batch-cvss", "1.0.0");
        string caClean = await InsertCacheArtifactAsync("npm", "batch-clean", "1.0.0");
        string caWithMal = await InsertCacheArtifactAsync("npm", "batch-mal", "1.0.0");

        string cvssVulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _db, $"GHSA-batch-cvss-{Guid.NewGuid():N}", cvssScore: 7.5);
        string malVulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _db, $"MAL-batch-{Guid.NewGuid():N}", severity: null, cvssScore: null);

        await LinkVulnToCacheArtifactAsync(caWithCvss, cvssVulnId);
        // caClean: no links
        await LinkVulnToCacheArtifactAsync(caWithMal, malVulnId);

        var repo = new VulnerabilityRepository(_db, _clock);

        var withCvss = await repo.GetGateSignalsAsync("cache_artifact", caWithCvss);
        var clean = await repo.GetGateSignalsAsync("cache_artifact", caClean);
        var withMal = await repo.GetGateSignalsAsync("cache_artifact", caWithMal);

        // Scored artifact
        Assert.Equal(7.5, withCvss.MaxCvss);
        Assert.False(withCvss.HasMalicious);

        // Clean artifact — all signals absent
        Assert.Null(clean.MaxCvss);
        Assert.False(clean.HasMalicious);

        // Malicious artifact
        Assert.True(withMal.HasMalicious);
        Assert.Null(withMal.MaxCvss);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Inserts a minimal <c>cache_artifact</c> row and returns its id.
    /// </summary>
    private async Task<string> InsertCacheArtifactAsync(
        string ecosystem, string name, string version)
    {
        string id = Guid.NewGuid().ToString("N");
        string filename = $"{name}-{version}.tgz";
        string blobKey = $"proxy/{ecosystem}/{name}/{version}/{filename}";
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes)
            VALUES
                (@id, @ecosystem, @name, @version, @filename, @blobKey, @contentHash, 0)
            """,
            new
            {
                id,
                ecosystem,
                name,
                version,
                filename,
                blobKey,
                contentHash = $"sha256:{Guid.NewGuid():N}",
            });
        return id;
    }

    /// <summary>
    /// Inserts a <c>package_version_vulns</c> row owned by a <c>cache_artifact</c>
    /// (<c>owner_kind='cache_artifact'</c>, <c>package_version_id=NULL</c>).
    /// The nullable column is correct after the P3 <c>make_pvv_package_version_id_nullable</c>
    /// migration — no FK workaround or sentinel required.
    /// </summary>
    private async Task LinkVulnToCacheArtifactAsync(string cacheArtifactId, string vulnId)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        // xtenant: cache_artifact is global; cacheArtifactId is caller-supplied from test setup.
        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_vulns
                (id, cache_artifact_id, vuln_id, owner_kind)
            VALUES (@id, @cacheArtifactId, @vulnId, 'cache_artifact')
            ON CONFLICT DO NOTHING
            """,
            new { id, cacheArtifactId, vulnId });
    }
}
