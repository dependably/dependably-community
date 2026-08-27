using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Alerts;
using Dependably.Infrastructure.Audit.Events;
using Dependably.Infrastructure.Webhooks;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Covers <see cref="BlockGateService"/>: the manual/release-age/OSV priority order and the
/// activity-row side effects. The release-age branch is the new policy (M5.x), so most cases
/// here exercise it; the manual + OSV branches keep their existing coverage in the controller
/// integration tests but the priority order is asserted here so a future refactor can't
/// silently reorder the gates.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BlockGateServiceTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly BlockGateService _sut;
    private readonly AuditRepository _audit;
    private readonly StubPerOrgTrustAnchorStore _anchors = new();
    private readonly Dependably.Infrastructure.Webhooks.IPackageEventSink _eventSink =
        NSubstitute.Substitute.For<Dependably.Infrastructure.Webhooks.IPackageEventSink>();

    public BlockGateServiceTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _audit = new AuditRepository(_fixture.Store);
        _sut = new BlockGateService(
            new VulnerabilityRepository(_fixture.Store, _clock),
            _audit,
            new QuarantineRepository(_fixture.Store, _clock),
            new AlertService(new AlertRepository(_fixture.Store, _clock), new NoOpAlertNotifier(), Microsoft.Extensions.Logging.Abstractions.NullLogger<AlertService>.Instance),
            new InstallScriptAllowlistService(_fixture.Store, new Microsoft.Extensions.Caching.Memory.MemoryCache(new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()), _clock),
            new LicenseRepository(_fixture.Store, _clock, new LicenseNormalizer(_fixture.Store, Microsoft.Extensions.Logging.Abstractions.NullLogger<LicenseNormalizer>.Instance)),
            _anchors,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<BlockGateService>.Instance,
            _clock,
            new OrgRepository(_fixture.Store),
            _eventSink,
            new BlockRefusalWebhookThrottle(_clock, TimeSpan.Zero));
    }

    // ── manual-block / manual-allow ───────────────────────────────────────────

    [Fact]
    public async Task ManualBlock_Wins_OverEverythingElse()
    {
        // Manual block takes precedence even when release-age would have allowed and OSV is fine.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"mb-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            ManualState = "blocked",
            MinReleaseAgeHours = 24,
            PublishedAt = _clock.GetUtcNow().AddDays(-30),
        };

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_manual"));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_release_age"));
    }

    [Fact]
    public async Task ManualAllow_ShortCircuits_PastReleaseAgeAndOsv()
    {
        // Operator override: manual allow returns early, skipping both auto gates.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"ma-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            ManualState = "allowed",
            MinReleaseAgeHours = 48,
            PublishedAt = _clock.GetUtcNow().AddHours(-1), // would be blocked by release-age
            VulnCheckedAt = _clock.GetUtcNow(),
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_release_age"));
    }

    // ── deprecated gate ───────────────────────────────────────────────────────

    [Fact]
    public async Task Deprecated_Block_Mode_Blocks_AndLogsActivity()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"dep-block-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            Deprecated = "This version is abandoned",
            BlockDeprecatedMode = "block",
        };

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_deprecated"));
    }

    [Fact]
    public async Task Deprecated_BlockAll_OnServePath_Blocks()
    {
        // block_all denies an already-cached deprecated version on the serve (cache-hit) path.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"dep-all-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            Deprecated = "This version is abandoned",
            BlockDeprecatedMode = "block_all",
        };

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_deprecated"));
    }

    [Fact]
    public async Task Deprecated_BlockNew_OnServePath_AllowsCachedThrough()
    {
        // The crux of the new/all split: block_new lets an already-cached deprecated version keep
        // serving. Its blocking happens only on the first-fetch path (asserted separately).
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"dep-new-serve-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            Deprecated = "This version is abandoned",
            BlockDeprecatedMode = "block_new",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_deprecated"));
    }

    [Theory]
    [InlineData("block_new")]
    [InlineData("block_all")]
    [InlineData("block")] // legacy value, honoured as block_all
    public async Task Deprecated_FirstFetch_BlocksUnderEveryBlockingMode(string mode)
    {
        // On the cache-miss first-fetch path both block_new and block_all (and legacy block)
        // refuse a deprecated version so it is never cached.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"dep-ff-{mode}-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            Deprecated = "abandoned",
            BlockDeprecatedMode = mode,
        };

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateFirstFetchDeprecationAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_deprecated"));
    }

    [Theory]
    [InlineData("off")]
    [InlineData("warn")]
    public async Task Deprecated_FirstFetch_AllowsUnderNonBlockingMode(string mode)
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"dep-ff-allow-{mode}-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            Deprecated = "abandoned",
            BlockDeprecatedMode = mode,
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateFirstFetchDeprecationAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_deprecated"));
    }

    [Fact]
    public async Task Deprecated_FirstFetch_NullDeprecated_AllowsThrough()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"dep-ff-null-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            Deprecated = null,
            BlockDeprecatedMode = "block_new",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateFirstFetchDeprecationAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_deprecated"));
    }

    [Fact]
    public async Task Deprecated_Warn_Mode_AllowsThrough()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"dep-warn-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            Deprecated = "Use the new package instead",
            BlockDeprecatedMode = "warn",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_deprecated"));
    }

    [Fact]
    public async Task Deprecated_Off_Mode_AllowsThrough()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"dep-off-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            Deprecated = "use something else",
            BlockDeprecatedMode = "off",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_deprecated"));
    }

    [Fact]
    public async Task Deprecated_Block_Mode_NullDeprecated_AllowsThrough()
    {
        // block mode only fires when the version actually has a deprecation message.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"dep-null-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            Deprecated = null,
            BlockDeprecatedMode = "block",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_deprecated"));
    }

    [Fact]
    public async Task ManualAllow_ShortCircuits_PastDeprecatedGate()
    {
        // Priority: manual-allow (2) wins over deprecated-block (3).
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"dep-ma-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            ManualState = "allowed",
            Deprecated = "This version is abandoned",
            BlockDeprecatedMode = "block",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_deprecated"));
    }

    [Fact]
    public async Task Deprecated_Block_LogsDeprecatedMessageInDetail()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"dep-detail-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            Deprecated = "legacy package",
            BlockDeprecatedMode = "block",
        };

        await _sut.EvaluateAsync(req);

        await using var conn = await _fixture.Store.OpenAsync();
        string? detail = await conn.ExecuteScalarAsync<string>(
            "SELECT detail FROM activity WHERE event_type = 'blocked_deprecated' AND org_id = @orgId",
            new { orgId });
        Assert.Contains("\"deprecated\":", detail);
        Assert.Contains("legacy package", detail);
    }

    // ── revoked (upstream-removed) gate ───────────────────────────────────────

    [Fact]
    public async Task Revoked_BlockMode_Blocks_AndLogsActivity()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-block-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            RevokedAt = _clock.GetUtcNow().AddDays(-1),
            BlockRevokedMode = "block",
        };

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_revoked"));
    }

    [Theory]
    [InlineData("warn")]
    [InlineData("off")]
    [InlineData(null)]
    public async Task Revoked_NonBlockingModes_AllowThrough(string? mode)
    {
        // 'warn'/'off'/null surface the badge but keep serving the cached copy.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-allow-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            RevokedAt = _clock.GetUtcNow().AddDays(-1),
            BlockRevokedMode = mode,
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_revoked"));
    }

    [Fact]
    public async Task Revoked_BlockMode_NullRevokedAt_AllowsThrough()
    {
        // The gate only fires when the version is actually revoked.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-null-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            RevokedAt = null,
            BlockRevokedMode = "block",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_revoked"));
    }

    [Fact]
    public async Task Revoked_Block_LogsRevokedAtInDetail_AndQueuesRevokedGate()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-detail-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            // Empty VersionId maps to a NULL review-row FK (the serve-path shape used by the
            // quarantine assertion below — a random non-existent id would violate the FK).
            VersionId = string.Empty,
            RevokedAt = _clock.GetUtcNow().AddDays(-1),
            BlockRevokedMode = "block",
        };

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));

        await using var conn = await _fixture.Store.OpenAsync();
        string? detail = await conn.ExecuteScalarAsync<string>(
            "SELECT detail FROM activity WHERE event_type = 'blocked_revoked' AND org_id = @orgId",
            new { orgId });
        Assert.Contains("\"revoked_at\":", detail);

        var quarantine = new QuarantineRepository(_fixture.Store, _clock);
        var (items, total) = await quarantine.ListAsync(new QuarantineListQuery(orgId, State: "pending", Limit: 10));
        Assert.Equal(1, total);
        Assert.Equal("revoked", items[0].Gate);
    }

    [Fact]
    public async Task ManualAllow_ShortCircuits_PastRevokedGate()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-ma-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            ManualState = "allowed",
            RevokedAt = _clock.GetUtcNow().AddDays(-1),
            BlockRevokedMode = "block",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_revoked"));
    }

    [Fact]
    public async Task Revoked_OutranksReleaseAge_SingleEvent()
    {
        // A revoked version still within a release-age hold records exactly one blocked_revoked
        // event — the revoked arm sits above release-age in priority order.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"rev-prio-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            RevokedAt = _clock.GetUtcNow().AddDays(-1),
            BlockRevokedMode = "block",
            MinReleaseAgeHours = 48,
            PublishedAt = _clock.GetUtcNow().AddHours(-1),
            Origin = "proxy",
        };

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_revoked"));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_release_age"));
    }

    // ── release-age branch ────────────────────────────────────────────────────

    [Fact]
    public async Task ReleaseAge_TooYoung_Blocks_AndLogsActivity()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"young-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            MinReleaseAgeHours = 24,
            PublishedAt = _clock.GetUtcNow().AddHours(-6), // 18 hours short of the hold
        };

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_release_age"));

        // Detail JSON carries the three diagnostic fields the dashboard renders.
        await using var conn = await _fixture.Store.OpenAsync();
        string? detail = await conn.ExecuteScalarAsync<string>(
            "SELECT detail FROM activity WHERE event_type = 'blocked_release_age' AND org_id = @orgId",
            new { orgId });
        Assert.Contains("\"published_at\":", detail);
        Assert.Contains("\"min_age_hours\":24", detail);
        Assert.Contains("\"age_at_block_hours\":", detail);
    }

    [Fact]
    public async Task ReleaseAge_OldEnough_FallsThrough_ToOsv()
    {
        // Published comfortably past the hold — release-age gate does not fire. With no
        // VulnCheckedAt, the OSV branch returns Allowed.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"old-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            MinReleaseAgeHours = 24,
            PublishedAt = _clock.GetUtcNow().AddDays(-7),
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_release_age"));
    }

    [Fact]
    public async Task ReleaseAge_NullPublishedAt_FailsOpen()
    {
        // Upstream metadata didn't carry a timestamp (rare quirk in older NuGet/npm rows).
        // Documented design choice: don't block on missing data — let the artefact through.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"nopub-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            MinReleaseAgeHours = 720, // very strict — wouldn't matter
            PublishedAt = null,
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_release_age"));
    }

    [Fact]
    public async Task ReleaseAge_PolicyUnset_DoesNotEvaluate()
    {
        // Belt + suspenders: a tenant with no policy set (NULL) must not block, even if the
        // version's published_at is "now" (which would be 0 hours old).
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"unset-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            MinReleaseAgeHours = null,
            PublishedAt = _clock.GetUtcNow(),
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_release_age"));
    }

    [Fact]
    public async Task ReleaseAge_ZeroHours_TreatedAsOff()
    {
        // 0 is a valid integer the controller could persist if a future migration zeroed the
        // column; the gate treats it as policy-off rather than blocking everything.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"zero-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            MinReleaseAgeHours = 0,
            PublishedAt = _clock.GetUtcNow(),
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_release_age"));
    }

    // ── malicious-advisory gate ───────────────────────────────────────────────

    [Fact]
    public async Task Malicious_UnscoredMalAdvisory_Blocks_UnderBlockMode()
    {
        // The gap the gate closes: MAL- advisories usually carry no CVSS score, so the
        // score-tolerance comparison alone would let known malware straight through.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"mal-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/acme@1.0.0");
        var req = BaseRequest(orgId) with
        {
            VersionId = verId,
            VulnCheckedAt = _clock.GetUtcNow(),
            BlockMaliciousMode = "block",
        };
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"MAL-2026-{Guid.NewGuid():N}", severity: null, cvssScore: null);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, req.VersionId, vulnId);

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_malicious"));

        await using var conn = await _fixture.Store.OpenAsync();
        string? detail = await conn.ExecuteScalarAsync<string>(
            "SELECT detail FROM activity WHERE event_type = 'blocked_malicious' AND org_id = @orgId",
            new { orgId });
        Assert.Contains("\"osv_ids\":", detail);
        Assert.Contains("MAL-2026-", detail);
    }

    [Theory]
    [InlineData("off")]
    [InlineData("warn")]
    [InlineData(null)] // callers that predate the gate behave as 'off'
    public async Task Malicious_NonBlockingModes_AllowThrough(string? mode)
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"mal-allow-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/acme@1.0.0");
        var req = BaseRequest(orgId) with
        {
            VersionId = verId,
            VulnCheckedAt = _clock.GetUtcNow(),
            BlockMaliciousMode = mode,
        };
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"MAL-2026-{Guid.NewGuid():N}", severity: null, cvssScore: null);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, req.VersionId, vulnId);

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_malicious"));
    }

    [Fact]
    public async Task ManualAllow_ShortCircuits_PastMaliciousGate()
    {
        // The false-positive escape hatch: a manual per-version allow wins over a MAL advisory.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"mal-ma-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/acme@1.0.0");
        var req = BaseRequest(orgId) with
        {
            VersionId = verId,
            ManualState = "allowed",
            VulnCheckedAt = _clock.GetUtcNow(),
            BlockMaliciousMode = "block",
        };
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"MAL-2026-{Guid.NewGuid():N}", severity: null, cvssScore: null);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, req.VersionId, vulnId);

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_malicious"));
    }

    [Fact]
    public async Task Malicious_RunsAhead_OfScoreGate_SingleEvent()
    {
        // A MAL advisory that also carries a CVSS score above tolerance produces exactly one
        // blocked_malicious event — the malicious verdict outranks the score comparison.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"mal-score-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/acme@1.0.0");
        var req = BaseRequest(orgId) with
        {
            VersionId = verId,
            VulnCheckedAt = _clock.GetUtcNow(),
            BlockMaliciousMode = "block",
            MaxOsvScoreTolerance = 0.0,
        };
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"MAL-2026-{Guid.NewGuid():N}", severity: "CRITICAL", cvssScore: 9.8);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, req.VersionId, vulnId);

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_malicious"));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_vuln_score"));
    }

    [Fact]
    public async Task ScoredNonMalAdvisory_StillBlocksOnScore()
    {
        // Regression guard for the signals-query refactor: the plain CVSS path is unchanged.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cvss-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/acme@1.0.0");
        var req = BaseRequest(orgId) with
        {
            VersionId = verId,
            VulnCheckedAt = _clock.GetUtcNow(),
            BlockMaliciousMode = "block",
            MaxOsvScoreTolerance = 5.0,
        };
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-{Guid.NewGuid():N}", severity: "CRITICAL", cvssScore: 9.8);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, req.VersionId, vulnId);

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_vuln_score"));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_malicious"));
    }

    [Fact]
    public async Task Cvss4OnlyAdvisory_StillBlocksOnScore()
    {
        // Regression guard for #609: a v4-only advisory (no CVSS v3 vector at all) now yields
        // a real numeric score via OsvScoring, so max_osv_score_tolerance fires exactly the
        // same way it does for a v3 advisory — this arm was previously permanently inert for
        // every CVSS-v4-only advisory (measured ~21% of npm, ~19% of crates.io).
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"cvss4-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/acme@1.0.0");
        var req = BaseRequest(orgId) with
        {
            VersionId = verId,
            VulnCheckedAt = _clock.GetUtcNow(),
            BlockMaliciousMode = "block",
            MaxOsvScoreTolerance = 5.0,
        };

        (double? cvss4Score, string? cvss4Severity) = OsvScoring.ParseCvssBaseScore(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
        Assert.Equal(10.0, cvss4Score);
        Assert.Equal("CRITICAL", cvss4Severity);

        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"EEF-CVE-{Guid.NewGuid():N}", severity: cvss4Severity, cvssScore: cvss4Score);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, req.VersionId, vulnId);

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_vuln_score"));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_malicious"));
    }

    [Fact]
    public async Task Malicious_UnscannedVersion_AllowsThrough()
    {
        // VulnCheckedAt null = the OSV scan hasn't run yet, so no advisory data exists to act
        // on; the gate keeps the existing fail-open-until-scanned semantics.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"mal-unscanned-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/acme@1.0.0");
        var req = BaseRequest(orgId) with
        {
            VersionId = verId,
            VulnCheckedAt = null,
            BlockMaliciousMode = "block",
        };
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"MAL-2026-{Guid.NewGuid():N}", severity: null, cvssScore: null);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, req.VersionId, vulnId);

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_malicious"));
    }

    // ── KEV / EPSS gates ──────────────────────────────────────────────────────

    [Fact]
    public async Task Kev_BlockMode_Blocks_AndLogsAdvisoryIds()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"kev-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/acme@1.0.0");
        var req = BaseRequest(orgId) with
        {
            VersionId = verId,
            VulnCheckedAt = _clock.GetUtcNow(),
            BlockKevMode = "block",
        };
        string kevOsvId = $"GHSA-kev-{Guid.NewGuid():N}";
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, kevOsvId, severity: "HIGH", cvssScore: 7.0, isKev: true);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, req.VersionId, vulnId);

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_kev"));

        await using var conn = await _fixture.Store.OpenAsync();
        string? detail = await conn.ExecuteScalarAsync<string>(
            "SELECT detail FROM activity WHERE event_type = 'blocked_kev' AND org_id = @orgId",
            new { orgId });
        Assert.Contains(kevOsvId, detail);
    }

    [Theory]
    [InlineData("off")]
    [InlineData("warn")]
    [InlineData(null)]
    public async Task Kev_NonBlockingModes_AllowThrough(string? mode)
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"kev-allow-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/acme@1.0.0");
        var req = BaseRequest(orgId) with
        {
            VersionId = verId,
            VulnCheckedAt = _clock.GetUtcNow(),
            BlockKevMode = mode,
        };
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-kev-{Guid.NewGuid():N}", severity: null, cvssScore: null, isKev: true);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, req.VersionId, vulnId);

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_kev"));
    }

    [Fact]
    public async Task Epss_AboveTolerance_Blocks_AndLogsDetail()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"epss-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/acme@1.0.0");
        var req = BaseRequest(orgId) with
        {
            VersionId = verId,
            VulnCheckedAt = _clock.GetUtcNow(),
            MaxEpssTolerance = 0.5,
        };
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-epss-{Guid.NewGuid():N}", severity: null, cvssScore: null, epssScore: 0.92);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, req.VersionId, vulnId);

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_epss"));

        await using var conn = await _fixture.Store.OpenAsync();
        string? detail = await conn.ExecuteScalarAsync<string>(
            "SELECT detail FROM activity WHERE event_type = 'blocked_epss' AND org_id = @orgId",
            new { orgId });
        Assert.Contains("\"max_epss\":0.92", detail);
        Assert.Contains("\"tolerance\":0.5", detail);
    }

    [Theory]
    [InlineData(0.92)] // equal to the score — pass-on-equal matches the CVSS convention
    [InlineData(0.95)]
    public async Task Epss_AtOrBelowTolerance_AllowsThrough(double tolerance)
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"epss-ok-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/acme@1.0.0");
        var req = BaseRequest(orgId) with
        {
            VersionId = verId,
            VulnCheckedAt = _clock.GetUtcNow(),
            MaxEpssTolerance = tolerance,
        };
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-epss-ok-{Guid.NewGuid():N}", severity: null, cvssScore: null, epssScore: 0.92);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, req.VersionId, vulnId);

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_epss"));
    }

    [Fact]
    public async Task Epss_PolicyUnset_DoesNotEvaluate()
    {
        // NULL tolerance = policy off even for a near-certain exploitation score.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"epss-unset-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/acme@1.0.0");
        var req = BaseRequest(orgId) with
        {
            VersionId = verId,
            VulnCheckedAt = _clock.GetUtcNow(),
            MaxEpssTolerance = null,
        };
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-epss-unset-{Guid.NewGuid():N}", severity: null, cvssScore: null, epssScore: 0.99);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, req.VersionId, vulnId);

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_epss"));
    }

    [Fact]
    public async Task GatePriority_MaliciousBeatsKev_KevBeatsEpss_SingleEvent()
    {
        // One advisory trips every signal at once; exactly one event fires, in priority order.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"prio-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/acme@1.0.0");
        var req = BaseRequest(orgId) with
        {
            VersionId = verId,
            VulnCheckedAt = _clock.GetUtcNow(),
            BlockMaliciousMode = "block",
            BlockKevMode = "block",
            MaxEpssTolerance = 0.1,
            MaxOsvScoreTolerance = 0.0,
        };
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"MAL-2026-{Guid.NewGuid():N}",
            severity: "CRITICAL", cvssScore: 9.9, isKev: true, epssScore: 0.99);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, req.VersionId, vulnId);

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_malicious"));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_kev"));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_epss"));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_vuln_score"));
    }

    [Fact]
    public async Task ManualAllow_ShortCircuits_PastKevAndEpssGates()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"kev-ma-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/acme@1.0.0");
        var req = BaseRequest(orgId) with
        {
            VersionId = verId,
            ManualState = "allowed",
            VulnCheckedAt = _clock.GetUtcNow(),
            BlockKevMode = "block",
            MaxEpssTolerance = 0.1,
        };
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-kev-ma-{Guid.NewGuid():N}", isKev: true, epssScore: 0.9);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, req.VersionId, vulnId);

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_kev"));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_epss"));
    }

    // ── quarantine review-row side effects ────────────────────────────────────

    [Fact]
    public async Task PolicyBlock_WritesPendingReviewRow()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"qr-{Guid.NewGuid():N}");
        // Empty VersionId maps to a NULL review-row FK — the first-fetch shape, where the
        // block fires before any version row exists.
        var req = BaseRequest(orgId) with
        {
            VersionId = string.Empty,
            MinReleaseAgeHours = 24,
            PublishedAt = _clock.GetUtcNow().AddHours(-1),
        };

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));

        var quarantine = new QuarantineRepository(_fixture.Store, _clock);
        var (items, total) = await quarantine.ListAsync(new QuarantineListQuery(orgId, State: "pending", Limit: 10));
        Assert.Equal(1, total);
        Assert.Equal("release_age", items[0].Gate);
        Assert.Equal(req.Purl, items[0].Purl);
        Assert.Contains("min_age_hours", items[0].Detail);
    }

    [Fact]
    public async Task ManualBlock_DoesNotWriteReviewRow()
    {
        // A manual block is already a human decision — queueing it for review would be noise.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"qr-manual-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with { ManualState = "blocked" };

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));

        var quarantine = new QuarantineRepository(_fixture.Store, _clock);
        var (_, total) = await quarantine.ListAsync(new QuarantineListQuery(orgId, Limit: 10));
        Assert.Equal(0, total);
    }

    [Fact]
    public async Task FirstFetchDeprecation_ApprovedReviewRow_Unblocks()
    {
        // The version-less unblock path: a first-fetch block has no version row to carry a
        // manual_block_state, so an approved review row on the purl is the override.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"qr-ff-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            VersionId = string.Empty,
            Deprecated = "abandoned",
            BlockDeprecatedMode = "block_new",
        };

        // First fetch blocks and queues the pending row.
        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateFirstFetchDeprecationAsync(req));
        var quarantine = new QuarantineRepository(_fixture.Store, _clock);
        var (items, _) = await quarantine.ListAsync(new QuarantineListQuery(orgId, State: "pending", Limit: 10));
        string id = items.Single(i => i.Purl == req.Purl).Id;

        // Approval flips the next first fetch to allowed.
        Assert.True(await quarantine.DecideAsync(orgId, id, "approved", null, null));
        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateFirstFetchDeprecationAsync(req));
    }

    [Fact]
    public async Task FirstFetchDeprecation_DeniedReviewRow_StaysBlocked()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"qr-ffd-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            VersionId = string.Empty,
            Deprecated = "abandoned",
            BlockDeprecatedMode = "block_new",
        };

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateFirstFetchDeprecationAsync(req));
        var quarantine = new QuarantineRepository(_fixture.Store, _clock);
        var (items, _) = await quarantine.ListAsync(new QuarantineListQuery(orgId, State: "pending", Limit: 10));
        await quarantine.DecideAsync(orgId, items.Single(i => i.Purl == req.Purl).Id, "denied", null, null);

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateFirstFetchDeprecationAsync(req));
    }

    // ── release-age cooldown origin exemption ─────────────────────────────────

    [Fact]
    public async Task ReleaseAge_HostedOrigin_ExemptsFromCooldown()
    {
        // Hosted packages set PublishedAt to the local push time, not an upstream release date.
        // A version pushed 1 hour ago must not be self-blocked by a 48-hour cooldown.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"ra-hosted-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            MinReleaseAgeHours = 48,
            PublishedAt = _clock.GetUtcNow().AddHours(-1),
            Origin = "hosted",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_release_age"));
    }

    [Fact]
    public async Task ReleaseAge_LocalOnlyOrigin_ExemptsFromCooldown()
    {
        // local_only follows the same exemption rationale as hosted: the publish timestamp
        // reflects a local push, not an upstream release.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"ra-local-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            MinReleaseAgeHours = 48,
            PublishedAt = _clock.GetUtcNow().AddHours(-1),
            Origin = "local_only",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_release_age"));
    }

    [Fact]
    public async Task ReleaseAge_ProxyOrigin_StillBlockedWithinCooldown()
    {
        // Proxy versions carry an upstream publish timestamp; the cooldown applies as intended.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"ra-proxy-young-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            MinReleaseAgeHours = 48,
            PublishedAt = _clock.GetUtcNow().AddHours(-1),
            Origin = "proxy",
        };

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_release_age"));
    }

    [Fact]
    public async Task ReleaseAge_ProxyOrigin_AllowedOnceCooldownExpires()
    {
        // A proxy version published 72 hours ago clears a 48-hour hold with comfortable margin.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"ra-proxy-old-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            MinReleaseAgeHours = 48,
            PublishedAt = _clock.GetUtcNow().AddHours(-72),
            Origin = "proxy",
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_release_age"));
    }

    // ── OCI-plane license-expression arm ──────────────────────────────────────

    [Fact]
    public async Task LicenseExpression_WarnMode_AllowedWithoutRepoCall()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"lic-warn-{Guid.NewGuid():N}");
        await LicensePolicySeeder.AddBlocklistEntryAsync(_fixture.Store, orgId, "GPL-3.0-only");
        var req = BaseRequest(orgId) with { Ecosystem = "oci", LicenseEnforcementMode = "warn" };

        Assert.Equal(BlockDecision.Allowed,
            await _sut.EvaluateLicenseExpressionAsync(req, ["GPL-3.0-only"]));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_license"));
    }

    [Fact]
    public async Task LicenseExpression_EmptyEntries_AllowedFailOpen()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"lic-empty-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with { Ecosystem = "oci", LicenseEnforcementMode = "block" };

        Assert.Equal(BlockDecision.Allowed,
            await _sut.EvaluateLicenseExpressionAsync(req, []));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_license"));
    }

    [Fact]
    public async Task LicenseExpression_BlockedUnderBlockMode_BlocksAndRecordsSideEffects()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"lic-block-{Guid.NewGuid():N}");
        // In 'block' mode a leaf is servable only when explicitly allowlisted; GPL is neither
        // allowlisted nor is anything, so the license is blocked.
        await LicensePolicySeeder.AddBlocklistEntryAsync(_fixture.Store, orgId, "GPL-3.0-only");
        var req = BaseRequest(orgId) with
        {
            Ecosystem = "oci",
            Purl = "pkg:oci/library/demo@sha256:abc",
            VersionId = string.Empty,
            LicenseEnforcementMode = "block",
        };

        Assert.Equal(BlockDecision.Blocked,
            await _sut.EvaluateLicenseExpressionAsync(req, ["GPL-3.0-only"]));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_license"));

        var quarantine = new QuarantineRepository(_fixture.Store, _clock);
        var (items, total) = await quarantine.ListAsync(new QuarantineListQuery(orgId, State: "pending", Limit: 10));
        Assert.Equal(1, total);
        Assert.Equal(req.Purl, items.Single().Purl);
    }

    // ── webhook dispatch (package.blocked) ──────────────────────────────────────

    [Fact]
    public async Task Refusal_DispatchesExactlyOneBlockedWebhookEvent_WithExpectedPayload()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"wh-single-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with { ManualState = "blocked", Purl = "pkg:npm/acme@2.3.4" };

        var captured = new List<PackageEventEnvelope>();
        _eventSink.Dispatch(Arg.Do<PackageEventEnvelope>(e => captured.Add(e)));

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));

        var envelope = Assert.Single(captured);
        Assert.Equal(PackageEvents.TypeBlocked, envelope.EventType);
        Assert.Equal(orgId, envelope.OrgId);
        Assert.Equal("npm", envelope.Ecosystem);
        Assert.Equal("acme", envelope.Name);
        Assert.Equal("2.3.4", envelope.Version);
        Assert.Equal(req.Purl, envelope.Purl);

        using var doc = JsonDocument.Parse(envelope.DataJson);
        Assert.Equal("manual", doc.RootElement.GetProperty("arm").GetString());
        Assert.Equal("acme", doc.RootElement.GetProperty("name").GetString());
        Assert.Equal("npm", doc.RootElement.GetProperty("ecosystem").GetString());
        Assert.Equal(JsonValueKind.Null, doc.RootElement.GetProperty("severity").ValueKind);
    }

    [Fact]
    public async Task VulnScoreArm_PayloadCarriesCvssSeverity()
    {
        // The vuln-score arm is the one arm whose block reason is itself a CVSS score, so its
        // webhook payload carries a real severity band rather than the null every other arm sends.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"wh-sev-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}/acme@1.0.0");
        var req = BaseRequest(orgId) with
        {
            VersionId = verId,
            Purl = "pkg:npm/acme@1.0.0",
            VulnCheckedAt = _clock.GetUtcNow(),
            MaxOsvScoreTolerance = 5.0,
        };
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-sev-{Guid.NewGuid():N}", severity: "CRITICAL", cvssScore: 9.8);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, req.VersionId, vulnId);

        var captured = new List<PackageEventEnvelope>();
        _eventSink.Dispatch(Arg.Do<PackageEventEnvelope>(e => captured.Add(e)));

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));

        var envelope = Assert.Single(captured);
        using var doc = JsonDocument.Parse(envelope.DataJson);
        Assert.Equal("vuln_score", doc.RootElement.GetProperty("arm").GetString());
        Assert.Equal("CRITICAL", doc.RootElement.GetProperty("severity").GetString());
    }

    [Fact]
    public async Task RepeatedRefusal_SameCoordinate_CoalescesWithinWindow_ThenResumesAfter()
    {
        // A CI loop hammering the same blocked (org, purl, arm) coordinate must not flood the
        // dispatch queue with one envelope per request: only the first refusal inside the window
        // dispatches, and advancing the clock past the window lets the next refusal dispatch again.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"wh-coalesce-{Guid.NewGuid():N}");
        var (gate, sink) = BuildGateWithThrottle(TimeSpan.FromMinutes(15));
        var req = BaseRequest(orgId) with { ManualState = "blocked", Purl = "pkg:npm/acme@2.3.4" };

        Assert.Equal(BlockDecision.Blocked, await gate.EvaluateAsync(req));
        Assert.Equal(BlockDecision.Blocked, await gate.EvaluateAsync(req));
        Assert.Equal(BlockDecision.Blocked, await gate.EvaluateAsync(req));
        sink.Received(1).Dispatch(Arg.Any<PackageEventEnvelope>());

        _clock.Advance(TimeSpan.FromMinutes(15));

        Assert.Equal(BlockDecision.Blocked, await gate.EvaluateAsync(req));
        sink.Received(2).Dispatch(Arg.Any<PackageEventEnvelope>());
    }

    [Fact]
    public async Task RepeatedRefusal_DifferentArmOrDifferentPurl_NotCoalesced()
    {
        // Adversarial twin of the coalescing test above: the throttle must discriminate the
        // (org, purl, arm) coordinate, not just the org — a different arm on the same purl, and
        // the same arm on a different purl, both dispatch independently within the same window.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"wh-discriminate-{Guid.NewGuid():N}");
        var (gate, sink) = BuildGateWithThrottle(TimeSpan.FromMinutes(15));

        var manualBlock = BaseRequest(orgId) with { ManualState = "blocked", Purl = "pkg:npm/acme@2.3.4" };
        var releaseAgeBlock = BaseRequest(orgId) with
        {
            Purl = "pkg:npm/acme@2.3.4",
            MinReleaseAgeHours = 24,
            PublishedAt = _clock.GetUtcNow().AddHours(-1),
        };
        var otherPurlManualBlock = BaseRequest(orgId) with { ManualState = "blocked", Purl = "pkg:npm/other@9.9.9" };

        Assert.Equal(BlockDecision.Blocked, await gate.EvaluateAsync(manualBlock));
        Assert.Equal(BlockDecision.Blocked, await gate.EvaluateAsync(releaseAgeBlock));
        Assert.Equal(BlockDecision.Blocked, await gate.EvaluateAsync(otherPurlManualBlock));

        sink.Received(3).Dispatch(Arg.Any<PackageEventEnvelope>());
    }

    [Fact]
    public async Task RepeatedRefusal_ThrottledDispatch_StillWritesActivityRowEveryTime()
    {
        // The throttle narrows webhook dispatch only — it must never suppress the
        // audit/activity/quarantine trail that already protects the tenant.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"wh-audit-{Guid.NewGuid():N}");
        var (gate, sink) = BuildGateWithThrottle(TimeSpan.FromMinutes(15));
        var req = BaseRequest(orgId) with { ManualState = "blocked", Purl = "pkg:npm/acme@2.3.4" };

        for (int i = 0; i < 3; i++)
        {
            Assert.Equal(BlockDecision.Blocked, await gate.EvaluateAsync(req));
        }

        sink.Received(1).Dispatch(Arg.Any<PackageEventEnvelope>());
        Assert.Equal(3, await CountActivityAsync(orgId, "blocked_manual"));
    }

    [Fact]
    public async Task Refusal_WebhookDispatchThrows_StillBlocksAndWritesActivityAndQuarantineRows()
    {
        // EmitBlockWebhookEventAsync is best-effort: a failure inside the sink (a bad subscriber
        // URL resolving synchronously, a serialization bug, anything) must never turn a correct
        // block into an unhandled exception, and it must never cost the audit/activity/quarantine
        // trail that already protects the tenant — those are written before the dispatch call.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"wh-throws-{Guid.NewGuid():N}");
        // Empty VersionId maps to a NULL review-row FK — the first-fetch shape, where the block
        // fires before any version row exists (matches PolicyBlock_WritesPendingReviewRow above).
        var req = BaseRequest(orgId) with
        {
            VersionId = string.Empty,
            Purl = "pkg:npm/acme@2.3.4",
            MinReleaseAgeHours = 24,
            PublishedAt = _clock.GetUtcNow().AddHours(-1),
        };

        _eventSink.When(x => x.Dispatch(Arg.Any<PackageEventEnvelope>()))
            .Do(_ => throw new InvalidOperationException("dispatch boom"));

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_release_age"));

        var quarantine = new QuarantineRepository(_fixture.Store, _clock);
        var (items, total) = await quarantine.ListAsync(new QuarantineListQuery(orgId, State: "pending", Limit: 10));
        Assert.Equal(1, total);
        Assert.Equal(req.Purl, items.Single().Purl);
    }

    [Fact]
    public async Task FirstFetchDeprecationBlock_DispatchesTheSameEventShapeAsServePath()
    {
        // EvaluateFirstFetchDeprecationAsync is ProxyFetchService's cache-miss entry point — a
        // separate call path into RecordDeprecatedBlockAsync from the cache-hit serve path
        // (EvaluateAsync → ApplySideEffectsAsync). Both must reach the one shared webhook
        // emission helper, not just the serve path.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"wh-ff-dep-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            Purl = "pkg:npm/acme@2.3.4",
            Deprecated = "abandoned",
            BlockDeprecatedMode = "block_all",
        };

        var captured = new List<PackageEventEnvelope>();
        _eventSink.Dispatch(Arg.Do<PackageEventEnvelope>(e => captured.Add(e)));

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateFirstFetchDeprecationAsync(req));

        var envelope = Assert.Single(captured);
        Assert.Equal(PackageEvents.TypeBlocked, envelope.EventType);
        using var doc = JsonDocument.Parse(envelope.DataJson);
        Assert.Equal("deprecated", doc.RootElement.GetProperty("arm").GetString());
    }

    [Fact]
    public async Task FirstFetchProvenanceBlock_DispatchesTheSameEventShapeAsServePath()
    {
        // RecordProvenanceBlockAsync is public specifically so ProxyFetchService can call it
        // directly on the cache-miss first-fetch path (fail closed, before the version is
        // recorded) — the same shared side-effect method the serve path's ApplySideEffectsAsync
        // switch also calls for the Provenance arm.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"wh-ff-prov-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            VersionId = string.Empty,
            Purl = "pkg:npm/acme@2.3.4",
            ProvenanceStatus = "unsigned",
        };

        var captured = new List<PackageEventEnvelope>();
        _eventSink.Dispatch(Arg.Do<PackageEventEnvelope>(e => captured.Add(e)));

        await _sut.RecordProvenanceBlockAsync(req);

        var envelope = Assert.Single(captured);
        Assert.Equal(PackageEvents.TypeBlocked, envelope.EventType);
        using var doc = JsonDocument.Parse(envelope.DataJson);
        Assert.Equal("provenance", doc.RootElement.GetProperty("arm").GetString());
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private (BlockGateService Gate, Dependably.Infrastructure.Webhooks.IPackageEventSink Sink) BuildGateWithThrottle(
        TimeSpan window)
    {
        var sink = NSubstitute.Substitute.For<Dependably.Infrastructure.Webhooks.IPackageEventSink>();
        var gate = new BlockGateService(
            new VulnerabilityRepository(_fixture.Store, _clock),
            _audit,
            new QuarantineRepository(_fixture.Store, _clock),
            new AlertService(new AlertRepository(_fixture.Store, _clock), new NoOpAlertNotifier(), Microsoft.Extensions.Logging.Abstractions.NullLogger<AlertService>.Instance),
            new InstallScriptAllowlistService(_fixture.Store, new Microsoft.Extensions.Caching.Memory.MemoryCache(new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()), _clock),
            new LicenseRepository(_fixture.Store, _clock, new LicenseNormalizer(_fixture.Store, Microsoft.Extensions.Logging.Abstractions.NullLogger<LicenseNormalizer>.Instance)),
            _anchors,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<BlockGateService>.Instance,
            _clock,
            new OrgRepository(_fixture.Store),
            sink,
            new BlockRefusalWebhookThrottle(_clock, window));
        return (gate, sink);
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
