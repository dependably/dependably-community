using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Xunit;

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
    private readonly BlockGateService _sut;
    private readonly AuditRepository _audit;

    public BlockGateServiceTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _audit = new AuditRepository(_fixture.Store);
        _sut = new BlockGateService(new VulnerabilityRepository(_fixture.Store), _audit);
    }

    // ── manual-block / manual-allow ───────────────────────────────────────────

    [Fact]
    public async Task ManualBlock_Wins_OverEverythingElse()
    {
        // Manual block takes precedence even when release-age would have allowed and OSV is fine.
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"mb-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            ManualState = "blocked",
            MinReleaseAgeHours = 24,
            PublishedAt = DateTimeOffset.UtcNow.AddDays(-30),
        };

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_manual"));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_release_age"));
    }

    [Fact]
    public async Task ManualAllow_ShortCircuits_PastReleaseAgeAndOsv()
    {
        // Operator override: manual allow returns early, skipping both auto gates.
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"ma-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            ManualState = "allowed",
            MinReleaseAgeHours = 48,
            PublishedAt = DateTimeOffset.UtcNow.AddHours(-1), // would be blocked by release-age
            VulnCheckedAt = DateTimeOffset.UtcNow,
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_release_age"));
    }

    // ── release-age branch ────────────────────────────────────────────────────

    [Fact]
    public async Task ReleaseAge_TooYoung_Blocks_AndLogsActivity()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"young-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            MinReleaseAgeHours = 24,
            PublishedAt = DateTimeOffset.UtcNow.AddHours(-6), // 18 hours short of the hold
        };

        Assert.Equal(BlockDecision.Blocked, await _sut.EvaluateAsync(req));
        Assert.Equal(1, await CountActivityAsync(orgId, "blocked_release_age"));

        // Detail JSON carries the three diagnostic fields the dashboard renders.
        await using var conn = await _fixture.Store.OpenAsync();
        var detail = await conn.ExecuteScalarAsync<string>(
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
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"old-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            MinReleaseAgeHours = 24,
            PublishedAt = DateTimeOffset.UtcNow.AddDays(-7),
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_release_age"));
    }

    [Fact]
    public async Task ReleaseAge_NullPublishedAt_FailsOpen()
    {
        // Upstream metadata didn't carry a timestamp (rare quirk in older NuGet/npm rows).
        // Documented design choice: don't block on missing data — let the artefact through.
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"nopub-{Guid.NewGuid():N}");
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
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"unset-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            MinReleaseAgeHours = null,
            PublishedAt = DateTimeOffset.UtcNow,
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_release_age"));
    }

    [Fact]
    public async Task ReleaseAge_ZeroHours_TreatedAsOff()
    {
        // 0 is a valid integer the controller could persist if a future migration zeroed the
        // column; the gate treats it as policy-off rather than blocking everything.
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"zero-{Guid.NewGuid():N}");
        var req = BaseRequest(orgId) with
        {
            MinReleaseAgeHours = 0,
            PublishedAt = DateTimeOffset.UtcNow,
        };

        Assert.Equal(BlockDecision.Allowed, await _sut.EvaluateAsync(req));
        Assert.Equal(0, await CountActivityAsync(orgId, "blocked_release_age"));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static BlockGateRequest BaseRequest(string orgId) => new(
        OrgId: orgId,
        Ecosystem: "npm",
        Purl: "pkg:npm/test@1.0.0",
        VersionId: Guid.NewGuid().ToString("N"),
        ManualState: null,
        VulnCheckedAt: null,
        UserId: null,
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
