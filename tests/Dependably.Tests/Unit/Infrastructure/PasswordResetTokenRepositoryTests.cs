using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Unit tests for <see cref="PasswordResetTokenRepository"/>: issuance voids any outstanding
/// token, the atomic single-winner consume, expiry rejection, and the cross-tenant keying
/// property (a token is bound to the exact user it was minted for, never to any other user
/// that happens to share the same email in a different org).
/// </summary>
[Trait("Category", "Unit")]
public sealed class PasswordResetTokenRepositoryTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public PasswordResetTokenRepositoryTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private async Task<(string OrgId, string UserId)> SeedOrgAndUserAsync(string suffix, string email)
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"prt-org-{suffix}");
        string userId = await UserSeeder.InsertAsync(_fixture.Store, orgId, email);
        return (orgId, userId);
    }

    // ── IssueAsync / ConsumeAsync — happy path ──────────────────────────────

    [Fact]
    public async Task ConsumeAsync_ValidToken_ReturnsRecord_SetsConsumedAt()
    {
        var clock = TestTime.Frozen();
        string suffix = Guid.NewGuid().ToString("N");
        var (orgId, userId) = await SeedOrgAndUserAsync(suffix, $"reset-{suffix}@x.test");
        var repo = new PasswordResetTokenRepository(_fixture.Store, clock);

        string raw = await repo.IssueAsync(userId, orgId);
        var record = await repo.ConsumeAsync(raw);

        Assert.NotNull(record);
        Assert.Equal(userId, record.UserId);
        Assert.Equal(orgId, record.OrgId);
        Assert.Equal($"reset-{suffix}@x.test", record.Email);
    }

    [Fact]
    public async Task ConsumeAsync_SecondCall_SameToken_ReturnsNull()
    {
        var clock = TestTime.Frozen();
        string suffix = Guid.NewGuid().ToString("N");
        var (orgId, userId) = await SeedOrgAndUserAsync(suffix, $"double-{suffix}@x.test");
        var repo = new PasswordResetTokenRepository(_fixture.Store, clock);

        string raw = await repo.IssueAsync(userId, orgId);

        var first = await repo.ConsumeAsync(raw);
        var second = await repo.ConsumeAsync(raw);

        Assert.NotNull(first);
        Assert.Null(second);  // already-used — single-use twin
    }

    [Fact]
    public async Task ConsumeAsync_ExpiredToken_ReturnsNull()
    {
        var clock = TestTime.Frozen();
        string suffix = Guid.NewGuid().ToString("N");
        var (orgId, userId) = await SeedOrgAndUserAsync(suffix, $"expired-{suffix}@x.test");
        var repo = new PasswordResetTokenRepository(_fixture.Store, clock);

        // Issue at T0 (30-minute TTL), then advance well past the boundary — far enough that
        // clock skew in the string round-trip can never flip the assertion.
        string raw = await repo.IssueAsync(userId, orgId);
        clock.Advance(TimeSpan.FromHours(2));

        var record = await repo.ConsumeAsync(raw);

        Assert.Null(record);
    }

    [Fact]
    public async Task ConsumeAsync_UnknownToken_ReturnsNull()
    {
        var clock = TestTime.Frozen();
        var repo = new PasswordResetTokenRepository(_fixture.Store, clock);

        var record = await repo.ConsumeAsync("completely-invalid-token-that-does-not-exist");

        Assert.Null(record);
    }

    // ── PeekAsync — non-consuming ────────────────────────────────────────────

    [Fact]
    public async Task PeekAsync_ValidToken_DoesNotConsume_SubsequentConsumeStillWorks()
    {
        var clock = TestTime.Frozen();
        string suffix = Guid.NewGuid().ToString("N");
        var (orgId, userId) = await SeedOrgAndUserAsync(suffix, $"peek-{suffix}@x.test");
        var repo = new PasswordResetTokenRepository(_fixture.Store, clock);

        string raw = await repo.IssueAsync(userId, orgId);

        var peeked = await repo.PeekAsync(raw);
        Assert.NotNull(peeked);
        Assert.Equal(userId, peeked.UserId);

        // The link's single use is unaffected by peeking.
        var consumed = await repo.ConsumeAsync(raw);
        Assert.NotNull(consumed);
    }

    [Fact]
    public async Task PeekAsync_ExpiredToken_ReturnsNull()
    {
        var clock = TestTime.Frozen();
        string suffix = Guid.NewGuid().ToString("N");
        var (orgId, userId) = await SeedOrgAndUserAsync(suffix, $"peek-expired-{suffix}@x.test");
        var repo = new PasswordResetTokenRepository(_fixture.Store, clock);

        string raw = await repo.IssueAsync(userId, orgId);
        clock.Advance(TimeSpan.FromHours(2));

        Assert.Null(await repo.PeekAsync(raw));
    }

    // ── IssueAsync — voids any outstanding token ─────────────────────────────

    [Fact]
    public async Task IssueAsync_SecondCall_VoidsFirstOutstandingToken()
    {
        var clock = TestTime.Frozen();
        string suffix = Guid.NewGuid().ToString("N");
        var (orgId, userId) = await SeedOrgAndUserAsync(suffix, $"reissue-{suffix}@x.test");
        var repo = new PasswordResetTokenRepository(_fixture.Store, clock);

        string first = await repo.IssueAsync(userId, orgId);
        string second = await repo.IssueAsync(userId, orgId);

        // The stale first link is voided the moment a fresher one is requested.
        Assert.Null(await repo.ConsumeAsync(first));
        Assert.NotNull(await repo.ConsumeAsync(second));
    }

    // ── Cross-tenant keying: token is bound to its exact user, never to a same-email peer ──

    /// <summary>
    /// Two different orgs each have a user with the identical email address (the users table's
    /// uniqueness constraint is (tenant_id, email), not email alone — this is a legitimate,
    /// supported state). A reset token minted for org A's user must resolve to, and only ever be
    /// consumable against, that exact <c>user_id</c> — never org B's user with the matching
    /// email. This is the "must NOT" twin for the self-serve reset flow's tenant-crossing risk.
    /// </summary>
    [Fact]
    public async Task ConsumeAsync_TokenMintedForOrgAUser_NeverResolvesToOrgBUser_EvenWithSameEmail()
    {
        var clock = TestTime.Frozen();
        string suffix = Guid.NewGuid().ToString("N");
        string sharedEmail = $"shared-{suffix}@x.test";

        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"prt-orgA-{suffix}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"prt-orgB-{suffix}");
        string userA = await UserSeeder.InsertAsync(_fixture.Store, orgA, sharedEmail);
        string userB = await UserSeeder.InsertAsync(_fixture.Store, orgB, sharedEmail);

        var repo = new PasswordResetTokenRepository(_fixture.Store, clock);
        string rawForA = await repo.IssueAsync(userA, orgA);

        var consumed = await repo.ConsumeAsync(rawForA);

        Assert.NotNull(consumed);
        Assert.Equal(userA, consumed.UserId);
        Assert.Equal(orgA, consumed.OrgId);
        Assert.NotEqual(userB, consumed.UserId);
        Assert.NotEqual(orgB, consumed.OrgId);
    }
}
