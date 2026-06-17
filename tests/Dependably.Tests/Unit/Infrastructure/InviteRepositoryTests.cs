using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Unit tests for <see cref="InviteRepository"/> covering the atomic accept, expiry
/// rejection, pending count, and expired-row prune.
/// </summary>
[Trait("Category", "Unit")]
public sealed class InviteRepositoryTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public InviteRepositoryTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private async Task<(string OrgId, string InviterId)> SeedOrgAndInviterAsync(string suffix)
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"invite-org-{suffix}");
        string inviterId = await UserSeeder.InsertAsync(
            _fixture.Store, orgId, $"inviter-{suffix}@x.test", "owner");
        return (orgId, inviterId);
    }

    // ── AcceptAsync — first call wins ────────────────────────────────────────

    [Fact]
    public async Task AcceptAsync_ValidToken_ReturnsRecord_SetsAcceptedAt()
    {
        var clock = TestTime.Frozen();
        var (orgId, inviterId) = await SeedOrgAndInviterAsync(Guid.NewGuid().ToString("N"));
        var repo = new InviteRepository(_fixture.Store, clock);

        var (raw, _) = await repo.CreateAsync(orgId, "invited@x.test", inviterId);

        var record = await repo.AcceptAsync(raw);

        Assert.NotNull(record);
        Assert.Equal(orgId, record.OrgId);
        Assert.Equal("invited@x.test", record.Email);
        // accepted_at must be the frozen instant, not an approximation.
        Assert.Equal(clock.GetUtcNow(), record.AcceptedAt);
    }

    [Fact]
    public async Task AcceptAsync_SecondCall_SameToken_ReturnsNull()
    {
        var clock = TestTime.Frozen();
        var (orgId, inviterId) = await SeedOrgAndInviterAsync(Guid.NewGuid().ToString("N"));
        var repo = new InviteRepository(_fixture.Store, clock);

        var (raw, _) = await repo.CreateAsync(orgId, "double@x.test", inviterId);

        var first = await repo.AcceptAsync(raw);
        var second = await repo.AcceptAsync(raw);

        Assert.NotNull(first);
        Assert.Null(second);  // already-used
    }

    [Fact]
    public async Task AcceptAsync_ExpiredToken_ReturnsNull()
    {
        var clock = TestTime.Frozen();
        var (orgId, inviterId) = await SeedOrgAndInviterAsync(Guid.NewGuid().ToString("N"));
        var repo = new InviteRepository(_fixture.Store, clock);

        // Create with the clock frozen at T0, then advance clock far past the 24-hour TTL.
        var (raw, _) = await repo.CreateAsync(orgId, "expired@x.test", inviterId);
        clock.Advance(TimeSpan.FromHours(48));

        var record = await repo.AcceptAsync(raw);

        Assert.Null(record);
    }

    [Fact]
    public async Task AcceptAsync_UnknownToken_ReturnsNull()
    {
        var clock = TestTime.Frozen();
        var repo = new InviteRepository(_fixture.Store, clock);

        var record = await repo.AcceptAsync("completely-invalid-token-that-does-not-exist");

        Assert.Null(record);
    }

    // ── CountPendingAsync ────────────────────────────────────────────────────

    [Fact]
    public async Task CountPendingAsync_ExcludesAcceptedAndExpiredRows()
    {
        var clock = TestTime.Frozen();
        var (orgId, inviterId) = await SeedOrgAndInviterAsync(Guid.NewGuid().ToString("N"));
        var repo = new InviteRepository(_fixture.Store, clock);

        // Seed three invites: one pending, one to accept, one that will expire.
        var (_, _) = await repo.CreateAsync(orgId, "pending@x.test", inviterId);
        var (rawAccept, _) = await repo.CreateAsync(orgId, "accept@x.test", inviterId);
        var (_, _) = await repo.CreateAsync(orgId, "expire@x.test", inviterId);

        // Accept one.
        await repo.AcceptAsync(rawAccept);

        // Expire one by advancing the clock past TTL before accepting — re-create from scratch.
        // The already-seeded expire invite will become stale when the clock advances.
        clock.Advance(TimeSpan.FromHours(48));

        // At T+48h: only "pending" row was created before the clock advance and is now also expired.
        // Count should be zero because all 24-hour invites are past expiry at T+48h.
        int countAfterAdvance = await repo.CountPendingAsync(orgId);
        Assert.Equal(0, countAfterAdvance);

        // Create a fresh invite at T+48h; it expires at T+72h.
        clock.Advance(TimeSpan.FromHours(0)); // still T+48h
        var (_, _) = await repo.CreateAsync(orgId, "fresh@x.test", inviterId);
        int countWithFresh = await repo.CountPendingAsync(orgId);
        Assert.Equal(1, countWithFresh);
    }

    [Fact]
    public async Task CountPendingAsync_IsScopedToOrg()
    {
        var clock = TestTime.Frozen();
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"count-orgA-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"count-orgB-{Guid.NewGuid():N}");
        string invA = await UserSeeder.InsertAsync(_fixture.Store, orgA, $"ia-{Guid.NewGuid():N}@x.test", "owner");
        string invB = await UserSeeder.InsertAsync(_fixture.Store, orgB, $"ib-{Guid.NewGuid():N}@x.test", "owner");
        var repo = new InviteRepository(_fixture.Store, clock);

        await repo.CreateAsync(orgA, $"u1-{Guid.NewGuid():N}@x.test", invA);
        await repo.CreateAsync(orgA, $"u2-{Guid.NewGuid():N}@x.test", invA);
        await repo.CreateAsync(orgB, $"u3-{Guid.NewGuid():N}@x.test", invB);

        Assert.Equal(2, await repo.CountPendingAsync(orgA));
        Assert.Equal(1, await repo.CountPendingAsync(orgB));
    }

    // ── PruneExpiredAsync ────────────────────────────────────────────────────

    [Fact]
    public async Task PruneExpiredAsync_DeletesOnlyExpiredUnacceptedRows()
    {
        // Use unique email suffixes per test run to distinguish this test's rows from any
        // other data that may exist in the shared class fixture. Assertions check the
        // org-scoped list, not the global prune count (which includes all orgs' rows).
        string suffix = Guid.NewGuid().ToString("N");
        var clock = TestTime.Frozen();
        var (orgId, inviterId) = await SeedOrgAndInviterAsync(suffix);
        var repo = new InviteRepository(_fixture.Store, clock);

        string emailExpiring = $"expiring-{suffix}@x.test";
        string emailAccepted = $"toacceptexp-{suffix}@x.test";
        string emailFresh = $"fresh-{suffix}@x.test";

        // Seed: one pending (will expire), one to be accepted before expiry.
        var (_, _) = await repo.CreateAsync(orgId, emailExpiring, inviterId);
        var (rawAccept, _) = await repo.CreateAsync(orgId, emailAccepted, inviterId);

        // Accept one now (before advancing clock).
        await repo.AcceptAsync(rawAccept);

        // Advance past 24-hour TTL.
        clock.Advance(TimeSpan.FromHours(36));

        // Create a fresh invite that should survive the prune (expires at T+60h).
        await repo.CreateAsync(orgId, emailFresh, inviterId);

        // Prune fires; count may be >= 1 because other tests share the fixture and may have
        // left expired rows. Assert on the org-scoped list instead of the absolute count.
        int pruned = await repo.PruneExpiredAsync();
        Assert.True(pruned >= 1, $"PruneExpiredAsync should have deleted at least 1 row; got {pruned}.");

        var remaining = await repo.ListAsync(orgId);
        Assert.DoesNotContain(remaining, r => r.Email == emailExpiring);
        Assert.Contains(remaining, r => r.Email == emailAccepted);  // accepted row kept
        Assert.Contains(remaining, r => r.Email == emailFresh);      // still-valid kept
    }

    // ── Cap enforcement via controller ───────────────────────────────────────

    [Fact]
    public async Task CreateInvite_ReturnsBadRequest_WhenPendingCapReached()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Seed pending invites up to the default cap (100) directly via the repo,
        // bypassing the controller so we don't trip rate-limits or duplicate-email
        // constraints. Use unique emails.
        var inviteRepo = new InviteRepository(b.Db, s.Clock);
        string orgId = b.PrimaryOrgId;
        string inviterId = b.ActorUserId!;
        for (int i = 0; i < 100; i++)
        {
            await inviteRepo.CreateAsync(orgId, $"cap-fill-{i}@x.test", inviterId);
        }

        // 101st invite via the controller must be rejected.
        var result = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest("overflow@x.test", "member"),
            CancellationToken.None);

        var bad = Assert.IsAssignableFrom<Microsoft.AspNetCore.Mvc.ObjectResult>(result);
        Assert.Equal(422, bad.StatusCode);  // ValidationErrorAction returns 422 (Unprocessable Entity)
    }

    [Fact]
    public async Task CreateInvite_Succeeds_AtOneBelowCap()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var inviteRepo = new InviteRepository(b.Db, s.Clock);
        string orgId = b.PrimaryOrgId;
        string inviterId = b.ActorUserId!;
        // Fill to cap-1 (99).
        for (int i = 0; i < 99; i++)
        {
            await inviteRepo.CreateAsync(orgId, $"pre-cap-{i}@x.test", inviterId);
        }

        // The 100th invite via the controller should succeed (count == 99 < cap == 100).
        var result = await b.OrgInvitesController.CreateInvite(
            new CreateInviteRequest("at-cap@x.test", "member"),
            CancellationToken.None);

        Assert.IsType<Microsoft.AspNetCore.Mvc.OkObjectResult>(result);
    }

    // ── Mixed/partial-failure: multiple concurrent-like calls, some succeed some fail ──

    [Fact]
    public async Task AcceptAsync_MultipleSequentialAccepts_ExactlyOneSucceeds()
    {
        // Simulates the check-then-act race: issue N sequential accept calls (in tests
        // we cannot race SQLite's serialized WAL, but this validates the single-winner
        // property in the happy path and every subsequent call returns null).
        var clock = TestTime.Frozen();
        var (orgId, inviterId) = await SeedOrgAndInviterAsync(Guid.NewGuid().ToString("N"));
        var repo = new InviteRepository(_fixture.Store, clock);

        var (raw, _) = await repo.CreateAsync(orgId, "race@x.test", inviterId);

        const int Attempts = 5;
        var results = new List<bool>();
        for (int i = 0; i < Attempts; i++)
        {
            var r = await repo.AcceptAsync(raw);
            results.Add(r is not null);
        }

        // Exactly one winner.
        Assert.Equal(1, results.Count(x => x));
        Assert.Equal(Attempts - 1, results.Count(x => !x));
    }

    [Fact]
    public async Task PruneAndCount_MixedRows_PartialEffect()
    {
        // Partial-failure scenario: prune affects only expired rows; pending and accepted
        // rows survive. CountPendingAsync reflects only the pending survivors.
        // Uses a unique org per run so CountPendingAsync is scoped and unaffected by other tests.
        string suffix = Guid.NewGuid().ToString("N");
        var clock = TestTime.Frozen();
        var (orgId, inviterId) = await SeedOrgAndInviterAsync(suffix);
        var repo = new InviteRepository(_fixture.Store, clock);

        string emailPending = $"mix-pending-{suffix}@x.test";
        string emailAccepted = $"mix-accepted-{suffix}@x.test";
        string emailValid = $"mix-valid-{suffix}@x.test";

        // Three rows: one pending (will expire), one accepted (will expire), one still-valid.
        var (_, _) = await repo.CreateAsync(orgId, emailPending, inviterId);
        var (rawAccepted, _) = await repo.CreateAsync(orgId, emailAccepted, inviterId);
        await repo.AcceptAsync(rawAccepted);

        clock.Advance(TimeSpan.FromHours(36)); // past 24h TTL

        // Create a still-valid invite at T+36h (expires at T+60h).
        await repo.CreateAsync(orgId, emailValid, inviterId);

        int pruned = await repo.PruneExpiredAsync();
        int pending = await repo.CountPendingAsync(orgId);

        // At least one unaccepted+expired row is pruned (this org contributed exactly 1).
        // The org-scoped pending count must be exactly 1 (mix-valid only) regardless of
        // other tests' data in the shared fixture.
        Assert.True(pruned >= 1, $"At least 1 expired invite should be pruned; got {pruned}.");
        Assert.Equal(1, pending);  // mix-valid still counts; mix-pending and mix-accepted gone

        // Verify the org-specific row state.
        var remaining = await repo.ListAsync(orgId);
        Assert.DoesNotContain(remaining, r => r.Email == emailPending);
        Assert.Contains(remaining, r => r.Email == emailAccepted);  // accepted rows kept
        Assert.Contains(remaining, r => r.Email == emailValid);      // still-valid kept
    }
}
