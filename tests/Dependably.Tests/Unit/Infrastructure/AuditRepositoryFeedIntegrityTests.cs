using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Regression coverage for the <c>latest_event_at</c>/<c>matched</c>/<c>matched_capped</c>
/// feed-integrity fields on <see cref="AuditRepository.ListAuthEventsAsync"/>. Without these,
/// "the registry is quiet", "the audit writer is broken", and "my action filter matches nothing"
/// are all indistinguishable — every one of them returns an empty <c>items</c> page.
/// <c>LatestEventAt</c> answers that by deliberately ignoring the action filter (and the
/// <c>since</c> lower bound) so it reports the most recent row visible to the caller at all, not
/// the most recent row that happened to match; <c>Matched</c> is the total filtered-window row
/// count, independent of page size, probed and capped exactly like <see cref="AuditRepository.ListAuditAsync"/>'s
/// total rather than an uncapped <c>COUNT(*)</c>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuditRepositoryFeedIntegrityTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    /// <summary>
    /// Bulk-inserts <paramref name="count"/> matching rows in one statement — mirrors
    /// <c>AuditListTotalCapTests</c>'s seeding shape, since one-by-one <c>LogAsync</c> calls at
    /// <see cref="AuditRepository.ListTotalCap"/> scale would make the cap test itself the
    /// slowest thing in the suite. Timestamps step by one second (millisecond-precision text,
    /// matching <see cref="AuditRepository"/>'s real writer) so ordering stays deterministic.
    /// </summary>
    private async Task SeedLoginRowsAsync(int count, string orgId = "o1")
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO audit_log (id, scope, org_id, action, created_at)
            WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < @count)
            SELECT 'cap' || n, 'tenant', @orgId, 'login.success',
                   strftime('%Y-%m-%dT%H:%M:%f', 1700000000 + n, 'unixepoch') || 'Z'
            FROM seq
            """,
            new { count, orgId });
    }

    [Fact]
    public async Task LatestEventAt_IgnoresActionFilter_ReflectsMostRecentRowRegardlessOfMatch()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.Zero));
        var audit = new AuditRepository(_db, time: clock);

        await audit.LogAsync("login.success", orgId: "o1", actorId: "user-a");
        clock.Advance(TimeSpan.FromMinutes(9));
        // Deliberately does NOT match the "login" filter below — this is the row a
        // filter-blind collector would otherwise never learn about.
        await audit.LogAsync("lockout.triggered", orgId: "o1", actorId: "user-a");
        var lockoutAt = clock.GetUtcNow();

        var (items, _, latestEventAt, matched, matchedCapped) = await audit.ListAuthEventsAsync(
            since: clock.GetUtcNow().AddMinutes(-20),
            until: clock.GetUtcNow().AddMinutes(1),
            orgId: "o1",
            actionFilter: new[] { "login" },
            limit: 50,
            afterCursor: null);

        Assert.Single(items);
        Assert.Equal("login.success", items[0].Action);
        Assert.Equal(1, matched);
        Assert.False(matchedCapped);
        // The lockout row is excluded from `items` by the action filter, but its instant still
        // surfaces on LatestEventAt — proving the field is not merely "latest of the returned page".
        Assert.Equal(lockoutAt, latestEventAt);
    }

    [Fact]
    public async Task LatestEventAt_RespectsUntilUpperBound_ButIgnoresSinceLowerBound()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.Zero));
        var audit = new AuditRepository(_db, time: clock);

        // Well before the caller's requested `since` — must still count toward LatestEventAt,
        // because "nothing happened inside my window" and "the writer is broken" must not
        // collapse into the same empty-items response.
        await audit.LogAsync("login.success", orgId: "o1", actorId: "old-row");
        var oldRowAt = clock.GetUtcNow();

        clock.Advance(TimeSpan.FromHours(2));
        // After the caller's requested `until` — must be excluded from LatestEventAt, or a
        // collector polling a bounded window would see events from its own future.
        await audit.LogAsync("login.success", orgId: "o1", actorId: "future-row");

        var since = oldRowAt.AddMinutes(30);
        var until = oldRowAt.AddMinutes(45);

        var (items, _, latestEventAt, matched, matchedCapped) = await audit.ListAuthEventsAsync(
            since: since,
            until: until,
            orgId: "o1",
            actionFilter: null,
            limit: 50,
            afterCursor: null);

        Assert.Empty(items); // neither row falls inside [since, until]
        Assert.Equal(0, matched);
        Assert.False(matchedCapped);
        Assert.Equal(oldRowAt, latestEventAt);
    }

    [Fact]
    public async Task Matched_ReflectsTotalFilteredCount_IndependentOfPageLimit()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.Zero));
        var audit = new AuditRepository(_db, time: clock);

        for (int i = 0; i < 5; i++)
        {
            await audit.LogAsync("login.success", orgId: "o1", actorId: $"user{i}");
            clock.Advance(TimeSpan.FromMinutes(1));
        }

        var (items, nextCursor, _, matched, matchedCapped) = await audit.ListAuthEventsAsync(
            since: clock.GetUtcNow().AddMinutes(-10),
            until: clock.GetUtcNow().AddMinutes(1),
            orgId: "o1",
            actionFilter: null,
            limit: 2,
            afterCursor: null);

        Assert.Equal(2, items.Count);
        Assert.NotNull(nextCursor);
        Assert.Equal(5, matched);
        Assert.False(matchedCapped);
    }

    /// <summary>
    /// <c>Matched</c> re-runs the unindexable <c>json_each ... LIKE</c> filter across the whole
    /// window, so it is probed and capped exactly like <see cref="AuditRepository.ListAuditAsync"/>'s
    /// total — never an uncapped <c>COUNT(*)</c> that would scan a wide-window, unscoped
    /// (platform-admin) query to completion.
    /// </summary>
    [Fact]
    public async Task Matched_PastTheCap_IsCappedAndFlagged_ButItemsStayPageable()
    {
        await SeedLoginRowsAsync(AuditRepository.ListTotalCap + 5);
        var audit = new AuditRepository(_db);

        var (items, _, _, matched, matchedCapped) = await audit.ListAuthEventsAsync(
            since: DateTimeOffset.UnixEpoch,
            until: DateTimeOffset.UnixEpoch.AddYears(100),
            orgId: "o1",
            actionFilter: new[] { "login" },
            limit: 50,
            afterCursor: null);

        Assert.Equal(AuditRepository.ListTotalCap, matched);
        Assert.True(matchedCapped);
        // The cap bounds only the reported count — the page itself is unaffected.
        Assert.Equal(50, items.Count);
    }

    /// <summary>
    /// Adversarial pair for the isolation property: a caller pinned to org "o1" must never see
    /// org "o2"'s later event reflected in <c>LatestEventAt</c>, even though o2's row is
    /// unambiguously the most recent row in the table overall.
    /// </summary>
    [Fact]
    public async Task LatestEventAt_TenantScoped_DoesNotLeakAnotherOrgsLaterEvent()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.Zero));
        var audit = new AuditRepository(_db, time: clock);

        await audit.LogAsync("login.success", orgId: "o1", actorId: "o1-user");
        var o1LatestAt = clock.GetUtcNow();

        clock.Advance(TimeSpan.FromMinutes(30));
        // A different org's row, strictly later than o1's — the table-wide MAX(created_at).
        await audit.LogAsync("login.success", orgId: "o2", actorId: "o2-user");

        var (_, _, latestEventAt, _, _) = await audit.ListAuthEventsAsync(
            since: DateTimeOffset.UnixEpoch,
            until: clock.GetUtcNow().AddMinutes(1),
            orgId: "o1",
            actionFilter: null,
            limit: 50,
            afterCursor: null);

        Assert.Equal(o1LatestAt, latestEventAt);
    }

    /// <summary>
    /// Positive counterpart to the isolation test above: an unscoped (platform-admin, orgId
    /// null) read is *supposed* to see across tenants, so LatestEventAt must reflect the
    /// table-wide max in that case — proving the o1 scoping above is a deliberate filter, not an
    /// accidental narrowing that happens to hide o2 for every caller.
    /// </summary>
    [Fact]
    public async Task LatestEventAt_UnscopedOrgId_SeesAcrossTenants()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.Zero));
        var audit = new AuditRepository(_db, time: clock);

        await audit.LogAsync("login.success", orgId: "o1", actorId: "o1-user");

        clock.Advance(TimeSpan.FromMinutes(30));
        await audit.LogAsync("login.success", orgId: "o2", actorId: "o2-user");
        var o2LatestAt = clock.GetUtcNow();

        var (_, _, latestEventAt, _, _) = await audit.ListAuthEventsAsync(
            since: DateTimeOffset.UnixEpoch,
            until: clock.GetUtcNow().AddMinutes(1),
            orgId: null,
            actionFilter: null,
            limit: 50,
            afterCursor: null);

        Assert.Equal(o2LatestAt, latestEventAt);
    }

    /// <summary>
    /// Mutant guard for the "deliberately no <c>scope</c> filter" design claim on the doc
    /// comment: every other test in this file seeds only <c>scope='tenant'</c> rows, so a
    /// mutant that adds <c>AND scope = 'tenant'</c> to the tenant-scoped SQL body would leave
    /// them all green. Seeding a <c>scope='system'</c> row carrying the caller's own
    /// <c>org_id</c> (the shape <see cref="AuditRepository.LogSystemAsync"/> writes) and
    /// asserting <c>LatestEventAt</c> reflects it is what pins the claim.
    /// </summary>
    [Fact]
    public async Task LatestEventAt_IncludesSystemScopeRowsCarryingCallersOrgId_NoImplicitScopeFilter()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.Zero));
        var audit = new AuditRepository(_db, time: clock);

        await audit.LogAsync("login.success", orgId: "o1", actorId: "user-a");

        clock.Advance(TimeSpan.FromMinutes(5));
        // scope='system' row carrying the caller's own org_id. If a `scope = 'tenant'` filter
        // were added to the tenant-scoped SQL body, this row would be invisible to LatestEventAt
        // and the field would fall back to the older tenant row above instead.
        await audit.LogSystemAsync("system_admin.impersonated", orgId: "o1", actorId: "admin-1");
        var systemRowAt = clock.GetUtcNow();

        var (_, _, latestEventAt, _, _) = await audit.ListAuthEventsAsync(
            since: DateTimeOffset.UnixEpoch,
            until: clock.GetUtcNow().AddMinutes(1),
            orgId: "o1",
            actionFilter: null,
            limit: 50,
            afterCursor: null);

        Assert.Equal(systemRowAt, latestEventAt);
    }

    /// <summary>
    /// Boundary case for the cap's own comparison: a count sitting at exactly
    /// <see cref="AuditRepository.ListTotalCap"/> must NOT be flagged. Paired with
    /// <see cref="Matched_OneRowPastTheCap_IsFlagged"/> so an off-by-one (<c>&gt;=</c> instead of
    /// <c>&gt;</c>) in the cap comparison fails one of the two rather than staying green either way.
    /// </summary>
    [Fact]
    public async Task Matched_AtExactlyTheCap_IsNotFlagged()
    {
        await SeedLoginRowsAsync(AuditRepository.ListTotalCap);
        var audit = new AuditRepository(_db);

        var (_, _, _, matched, matchedCapped) = await audit.ListAuthEventsAsync(
            since: DateTimeOffset.UnixEpoch,
            until: DateTimeOffset.UnixEpoch.AddYears(100),
            orgId: "o1",
            actionFilter: new[] { "login" },
            limit: 50,
            afterCursor: null);

        Assert.Equal(AuditRepository.ListTotalCap, matched);
        Assert.False(matchedCapped);
    }

    /// <summary>Boundary counterpart: one row past the cap must flip <c>MatchedCapped</c>.</summary>
    [Fact]
    public async Task Matched_OneRowPastTheCap_IsFlagged()
    {
        await SeedLoginRowsAsync(AuditRepository.ListTotalCap + 1);
        var audit = new AuditRepository(_db);

        var (_, _, _, matched, matchedCapped) = await audit.ListAuthEventsAsync(
            since: DateTimeOffset.UnixEpoch,
            until: DateTimeOffset.UnixEpoch.AddYears(100),
            orgId: "o1",
            actionFilter: new[] { "login" },
            limit: 50,
            afterCursor: null);

        Assert.Equal(AuditRepository.ListTotalCap, matched);
        Assert.True(matchedCapped);
    }

    [Fact]
    public async Task LatestEventAt_NoRowsAtAll_IsNull()
    {
        var audit = new AuditRepository(_db, time: new FakeTimeProvider(TestTime.KnownNow));

        var (items, _, latestEventAt, matched, matchedCapped) = await audit.ListAuthEventsAsync(
            since: TestTime.KnownNow.AddDays(-1),
            until: TestTime.KnownNow,
            orgId: "o1",
            actionFilter: null,
            limit: 50,
            afterCursor: null);

        Assert.Empty(items);
        Assert.Equal(0, matched);
        Assert.False(matchedCapped);
        Assert.Null(latestEventAt);
    }
}
