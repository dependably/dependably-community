using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Regression coverage for <see cref="AuditRepository.ListAuthEventsAsync"/>: the SIEM auth-event
/// pagination cursor and window bounds must compare at the same millisecond precision
/// <c>audit_log.created_at</c> is actually written at (<see cref="AuditRepository.LogAsync"/>'s
/// <c>NowMs()</c>) — a second-precision bound or cursor silently drops/duplicates rows because
/// <c>'.'</c> (0x2E) sorts before <c>'Z'</c> (0x5A) in the stored TEXT.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuditRepositoryAuthEventsTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task Pagination_MoreThanLimitEventsInOneWallClockSecond_PagesAdvanceWithoutDuplicates()
    {
        // Five login events, 100ms apart, all inside the wall-clock second 12:00:00 — exactly
        // the "many events land in the same second" scenario the second-precision cursor bug
        // could never page past on current main.
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 6, 15, 12, 0, 0, 0, TimeSpan.Zero));
        var audit = new AuditRepository(_db, time: clock);
        var seededIds = new List<string>();
        for (int i = 0; i < 5; i++)
        {
            await audit.LogAsync("login.success", orgId: "o1", actorId: $"user{i}");
            seededIds.Add(await LastInsertedIdAsync());
            clock.Advance(TimeSpan.FromMilliseconds(100));
        }

        var since = new DateTimeOffset(2026, 6, 15, 11, 59, 0, TimeSpan.Zero);
        var until = new DateTimeOffset(2026, 6, 15, 12, 1, 0, TimeSpan.Zero);

        var seenIds = new HashSet<string>();
        string? cursor = null;
        int pages = 0;
        const int limit = 2;
        const int maxPages = 10; // bounds a runaway loop if pagination never terminates

        while (pages < maxPages)
        {
            var (items, nextCursor) = await audit.ListAuthEventsAsync(
                since, until, orgId: null, actionFilter: null, limit: limit, afterCursor: cursor);
            pages++;

            foreach (var item in items)
            {
                // A row reappearing on a later page is exactly the stuck-cursor symptom: the
                // predicate re-matched every row in the cursor's own second, including rows
                // already returned.
                Assert.True(seenIds.Add(item.Id), $"row {item.Id} was returned on more than one page");
            }

            if (nextCursor is null)
            {
                break;
            }

            cursor = nextCursor;
        }

        Assert.True(pages < maxPages, "pagination did not terminate within the page budget");
        Assert.Equal(5, seenIds.Count);
        Assert.Equal(seededIds.ToHashSet(), seenIds);
    }

    [Fact]
    public async Task Since_AtWholeSecondBoundary_IncludesSubSecondEventInSameSecond()
    {
        var audit = new AuditRepository(_db, time: new FakeTimeProvider(
            new DateTimeOffset(2026, 6, 15, 12, 0, 0, 500, TimeSpan.Zero)));
        await audit.LogAsync("login.success", orgId: "o1", actorId: "user-a");

        // since == the whole second the event's millisecond component falls inside; a
        // second-precision-formatted `since` fails `created_at >= @since` for this row because
        // "12:00:00.500Z" sorts before "12:00:00Z" byte-for-byte ('.' < 'Z').
        var since = new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.Zero);
        var until = new DateTimeOffset(2026, 6, 15, 12, 0, 1, TimeSpan.Zero);

        var (items, _) = await audit.ListAuthEventsAsync(
            since, until, orgId: null, actionFilter: null, limit: 100, afterCursor: null);

        Assert.Single(items);
        Assert.Equal("user-a", items[0].ActorId);
    }

    [Fact]
    public async Task Until_AtWholeSecondBoundary_ExcludesEventOneSecondLater()
    {
        // The over-inclusion mirror of the `since` case: a second-precision-formatted `until`
        // makes "12:00:01.500Z" <= "12:00:01Z" evaluate true ('.' sorts before 'Z'), so an event
        // a full second after `until`'s whole-second value was wrongly included.
        var audit = new AuditRepository(_db, time: new FakeTimeProvider(
            new DateTimeOffset(2026, 6, 15, 12, 0, 1, 500, TimeSpan.Zero)));
        await audit.LogAsync("login.success", orgId: "o1", actorId: "user-b");

        var since = new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.Zero);
        var until = new DateTimeOffset(2026, 6, 15, 12, 0, 1, TimeSpan.Zero);

        var (items, _) = await audit.ListAuthEventsAsync(
            since, until, orgId: null, actionFilter: null, limit: 100, afterCursor: null);

        Assert.Empty(items);
    }

    [Fact]
    public async Task MalformedCursorTimestamp_TreatedAsNoCursor_ReturnsFirstPageIdenticalToNullCursor()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 6, 15, 12, 0, 0, 0, TimeSpan.Zero));
        var audit = new AuditRepository(_db, time: clock);
        for (int i = 0; i < 3; i++)
        {
            await audit.LogAsync("login.success", orgId: "o1", actorId: $"user{i}");
            clock.Advance(TimeSpan.FromSeconds(1));
        }

        var since = new DateTimeOffset(2026, 6, 15, 11, 59, 0, TimeSpan.Zero);
        var until = new DateTimeOffset(2026, 6, 15, 12, 5, 0, TimeSpan.Zero);

        var (withoutCursor, _) = await audit.ListAuthEventsAsync(
            since, until, orgId: null, actionFilter: null, limit: 100, afterCursor: null);

        // A cursor whose timestamp half is second-precision (not the canonical millisecond
        // shape audit_log.created_at is written at) must be rejected outright rather than bound
        // as-is into the SQL comparison.
        string wrongPrecisionCursor = Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes($"2026-06-15T12:00:01Z|{withoutCursor[0].Id}"));

        var (withMalformedCursor, _) = await audit.ListAuthEventsAsync(
            since, until, orgId: null, actionFilter: null, limit: 100, afterCursor: wrongPrecisionCursor);

        Assert.Equal(
            withoutCursor.Select(i => i.Id).ToArray(),
            withMalformedCursor.Select(i => i.Id).ToArray());
    }

    [Fact]
    public async Task NonBase64Cursor_TreatedAsNoCursor_ReturnsFirstPage()
    {
        var audit = new AuditRepository(_db, time: new FakeTimeProvider(TestTime.KnownNow));
        await audit.LogAsync("login.success", orgId: "o1", actorId: "user-a");

        var (items, _) = await audit.ListAuthEventsAsync(
            TestTime.KnownNow.AddMinutes(-1), TestTime.KnownNow.AddMinutes(1),
            orgId: null, actionFilter: null, limit: 100, afterCursor: "!!!not-base64!!!");

        Assert.Single(items);
    }

    private async Task<string> LastInsertedIdAsync()
    {
        await using var conn = await _db.OpenAsync();
        return (await Dapper.SqlMapper.ExecuteScalarAsync<string>(
            conn, "SELECT id FROM audit_log ORDER BY created_at DESC LIMIT 1"))!;
    }
}
