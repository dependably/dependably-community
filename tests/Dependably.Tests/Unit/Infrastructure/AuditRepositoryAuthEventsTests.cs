using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
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
            var (items, nextCursor, _, _, _) = await audit.ListAuthEventsAsync(
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

        var (items, _, _, _, _) = await audit.ListAuthEventsAsync(
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

        var (items, _, _, _, _) = await audit.ListAuthEventsAsync(
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

        var (withoutCursor, _, _, _, _) = await audit.ListAuthEventsAsync(
            since, until, orgId: null, actionFilter: null, limit: 100, afterCursor: null);

        // A cursor whose timestamp half is second-precision (not the canonical millisecond
        // shape audit_log.created_at is written at) must be rejected outright rather than bound
        // as-is into the SQL comparison.
        string wrongPrecisionCursor = Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes($"2026-06-15T12:00:01Z|{withoutCursor[0].Id}"));

        var (withMalformedCursor, _, _, _, _) = await audit.ListAuthEventsAsync(
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

        var (items, _, _, _, _) = await audit.ListAuthEventsAsync(
            TestTime.KnownNow.AddMinutes(-1), TestTime.KnownNow.AddMinutes(1),
            orgId: null, actionFilter: null, limit: 100, afterCursor: "!!!not-base64!!!");

        Assert.Single(items);
    }

    [Fact]
    public async Task ActionPrefixes_OverlappingPlusOneThatMatchesNothing_ReturnEachMatchingRowOnce()
    {
        // The prefix filter is a disjunction of bound LIKE patterns, so the property the previous
        // EXISTS-over-an-unfold gave for free has to be asserted: a row matched by two prefixes
        // ("login" and "login.mfa" both cover login.mfa.challenge) comes back exactly once, a
        // prefix matching nothing contributes nothing, and a prefix is a family rather than a
        // substring — "logins.…" is not swept in by "login".
        var clock = new FakeTimeProvider(TestTime.KnownNow);
        var audit = new AuditRepository(_db, time: clock);
        foreach (string action in new[]
                 {
                     "login.success", "login.mfa.challenge", "token.created",
                     "package.published", "logins.not_a_family",
                 })
        {
            await audit.LogAsync(action, orgId: "o1", actorId: "u1");
            clock.Advance(TimeSpan.FromMilliseconds(1));
        }

        var (items, _, _, _, _) = await audit.ListAuthEventsAsync(
            TestTime.KnownNow.AddMinutes(-1), TestTime.KnownNow.AddMinutes(1),
            orgId: null, actionFilter: ["login", "login.mfa", "token", "nosuchfamily"],
            limit: 100, afterCursor: null);

        Assert.Equal(
            new[] { "login.mfa.challenge", "login.success", "token.created" },
            items.Select(i => i.Action).OrderBy(a => a, StringComparer.Ordinal).ToArray());
        Assert.Equal(items.Count, items.Select(i => i.Id).Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public async Task ActionFilters_AtTheTotalCap_AreAcceptedAndTheFamilyCapRefusesBeyondIt()
    {
        // The two caps compose: every declared action plus a full complement of families is the
        // most a caller can send, and it is exactly the total cap, so the total cap is reached
        // rather than crossed. What refuses the next value is the family cap — only declared
        // actions are free and there are only so many of those, so any longer list necessarily
        // carries more non-declared values than the family bound allows.
        var audit = new AuditRepository(_db, time: new FakeTimeProvider(TestTime.KnownNow));
        await audit.LogAsync("checksum_failure", orgId: "o1", actorId: "u1");

        string[] families = [.. AuditActions.ImpliedFamilyPrefixes];
        string[] atTheCap = [.. AuditActions.All, .. families];
        Assert.Equal(AuditRepository.MaxAuthEventActionFilters, atTheCap.Length);
        Assert.Equal(AuditRepository.MaxAuthEventFamilyFilters, families.Length);

        var (items, _, _, _, _) = await audit.ListAuthEventsAsync(
            TestTime.KnownNow.AddMinutes(-1), TestTime.KnownNow.AddMinutes(1),
            orgId: null, actionFilter: atTheCap, limit: 100, afterCursor: null);
        Assert.Equal("checksum_failure", Assert.Single(items).Action);

        // One value past it, and the request is invalid input rather than a query handed to the
        // driver to fail on against its bind-parameter ceiling.
        string[] oneMore = [.. atTheCap, "zzz_one_past_the_composition"];
        var ex = await Assert.ThrowsAsync<ArgumentException>(() => audit.ListAuthEventsAsync(
            TestTime.KnownNow.AddMinutes(-1), TestTime.KnownNow.AddMinutes(1),
            orgId: null, actionFilter: oneMore, limit: 100, afterCursor: null));
        Assert.Equal("actionFilter", ex.ParamName);
    }

    [Fact]
    public async Task ActionFilters_PastTheFamilyCap_AreRejectedEvenWellUnderTheTotalCap()
    {
        var audit = new AuditRepository(_db, time: new FakeTimeProvider(TestTime.KnownNow));

        // Each of these needs its own unindexable LIKE, evaluated against every candidate row of
        // the window and never short-circuiting because none of them match. That is the cost the
        // family cap bounds, and it bites long before the total cap does.
        string[] filters = [.. Enumerable
            .Range(0, AuditRepository.MaxAuthEventFamilyFilters + 1)
            .Select(i => $"family{i}")];
        Assert.True(filters.Length <= AuditRepository.MaxAuthEventActionFilters,
            "this list must stay under the total cap so the family cap is what rejects it");

        var ex = await Assert.ThrowsAsync<ArgumentException>(() => audit.ListAuthEventsAsync(
            TestTime.KnownNow.AddMinutes(-1), TestTime.KnownNow.AddMinutes(1),
            orgId: null, actionFilter: filters, limit: 100, afterCursor: null));
        Assert.Equal("actionFilter", ex.ParamName);
    }

    [Fact]
    public async Task EveryDeclaredActionNamedExplicitly_IsAcceptedAndServed()
    {
        // The collector this exists for pins the action set it understands rather than inheriting
        // a default that can widen under it on the next upgrade. Naming all 138 declared actions
        // costs 138 entries in an IN list and not one LIKE term, so there is no reason to refuse
        // it — and a cap chosen for the family half would have made the server's own published
        // default set unsendable.
        var audit = new AuditRepository(_db, time: new FakeTimeProvider(TestTime.KnownNow));
        await audit.LogAsync("checksum_failure", orgId: "o1", actorId: "u1");

        string[] filters = [.. AuditActions.All];
        Assert.Equal(0, filters.Count(f => !AuditActions.IsDeclaredLeaf(f)));

        var (items, _, _, _, _) = await audit.ListAuthEventsAsync(
            TestTime.KnownNow.AddMinutes(-1), TestTime.KnownNow.AddMinutes(1),
            orgId: null, actionFilter: filters, limit: 100, afterCursor: null);

        Assert.Equal("checksum_failure", Assert.Single(items).Action);
    }

    [Fact]
    public async Task DeclaredLeafFilter_ServesTheNameAndNotAnUndeclaredActionUnderIt()
    {
        // A declared action has nothing declared under it, so its family LIKE term is omitted
        // entirely. The observable consequence is here: a stray undeclared `checksum_failure.x`
        // row is NOT swept in by action=checksum_failure. Emit the term unconditionally instead
        // and the assertion below sees two rows.
        var clock = new FakeTimeProvider(TestTime.KnownNow);
        var audit = new AuditRepository(_db, time: clock);
        foreach (string action in new[] { "checksum_failure", "checksum_failure.extra" })
        {
            await audit.LogAsync(action, orgId: "o1", actorId: "u1");
            clock.Advance(TimeSpan.FromMilliseconds(1));
        }

        var (items, _, _, matched, _) = await audit.ListAuthEventsAsync(
            TestTime.KnownNow.AddMinutes(-1), TestTime.KnownNow.AddMinutes(2),
            orgId: null, actionFilter: ["checksum_failure"], limit: 100, afterCursor: null);

        Assert.Equal("checksum_failure", Assert.Single(items).Action);
        // The matched total is built from the same predicate, so it must agree rather than
        // counting rows the page does not return.
        Assert.Equal(1, matched);
    }

    [Fact]
    public async Task FamilyAndUndeclaredFilters_StillCarryTheirFamilyTerm()
    {
        // The other half of the elision: skipping the LIKE for declared leaves must not skip it
        // for a value that is genuinely a family root (`auth`, which the vocabulary implies but
        // never declares) or for a name this release does not declare at all — a collector
        // filtering on an action from a newer build still has to match its family.
        var clock = new FakeTimeProvider(TestTime.KnownNow);
        var audit = new AuditRepository(_db, time: clock);
        foreach (string action in new[]
                 {
                     "auth.saml.login.failure", "zzz_future.event", "package.publish",
                 })
        {
            await audit.LogAsync(action, orgId: "o1", actorId: "u1");
            clock.Advance(TimeSpan.FromMilliseconds(1));
        }

        Assert.Contains("auth", AuditActions.ImpliedFamilyPrefixes);
        Assert.False(AuditActions.IsDeclaredLeaf("auth"));
        Assert.False(AuditActions.IsDeclaredLeaf("zzz_future"));

        var (items, _, _, _, _) = await audit.ListAuthEventsAsync(
            TestTime.KnownNow.AddMinutes(-1), TestTime.KnownNow.AddMinutes(2),
            orgId: null, actionFilter: ["auth", "zzz_future"], limit: 100, afterCursor: null);

        Assert.Equal(
            new[] { "auth.saml.login.failure", "zzz_future.event" },
            items.Select(i => i.Action).OrderBy(a => a, StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public async Task ActionPrefixes_RepeatedIdentically_AreFoldedAndStillMatch()
    {
        var audit = new AuditRepository(_db, time: new FakeTimeProvider(TestTime.KnownNow));
        await audit.LogAsync("login.success", orgId: "o1", actorId: "u1");

        string[] prefixes = [.. Enumerable.Repeat("login", AuditRepository.MaxAuthEventActionFilters + 50)];

        var (items, _, _, _, _) = await audit.ListAuthEventsAsync(
            TestTime.KnownNow.AddMinutes(-1), TestTime.KnownNow.AddMinutes(1),
            orgId: null, actionFilter: prefixes, limit: 100, afterCursor: null);

        Assert.Single(items);
    }

    /// <summary>
    /// A collector polling with no <c>action=</c> filter must see a <c>ratelimit.rejected</c> row
    /// on the default action set — otherwise a caller relying on the documented defaults never
    /// observes rate-limit denials at all, silently, since an absent filter reads as "give me
    /// everything security-relevant" rather than "give me a curated subset that forgot one
    /// family". This is the property the default-set entry exists to pin, not just its presence
    /// as a string in the array.
    /// </summary>
    [Fact]
    public async Task DefaultActionFilter_IncludesRateLimitRejectedEvents()
    {
        var audit = new AuditRepository(_db, time: new FakeTimeProvider(TestTime.KnownNow));
        await audit.LogAsync(
            "ratelimit.rejected", orgId: "o1", ecosystem: "npm", detail: "{\"count\":3}");

        var (items, _, _, _, _) = await audit.ListAuthEventsAsync(
            TestTime.KnownNow.AddMinutes(-1), TestTime.KnownNow.AddMinutes(1),
            orgId: null, actionFilter: null, limit: 100, afterCursor: null);

        Assert.Contains(items, i => i.Action == "ratelimit.rejected");
    }

    private async Task<string> LastInsertedIdAsync()
    {
        await using var conn = await _db.OpenAsync();
        return (await Dapper.SqlMapper.ExecuteScalarAsync<string>(
            conn, "SELECT id FROM audit_log ORDER BY created_at DESC LIMIT 1"))!;
    }
}
