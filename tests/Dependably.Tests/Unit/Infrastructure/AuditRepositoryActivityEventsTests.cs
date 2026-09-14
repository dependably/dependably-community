using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Coverage for <see cref="AuditRepository.ListActivityEventsAsync"/>, the cursor-paged
/// allowlist read behind the SIEM activity feed. Three properties are load-bearing and none of
/// them is visible from the older <c>ListActivityAsync</c>: the <c>blocked*</c> family is matched
/// as a range (so an arm that ships tomorrow is in the feed with no allowlist edit), the org
/// filter is structural rather than optional, and paging is keyset-based so a feed being appended
/// to while it is read returns every row exactly once.
///
/// Rows are written through the real writer — <see cref="AuditRepository.LogActivityAsync"/> —
/// rather than by hand-rolled INSERTs, so the timestamp precision under test is the precision
/// production actually stores.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuditRepositoryActivityEventsTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = new(TestTime.KnownNow);
    private AuditRepository _audit = null!;
    private string _orgA = "";
    private string _orgB = "";

    private static readonly DateTimeOffset WindowStart = TestTime.KnownNow.AddHours(-1);
    private static readonly DateTimeOffset WindowEnd = TestTime.KnownNow.AddHours(1);

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgA = await OrgSeeder.InsertAsync(_db, "activity-org-a");
        _orgB = await OrgSeeder.InsertAsync(_db, "activity-org-b");
        _audit = new AuditRepository(_db, time: _clock);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private async Task WriteAsync(string orgId, string eventType, string purl)
    {
        await _audit.LogActivityAsync(
            orgId, "npm", purl, eventType,
            actorId: "tok-1", actorKind: ActorKinds.Service, sourceIp: "203.0.113.7");
        _clock.Advance(TimeSpan.FromMilliseconds(1));
    }

    [Fact]
    public async Task BlockedFamily_SelectsEveryBlockedArm_AndNothingElse()
    {
        // The range bound has to cover the bare 'blocked' value, every 'blocked_<gate>' arm
        // (including one this test invents, standing in for an arm that ships later), and stop
        // before the next event type alphabetically.
        //
        // 'blockedxyz' is the discriminator that makes this test see the bound at all: under
        // SQLite's byte ordering every underscored arm sorts below the mechanical successor
        // 'blocked' || char(96), so a wrong bound is invisible here — but 'x' (0x78) does not.
        // The provider-level pin is SiemActivityEventsPostgresTests, where a linguistic
        // collation drops the underscored arms too.
        await WriteAsync(_orgA, "blocked", "pkg:npm/a@1");
        await WriteAsync(_orgA, "blocked_license", "pkg:npm/b@1");
        await WriteAsync(_orgA, "blocked_vuln_score", "pkg:npm/c@1");
        await WriteAsync(_orgA, "blocked_some_future_gate", "pkg:npm/d@1");
        await WriteAsync(_orgA, "blockedxyz", "pkg:npm/h@1");
        await WriteAsync(_orgA, "download", "pkg:npm/e@1");
        await WriteAsync(_orgA, "first_fetch", "pkg:npm/f@1");
        await WriteAsync(_orgA, "push", "pkg:npm/g@1");

        var (items, _) = await _audit.ListActivityEventsAsync(
            WindowStart, WindowEnd, _orgA, includeBlockedFamily: true, eventTypes: [],
            limit: 100, afterCursor: null);

        Assert.Equal(
            new[]
            {
                "blocked", "blocked_license", "blocked_some_future_gate", "blocked_vuln_score",
                "blockedxyz",
            },
            items.Select(i => i.EventType).OrderBy(t => t, StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public async Task ExactEventTypes_SelectOnlyThoseValues()
    {
        await WriteAsync(_orgA, "blocked_license", "pkg:npm/a@1");
        await WriteAsync(_orgA, "blocked_malicious", "pkg:npm/b@1");
        await WriteAsync(_orgA, "download", "pkg:npm/c@1");

        var (items, _) = await _audit.ListActivityEventsAsync(
            WindowStart, WindowEnd, _orgA, includeBlockedFamily: false,
            eventTypes: ["blocked_license", "download"], limit: 100, afterCursor: null);

        Assert.Equal(
            new[] { "blocked_license", "download" },
            items.Select(i => i.EventType).OrderBy(t => t, StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public async Task OrgScope_NeverReturnsAnotherTenantsRows()
    {
        await WriteAsync(_orgA, "blocked_license", "pkg:npm/mine@1");
        await WriteAsync(_orgB, "blocked_license", "pkg:npm/theirs@1");

        var (items, _) = await _audit.ListActivityEventsAsync(
            WindowStart, WindowEnd, _orgA, includeBlockedFamily: true, eventTypes: [],
            limit: 100, afterCursor: null);

        Assert.Equal(new[] { "pkg:npm/mine@1" }, items.Select(i => i.Purl).ToArray());
        Assert.All(items, i => Assert.Equal(_orgA, i.OrgId));
    }

    [Fact]
    public async Task EmptyAllowlist_SelectsNothing()
    {
        await WriteAsync(_orgA, "blocked_license", "pkg:npm/a@1");
        await WriteAsync(_orgA, "download", "pkg:npm/b@1");

        var (items, nextCursor) = await _audit.ListActivityEventsAsync(
            WindowStart, WindowEnd, _orgA, includeBlockedFamily: false, eventTypes: [],
            limit: 100, afterCursor: null);

        Assert.Empty(items);
        Assert.Null(nextCursor);
    }

    [Fact]
    public async Task UntilBound_ExcludesRowsWrittenAfterIt()
    {
        // The lag cap the controller applies is expressed as this `until` bound, so the bound
        // itself has to exclude — not merely order after — a newer row.
        await WriteAsync(_orgA, "blocked_license", "pkg:npm/old@1");
        var cut = _clock.GetUtcNow();
        _clock.Advance(TimeSpan.FromSeconds(30));
        await WriteAsync(_orgA, "blocked_license", "pkg:npm/new@1");

        var (items, _) = await _audit.ListActivityEventsAsync(
            WindowStart, cut, _orgA, includeBlockedFamily: true, eventTypes: [],
            limit: 100, afterCursor: null);

        Assert.Equal(new[] { "pkg:npm/old@1" }, items.Select(i => i.Purl).ToArray());
    }

    [Fact]
    public async Task CursorPaging_ReturnsEveryRowExactlyOnce_WithNoGap()
    {
        const int rows = 25;
        const int limit = 7;
        var written = new List<string>();
        for (int i = 0; i < rows; i++)
        {
            string purl = $"pkg:npm/p{i}@1";
            written.Add(purl);
            await WriteAsync(_orgA, i % 2 == 0 ? "blocked_license" : "blocked_malicious", purl);
        }

        var seen = new List<string>();
        string? cursor = null;
        int pages = 0;
        const int maxPages = 10; // bounds a runaway loop if paging never terminates

        while (pages < maxPages)
        {
            var (items, nextCursor) = await _audit.ListActivityEventsAsync(
                WindowStart, WindowEnd, _orgA, includeBlockedFamily: true, eventTypes: [],
                limit: limit, afterCursor: cursor);
            pages++;
            seen.AddRange(items.Select(i => i.Purl));

            if (nextCursor is null)
            {
                break;
            }

            cursor = nextCursor;
        }

        Assert.True(pages < maxPages, "paging did not terminate within the page budget");
        Assert.Equal(rows, seen.Count);                    // no gap
        Assert.Equal(rows, seen.Distinct().Count());       // no duplicate
        Assert.Equal(written.OrderBy(p => p, StringComparer.Ordinal).ToArray(),
                     seen.OrderBy(p => p, StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public async Task CursorPaging_PagesNewestFirst()
    {
        await WriteAsync(_orgA, "blocked_license", "pkg:npm/first@1");
        await WriteAsync(_orgA, "blocked_license", "pkg:npm/second@1");
        await WriteAsync(_orgA, "blocked_license", "pkg:npm/third@1");

        var (page, nextCursor) = await _audit.ListActivityEventsAsync(
            WindowStart, WindowEnd, _orgA, includeBlockedFamily: true, eventTypes: [],
            limit: 2, afterCursor: null);

        Assert.Equal(new[] { "pkg:npm/third@1", "pkg:npm/second@1" }, page.Select(i => i.Purl).ToArray());
        Assert.NotNull(nextCursor);

        var (tail, tailCursor) = await _audit.ListActivityEventsAsync(
            WindowStart, WindowEnd, _orgA, includeBlockedFamily: true, eventTypes: [],
            limit: 2, afterCursor: nextCursor);

        Assert.Equal(new[] { "pkg:npm/first@1" }, tail.Select(i => i.Purl).ToArray());
        Assert.Null(tailCursor);
    }

    [Fact]
    public async Task SubSecondRows_AreNotDroppedByTheWindowBounds()
    {
        // created_at is millisecond text; a second-precision bound compares '.' (0x2E) against
        // 'Z' (0x5A) and silently drops the row that landed mid-second.
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 6, 15, 12, 0, 0, 500, TimeSpan.Zero));
        var audit = new AuditRepository(_db, time: clock);
        await audit.LogActivityAsync(_orgA, "npm", "pkg:npm/mid@1", "blocked_license", sourceIp: "203.0.113.7");

        var (items, _) = await audit.ListActivityEventsAsync(
            new DateTimeOffset(2026, 6, 15, 12, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 6, 15, 12, 0, 1, TimeSpan.Zero),
            _orgA, includeBlockedFamily: true, eventTypes: [], limit: 100, afterCursor: null);

        Assert.Single(items);
        Assert.Equal("pkg:npm/mid@1", items[0].Purl);
    }
}
