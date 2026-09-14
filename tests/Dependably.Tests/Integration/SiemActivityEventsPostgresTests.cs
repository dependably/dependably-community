using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Integration;

/// <summary>
/// Live-Postgres coverage for <see cref="AuditRepository.ListActivityEventsAsync"/> — the one
/// place in this change whose correctness is a property of the <em>provider</em>, not of the SQL.
///
/// <para>
/// The <c>blocked*</c> family is matched as a half-open range, and the exclusive upper bound is
/// <c>'blockee'</c> rather than the mechanical successor <c>'blocked' || chr(96)</c> ('`'). Under
/// the byte ordering SQLite uses, both bounds behave identically — <c>'_'</c> (0x5F) sorts below
/// <c>'`'</c> (0x60) — so the whole unit suite is blind to the difference. Under a libc/ICU
/// collation (a Postgres cluster initialized <c>en_US.utf8</c>, which is the default nearly
/// everywhere) punctuation is weighted below letters, so <c>'blocked`'</c> collates at or under
/// <c>'blocked_license'</c> and the backtick bound returns the bare <c>blocked</c> row alone,
/// silently dropping every gate arm. That is a feed that reports nothing wrong while carrying
/// almost no refusals — exactly the failure the SIEM surface exists to make impossible.
/// </para>
///
/// <para>
/// This test is therefore the pin on that constant: it must go red if
/// <see cref="AuditRepository.BlockedFamilyUpperBound"/> is changed back to the backtick form. It
/// is also the live-Postgres pin on the query's <c>IN</c> list, which is built by
/// <c>DapperInClause.Expand</c> because Dapper's own <c>IN @list</c> expansion binds a native
/// array on an Npgsql connection and is a syntax error after <c>IN</c>.
/// </para>
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class SiemActivityEventsPostgresTests
{
    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    private const string OrgId = "o1";
    private const string OtherOrgId = "o2";

    private static readonly DateTimeOffset WindowStart = TestTime.KnownNow.AddHours(-1);
    private static readonly DateTimeOffset WindowEnd = TestTime.KnownNow.AddHours(1);

    [Fact]
    public async Task BlockedFamilyRange_OnLivePostgres_ReturnsEveryArm_NotJustTheBareValue()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        await SeedOrgsAsync(pg.Store);

        var clock = new FakeTimeProvider(TestTime.KnownNow);
        var audit = new AuditRepository(pg.Store, time: clock);

        // The arms are the real event-type spellings a block gate writes, plus one with no
        // underscore at all — the family is a prefix, and the range bound has to hold for both
        // shapes under whatever collation the cluster was initialized with.
        foreach (string eventType in new[]
                 {
                     "blocked", "blocked_kev", "blocked_license", "blocked_malicious_live",
                     "blockedxyz", "download", "push",
                 })
        {
            await audit.LogActivityAsync(
                OrgId, "npm", $"pkg:npm/{eventType}@1", eventType,
                actorId: "tok-1", actorKind: ActorKinds.Service, sourceIp: "203.0.113.7");
            clock.Advance(TimeSpan.FromMilliseconds(1));
        }

        var (items, _) = await audit.ListActivityEventsAsync(
            WindowStart, WindowEnd, OrgId, includeBlockedFamily: true, eventTypes: [],
            limit: 100, afterCursor: null);

        Assert.Equal(
            new[] { "blocked", "blocked_kev", "blocked_license", "blocked_malicious_live", "blockedxyz" },
            items.Select(i => i.EventType).OrderBy(t => t, StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public async Task ExactEventTypeList_OnLivePostgres_BindsAsAParenthesizedList()
    {
        // Dapper's own `IN @eventTypes` binds the whole enumerable as one native array parameter
        // on an Npgsql connection, which is valid only after `= ANY(...)`; after `IN` it is a
        // syntax error at bind time that no SQLite test can observe.
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        await SeedOrgsAsync(pg.Store);

        var clock = new FakeTimeProvider(TestTime.KnownNow);
        var audit = new AuditRepository(pg.Store, time: clock);
        foreach (string eventType in new[] { "blocked_license", "blocked_kev", "download" })
        {
            await audit.LogActivityAsync(
                OrgId, "npm", $"pkg:npm/{eventType}@1", eventType, sourceIp: "203.0.113.7");
            clock.Advance(TimeSpan.FromMilliseconds(1));
        }

        var (items, _) = await audit.ListActivityEventsAsync(
            WindowStart, WindowEnd, OrgId, includeBlockedFamily: false,
            eventTypes: ["blocked_license", "download"], limit: 100, afterCursor: null);

        Assert.Equal(
            new[] { "blocked_license", "download" },
            items.Select(i => i.EventType).OrderBy(t => t, StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public async Task OrgScopeAndCursorPaging_OnLivePostgres_HoldAcrossPages()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        await SeedOrgsAsync(pg.Store);

        var clock = new FakeTimeProvider(TestTime.KnownNow);
        var audit = new AuditRepository(pg.Store, time: clock);
        for (int i = 0; i < 9; i++)
        {
            await audit.LogActivityAsync(
                OrgId, "npm", $"pkg:npm/mine{i}@1", "blocked_license", sourceIp: "203.0.113.7");
            await audit.LogActivityAsync(
                OtherOrgId, "npm", $"pkg:npm/theirs{i}@1", "blocked_license", sourceIp: "203.0.113.8");
            clock.Advance(TimeSpan.FromMilliseconds(1));
        }

        var seen = new List<string>();
        string? cursor = null;
        int pages = 0;
        const int maxPages = 6; // bounds a runaway loop if paging never terminates

        while (pages < maxPages)
        {
            var (items, nextCursor) = await audit.ListActivityEventsAsync(
                WindowStart, WindowEnd, OrgId, includeBlockedFamily: true, eventTypes: [],
                limit: 4, afterCursor: cursor);
            pages++;
            seen.AddRange(items.Select(i => i.Purl));

            if (nextCursor is null)
            {
                break;
            }

            cursor = nextCursor;
        }

        Assert.True(pages < maxPages, "paging did not terminate within the page budget");
        Assert.Equal(9, seen.Count);
        Assert.Equal(9, seen.Distinct().Count());
        Assert.All(seen, purl => Assert.StartsWith("pkg:npm/mine", purl, StringComparison.Ordinal));
    }

    private static async Task SeedOrgsAsync(IMetadataStore store)
    {
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new[] { new { id = OrgId, slug = "pg-activity-a" }, new { id = OtherOrgId, slug = "pg-activity-b" } });
    }
}
