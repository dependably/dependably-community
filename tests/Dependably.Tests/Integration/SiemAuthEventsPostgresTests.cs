using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Integration;

/// <summary>
/// Live-Postgres coverage for <see cref="AuditRepository.ListAuthEventsAsync"/> — the SIEM pull
/// feed at <c>GET /api/v1/siem/events/auth</c>.
///
/// <para>
/// The action-prefix filter is the part of that query whose correctness is a property of the
/// <em>provider</em> rather than of the SQL. Unfolding the prefix list inside the statement with
/// <c>json_each(@patternsJson)</c> works on SQLite, where <c>json_each</c> is a table-valued
/// function that walks a JSON array; Postgres's same-named function takes <c>json</c> rather than
/// <c>text</c> and deconstructs an <em>object</em>, so the identical statement fails outright
/// there — <c>function json_each(text) does not exist</c> for a bound string parameter. Every unit
/// test over this method runs on SQLite and so cannot see it: the feed returned rows locally and
/// threw on every Postgres deployment, which is the documented production topology.
/// </para>
///
/// <para>
/// These tests therefore pin the filter against a real Postgres connection. They go red on the
/// <c>json_each</c> form (it throws before returning a row) and stay red for a filter that merely
/// stops discriminating, because every case seeds a mixed batch: actions that must come back
/// alongside actions that must not, one prefix that matches nothing at all, and a row matched by
/// two prefixes at once — which the <c>LIKE</c> disjunction must still return exactly once, the
/// property the old <c>EXISTS</c> unfold gave for free.
/// </para>
///
/// <para>
/// <b>The prefix filter appears twice in that method</b> — once on the page query and once on the
/// <c>Matched</c> count probe — and only the first is exercised by returning rows. The count
/// statement is the one that stayed on the <c>json_each</c> unfold after the page query was fixed,
/// so it is covered here on its own terms: the count is asserted, the cap boundary is walked on
/// both sides, and the probe's <c>LIMIT</c>-bounded derived table has to parse and execute on
/// Postgres for any of it to return at all.
/// </para>
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class SiemAuthEventsPostgresTests
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
    public async Task MultiplePrefixes_OnLivePostgres_ReturnUnionOfMatches_AndSkipNonMatchingPrefix()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        await SeedOrgsAsync(pg.Store);

        var clock = new FakeTimeProvider(TestTime.KnownNow);
        var audit = new AuditRepository(pg.Store, time: clock);
        await SeedActionsAsync(
            audit, clock, OrgId,
            "login.success", "login.failed", "login.mfa.challenge",
            "token.created", "rbac.role_changed", "lockout.triggered",
            "package.published", "logins.not_a_family");

        // Three prefixes: two that match, one that matches nothing. "login.mfa" additionally
        // overlaps "login" on the login.mfa.challenge row, which must still come back once.
        var (items, _, _, _, _) = await audit.ListAuthEventsAsync(
            WindowStart, WindowEnd, orgId: null,
            actionFilter: ["login", "token", "login.mfa", "nosuchfamily"],
            limit: 100, afterCursor: null);

        Assert.Equal(
            new[] { "login.failed", "login.mfa.challenge", "login.success", "token.created" },
            items.Select(i => i.Action).OrderBy(a => a, StringComparer.Ordinal).ToArray());

        // The prefix is a family, not a substring: "logins.not_a_family" shares the first five
        // characters with "login" and must not be swept in by the appended separator.
        Assert.DoesNotContain(items, i => i.Action == "logins.not_a_family");
        Assert.Equal(items.Count, items.Select(i => i.Id).Distinct(StringComparer.Ordinal).Count());
    }

    /// <summary>
    /// The no-filter default on the provider production runs. The default set is exact declared
    /// names, which compiles to a single bound <c>IN</c> list rather than a <c>LIKE</c>
    /// disjunction — a different statement shape from the caller-filter path above, and one no
    /// SQLite-backed test exercises against Postgres's parameter handling.
    ///
    /// <para>
    /// The seeded batch is mixed on purpose: flat credential and RBAC names that must be served
    /// (the events the dead <c>token.</c>/<c>rbac.</c> default prefixes only implied), a dotted
    /// name from the same families that must be served, and operational rows that must not — so a
    /// default that stopped discriminating fails here rather than passing by coincidence.
    /// </para>
    /// </summary>
    [Fact]
    public async Task DefaultActionSet_OnLivePostgres_ServesTheSecurityVocabularyOnly()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        await SeedOrgsAsync(pg.Store);

        var clock = new FakeTimeProvider(TestTime.KnownNow);
        var audit = new AuditRepository(pg.Store, time: clock);
        await SeedActionsAsync(
            audit, clock, OrgId,
            "login.success", "lockout.triggered", "token_revoked", "member_role_changed",
            "checksum_failure", "ratelimit.rejected",
            "proxy_settings_updated", "project.created");

        // No filter supplied: the repository's own default set, which is the shape a collector
        // polling the endpoint with no action= parameter gets.
        var (items, _, _, matched, _) = await audit.ListAuthEventsAsync(
            WindowStart, WindowEnd, orgId: null, actionFilter: null, limit: 100, afterCursor: null);

        Assert.Equal(
            new[]
            {
                "checksum_failure", "lockout.triggered", "login.success", "member_role_changed",
                "ratelimit.rejected", "token_revoked",
            },
            items.Select(i => i.Action).OrderBy(a => a, StringComparer.Ordinal).ToArray());

        // The count probe binds the same IN list on its own statement; a divergence there is
        // invisible in the page.
        Assert.Equal(6, matched);
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
            await audit.LogAsync(
                "login.success", orgId: OrgId, actorId: $"mine{i}",
                actorKind: ActorKinds.User, sourceIp: "203.0.113.7");
            await audit.LogAsync(
                "login.success", orgId: OtherOrgId, actorId: $"theirs{i}",
                actorKind: ActorKinds.User, sourceIp: "203.0.113.8");
            clock.Advance(TimeSpan.FromMilliseconds(1));
        }

        var seen = new List<string>();
        string? cursor = null;
        int pages = 0;
        const int maxPages = 6; // bounds a runaway loop if paging never terminates

        while (pages < maxPages)
        {
            var (items, nextCursor, _, _, _) = await audit.ListAuthEventsAsync(
                WindowStart, WindowEnd, OrgId, actionFilter: ["login", "token"],
                limit: 4, afterCursor: cursor);
            pages++;
            seen.AddRange(items.Select(i => i.ActorId!));

            if (nextCursor is null)
            {
                break;
            }

            cursor = nextCursor;
        }

        Assert.True(pages < maxPages, "paging did not terminate within the page budget");
        Assert.Equal(9, seen.Count);
        Assert.Equal(9, seen.Distinct(StringComparer.Ordinal).Count());
        Assert.All(seen, actor => Assert.StartsWith("mine", actor, StringComparison.Ordinal));
    }

    [Fact]
    public async Task PrefixCountAtTheCap_OnLivePostgres_BindsWithoutExceedingTheParameterCeiling()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        await SeedOrgsAsync(pg.Store);

        var clock = new FakeTimeProvider(TestTime.KnownNow);
        var audit = new AuditRepository(pg.Store, time: clock);
        await SeedActionsAsync(audit, clock, OrgId, "login.success", "zzz_future.event", "package.published");

        // The most parameters the endpoint will ever let through is not simply the total cap: a
        // declared name binds one IN entry, while a family or undeclared name binds an IN entry
        // AND a LIKE pattern. The largest list the caps admit is every declared action plus every
        // implied family, so the worst-case bind count is the total cap plus the family cap — and
        // that is the list built here. Building it from junk names alone would trip the family cap
        // and never reach the driver at all.
        string[] filters = [.. AuditActions.All, .. AuditActions.ImpliedFamilyPrefixes];

        Assert.Equal(AuditRepository.MaxAuthEventActionFilters, filters.Length);
        Assert.Equal(
            AuditRepository.MaxAuthEventFamilyFilters,
            filters.Count(f => !AuditActions.IsDeclaredLeaf(f)));

        var (items, _, _, _, _) = await audit.ListAuthEventsAsync(
            WindowStart, WindowEnd, orgId: null, actionFilter: filters, limit: 100, afterCursor: null);

        // Both halves have to be live at the maximum bind count for this to mean anything on
        // Postgres: login.success arrives through the IN half (it is declared), package.published
        // only through the `package` family LIKE (nothing declares it). zzz_future.event is the
        // negative — no declared action sits under `zzz_future`, so it is not an implied family,
        // no filter in the list names it, and its absence is what proves the LIKE disjunction is
        // matching by prefix rather than sweeping the window.
        Assert.Equal(
            ["login.success", "package.published"],
            items.Select(i => i.Action).OrderBy(a => a, StringComparer.Ordinal).ToArray());
    }

    /// <summary>
    /// Bulk-seeds <paramref name="count"/> audit rows through <c>generate_series</c>. A per-row
    /// <c>LogAsync</c> would be tens of thousands of round trips for the cap boundary; the id is
    /// the only column that has to differ, since the count probe orders nothing and the window is
    /// deliberately wide.
    /// </summary>
    private static async Task SeedBulkAsync(
        IMetadataStore store, int count, string action, string orgId = OrgId)
    {
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO audit_log (id, scope, org_id, action, created_at)
            SELECT @action || '-' || n, 'tenant', @orgId, @action, @createdAt
            FROM generate_series(1, @count) AS n
            """,
            new { count, orgId, action, createdAt = TestTime.KnownNow.ToUtcIsoMillis() });
    }

    /// <summary>
    /// <c>Matched</c> is the whole filtered window, not the page — a collector compares it against
    /// what it received to notice a filter that matched less than it expected. A mixed batch, so a
    /// count that silently stopped discriminating (counting every row, or only the page) fails
    /// rather than coincidentally agreeing.
    /// </summary>
    [Fact]
    public async Task MatchedCount_OnLivePostgres_CoversTheFilteredWindowRatherThanThePage()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        await SeedOrgsAsync(pg.Store);

        var clock = new FakeTimeProvider(TestTime.KnownNow);
        var audit = new AuditRepository(pg.Store, time: clock);
        await SeedActionsAsync(
            audit, clock, OrgId,
            "login.success", "login.failed", "login.mfa.challenge", "token.created",
            "package.published", "org.updated", "logins.not_a_family");

        var (items, nextCursor, _, matched, matchedCapped) = await audit.ListAuthEventsAsync(
            WindowStart, WindowEnd, orgId: null,
            actionFilter: ["login", "token"], limit: 2, afterCursor: null);

        Assert.Equal(2, items.Count);
        Assert.NotNull(nextCursor);
        Assert.Equal(4, matched);
        Assert.False(matchedCapped);
    }

    /// <summary>
    /// The count runs the same <c>LIKE</c> disjunction the page does, so the two properties that
    /// disjunction owes must hold on it too: a row matched by two overlapping prefixes is counted
    /// once, and the org scope bounds it. An <c>EXISTS</c>-over-an-unfold gave the first for free;
    /// a disjunction has to be checked, and a count is where a double-match shows up as an
    /// inflated number rather than as a duplicate row.
    /// </summary>
    [Fact]
    public async Task MatchedCount_OnLivePostgres_CountsAnOverlappingMatchOnceAndHonoursOrgScope()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        await SeedOrgsAsync(pg.Store);

        var clock = new FakeTimeProvider(TestTime.KnownNow);
        var audit = new AuditRepository(pg.Store, time: clock);
        await SeedActionsAsync(audit, clock, OrgId, "login.mfa.challenge", "login.success");
        await SeedActionsAsync(audit, clock, OtherOrgId, "login.mfa.challenge", "login.success");

        var (_, _, _, scoped, _) = await audit.ListAuthEventsAsync(
            WindowStart, WindowEnd, OrgId,
            actionFilter: ["login", "login.mfa", "nosuchfamily"], limit: 100, afterCursor: null);
        var (_, _, _, unscoped, _) = await audit.ListAuthEventsAsync(
            WindowStart, WindowEnd, orgId: null,
            actionFilter: ["login", "login.mfa", "nosuchfamily"], limit: 100, afterCursor: null);

        Assert.Equal(2, scoped);
        Assert.Equal(4, unscoped);
    }

    /// <summary>
    /// The cap boundary on live Postgres, both sides. Exactly
    /// <see cref="AuditRepository.ListTotalCap"/> must not be flagged and one past it must, so an
    /// off-by-one in the probe comparison fails one of the two instead of staying green either way
    /// — and the <c>LIMIT</c>-bounded derived table the probe is built on has to execute on the
    /// provider for either to return a number at all.
    /// </summary>
    [Theory]
    [InlineData(AuditRepository.ListTotalCap, false)]
    [InlineData(AuditRepository.ListTotalCap + 1, true)]
    public async Task MatchedCapped_OnLivePostgres_FlipsExactlyOnePastTheCap(int seeded, bool expectCapped)
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        await SeedOrgsAsync(pg.Store);

        await SeedBulkAsync(pg.Store, seeded, "login.success");
        // A second family inside the same window that the filter must exclude from the count:
        // without it, "counted everything" and "counted the matches" are the same number.
        await SeedBulkAsync(pg.Store, 5, "package.published");

        var audit = new AuditRepository(pg.Store, time: new FakeTimeProvider(TestTime.KnownNow));
        var (_, _, _, matched, matchedCapped) = await audit.ListAuthEventsAsync(
            WindowStart, WindowEnd, OrgId,
            actionFilter: ["login"], limit: 50, afterCursor: null);

        Assert.Equal(AuditRepository.ListTotalCap, matched);
        Assert.Equal(expectCapped, matchedCapped);
    }

    /// <summary>
    /// <c>LatestEventAt</c> is two literal SQL bodies picked on <c>orgId is null</c>, so both have
    /// to run on the provider. It also ignores the action filter by design — that is the whole
    /// point of the field, and it is what tells a collector "the registry is quiet" apart from "my
    /// filter matches nothing".
    /// </summary>
    [Fact]
    public async Task LatestEventAt_OnLivePostgres_RunsBothScopedAndUnscopedBodies()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        await SeedOrgsAsync(pg.Store);

        var clock = new FakeTimeProvider(TestTime.KnownNow);
        var audit = new AuditRepository(pg.Store, time: clock);
        await audit.LogAsync("login.success", orgId: OrgId, actorId: "u1", actorKind: ActorKinds.User);
        clock.Advance(TimeSpan.FromMinutes(1));
        var mineAt = clock.GetUtcNow();
        // Matches no filter below, and is the newest row in this org — exactly the row a
        // filter-blind watermark has to surface.
        await audit.LogAsync("package.published", orgId: OrgId, actorId: "u1", actorKind: ActorKinds.User);
        clock.Advance(TimeSpan.FromMinutes(1));
        var theirsAt = clock.GetUtcNow();
        await audit.LogAsync("login.success", orgId: OtherOrgId, actorId: "u2", actorKind: ActorKinds.User);

        var (_, _, scopedLatest, _, _) = await audit.ListAuthEventsAsync(
            WindowStart, WindowEnd, OrgId, actionFilter: ["login"], limit: 50, afterCursor: null);
        var (_, _, unscopedLatest, _, _) = await audit.ListAuthEventsAsync(
            WindowStart, WindowEnd, orgId: null, actionFilter: ["login"], limit: 50, afterCursor: null);

        Assert.Equal(mineAt, scopedLatest);
        Assert.Equal(theirsAt, unscopedLatest);
    }

    private static async Task SeedActionsAsync(
        AuditRepository audit, FakeTimeProvider clock, string orgId, params string[] actions)
    {
        foreach (string action in actions)
        {
            await audit.LogAsync(
                action, orgId: orgId, actorId: "u1", actorKind: ActorKinds.User,
                sourceIp: "203.0.113.7");
            clock.Advance(TimeSpan.FromMilliseconds(1));
        }
    }

    private static async Task SeedOrgsAsync(IMetadataStore store)
    {
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new[] { new { id = OrgId, slug = "pg-auth-a" }, new { id = OtherOrgId, slug = "pg-auth-b" } });
    }
}
