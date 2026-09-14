using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The SIEM auth feed's <c>action=</c> filter, driven through the real SQL rather than through a
/// restatement of its rule in C#.
///
/// <para>
/// The filter appended the family separator unconditionally, so every pattern was
/// <c>&lt;value&gt;.%</c>: an action with no dot in it — 57 of the declared vocabulary,
/// <c>checksum_failure</c>, <c>ssrf_blocked</c>, <c>token_created</c> and
/// <c>member_role_changed</c> among them — could not be matched by any value a caller was able to
/// send. Nothing surfaced it: the query ran, the endpoint returned 200, and the events simply were
/// not in the response. These tests seed one row per declared action and assert each one comes
/// back, which is the only form of this check that fails on the old predicate.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuditActionFilterTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static readonly DateTimeOffset Seeded = TestTime.KnownNow;
    private static readonly DateTimeOffset Since = TestTime.KnownNow.AddMinutes(-5);
    private static readonly DateTimeOffset Until = TestTime.KnownNow.AddMinutes(5);

    private async Task<AuditRepository> SeedOneRowPerDeclaredActionAsync()
    {
        var clock = new FakeTimeProvider(Seeded);
        var audit = new AuditRepository(_db, time: clock);
        foreach (string action in AuditActions.All)
        {
            await audit.LogAsync(action, orgId: "o1", actorId: "u1");
            clock.Advance(TimeSpan.FromMilliseconds(1));
        }

        return audit;
    }

    [Fact]
    public async Task EveryDeclaredActionIsReachableByItsOwnName()
    {
        var audit = await SeedOneRowPerDeclaredActionAsync();

        var unreachable = new List<string>();
        foreach (string action in AuditActions.All)
        {
            var (items, _, _, _, _) = await audit.ListAuthEventsAsync(
                Since, Until, orgId: null, actionFilter: [action], limit: 500, afterCursor: null);

            if (!items.Any(i => i.Action == action))
            {
                unreachable.Add(action);
            }
        }

        Assert.Equal([], unreachable);
    }

    /// <summary>
    /// An exact filter is exact: naming one action must not drag in its neighbours, or a collector
    /// subscribing to <c>token_created</c> silently ingests every action sharing its prefix.
    /// </summary>
    [Fact]
    public async Task AnExactNameMatchesOnlyThatActionAndItsOwnDottedFamily()
    {
        var clock = new FakeTimeProvider(Seeded);
        var audit = new AuditRepository(_db, time: clock);
        foreach (string action in new[]
                 {
                     "token_created", "token_revoked", "service_token_created",
                     "saml.config_updated", "saml.signing_cert_set",
                 })
        {
            await audit.LogAsync(action, orgId: "o1", actorId: "u1");
            clock.Advance(TimeSpan.FromMilliseconds(1));
        }

        var (exact, _, _, _, _) = await audit.ListAuthEventsAsync(
            Since, Until, orgId: null, actionFilter: ["token_created"], limit: 100, afterCursor: null);
        Assert.Equal(["token_created"], exact.Select(i => i.Action).ToArray());

        var (family, _, _, _, _) = await audit.ListAuthEventsAsync(
            Since, Until, orgId: null, actionFilter: ["saml"], limit: 100, afterCursor: null);
        Assert.Equal(
            ["saml.config_updated", "saml.signing_cert_set"],
            family.Select(i => i.Action).OrderBy(a => a, StringComparer.Ordinal).ToArray());
    }

    /// <summary>
    /// The no-filter feed is the one a collector gets by default, so "which actions does it serve"
    /// is a property worth asserting over the whole vocabulary rather than one family at a time —
    /// the previous default advertised two families (<c>token.</c>, <c>rbac.</c>) whose events it
    /// could never have served.
    /// </summary>
    [Fact]
    public async Task TheDefaultFeedServesExactlyTheSecurityVocabulary()
    {
        var audit = await SeedOneRowPerDeclaredActionAsync();

        var (items, _, _, matched, _) = await audit.ListAuthEventsAsync(
            Since, Until, orgId: null, actionFilter: null, limit: 500, afterCursor: null);

        var served = items.Select(i => i.Action).ToHashSet(StringComparer.Ordinal);

        Assert.Equal(
            AuditActions.DefaultFilters.OrderBy(a => a, StringComparer.Ordinal).ToArray(),
            served.OrderBy(a => a, StringComparer.Ordinal).ToArray());

        // The matched total is computed from the same predicate, so it cannot disagree with the
        // page about what the default set covers.
        Assert.Equal(AuditActions.DefaultFilters.Length, matched);
    }

    /// <summary>
    /// The credential, RBAC and supply-chain integrity events the dead <c>token.</c>/<c>rbac.</c>
    /// default prefixes implied coverage for. Named individually because these are the ones an
    /// operator wiring a SOC goes looking for, and the ones that were absent.
    /// </summary>
    [Theory]
    [InlineData("token_created")]
    [InlineData("token_revoked")]
    [InlineData("service_token_created")]
    [InlineData("member_role_changed")]
    [InlineData("member_removed")]
    [InlineData("checksum_failure")]
    [InlineData("ssrf_blocked")]
    [InlineData("provenance_verification_failed")]
    [InlineData("upstream_source_pin_violation")]
    [InlineData("quarantine_decision")]
    [InlineData("trust_anchor_added")]
    [InlineData("allowlist_blocked")]
    [InlineData("invite_accept_blocked")]
    public async Task AFlatSecurityActionReachesTheDefaultFeedAndAnExactFilter(string action)
    {
        var audit = new AuditRepository(_db, time: new FakeTimeProvider(Seeded));
        await audit.LogAsync(action, orgId: "o1", actorId: "u1");

        var (byDefault, _, _, _, _) = await audit.ListAuthEventsAsync(
            Since, Until, orgId: null, actionFilter: null, limit: 100, afterCursor: null);
        Assert.Contains(byDefault, i => i.Action == action);

        var (byName, _, _, _, _) = await audit.ListAuthEventsAsync(
            Since, Until, orgId: null, actionFilter: [action], limit: 100, afterCursor: null);
        Assert.Contains(byName, i => i.Action == action);
    }

    /// <summary>
    /// Every event on this feed named its tenant by 32-hex id and nothing else: a read:audit token
    /// has no tenant-lookup route, so an alert could not be resolved to a customer at all.
    /// </summary>
    [Fact]
    public async Task EventsCarryTheOrgSlugBesideTheOrgId()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        }

        var audit = new AuditRepository(_db, time: new FakeTimeProvider(Seeded));
        await audit.LogAsync("checksum_failure", orgId: "o1", actorId: "u1");
        await audit.LogAsync("ssrf_blocked", orgId: null, actorId: "u1");

        var (items, _, _, _, _) = await audit.ListAuthEventsAsync(
            Since, Until, orgId: null, actionFilter: null, limit: 100, afterCursor: null);

        var tenantRow = Assert.Single(items, i => i.Action == "checksum_failure");
        Assert.Equal("o1", tenantRow.OrgId);
        Assert.Equal("acme", tenantRow.OrgSlug);

        // An instance-scope row has no tenant to name, and the LEFT JOIN must leave it null rather
        // than drop the row — an inner join here would silently delete every system-scope event.
        var apexRow = Assert.Single(items, i => i.Action == "ssrf_blocked");
        Assert.Null(apexRow.OrgSlug);

        // actorEmail stays null by design: audit_log.actor_label is service-actors-only, because a
        // user's display name is an email and the member-removal and retention scrubs cover a
        // fixed column list. Pinned so a later "helpful" join has to argue with this test.
        Assert.All(items, i => Assert.Null(i.ActorEmail));
    }

    /// <summary>
    /// A collector that has been sending the documented trailing-dot form for years keeps getting
    /// exactly what it got.
    /// </summary>
    [Fact]
    public async Task TheTrailingDotFormStillSelectsTheWholeFamily()
    {
        var clock = new FakeTimeProvider(Seeded);
        var audit = new AuditRepository(_db, time: clock);
        foreach (string action in new[] { "login.success", "login.failure", "lockout.triggered" })
        {
            await audit.LogAsync(action, orgId: "o1", actorId: "u1");
            clock.Advance(TimeSpan.FromMilliseconds(1));
        }

        var (items, _, _, _, _) = await audit.ListAuthEventsAsync(
            Since, Until, orgId: null, actionFilter: ["login."], limit: 100, afterCursor: null);

        Assert.Equal(
            ["login.failure", "login.success"],
            items.Select(i => i.Action).OrderBy(a => a, StringComparer.Ordinal).ToArray());
    }
}
