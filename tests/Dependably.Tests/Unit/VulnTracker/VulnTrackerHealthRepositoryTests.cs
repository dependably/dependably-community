using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.VulnTracker;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.VulnTracker;

/// <summary>
/// The observed-health store behind the tracker connection panel.
///
/// <para>
/// Four properties are pinned here because each one, if it broke, would produce a panel that
/// looks right and reports the wrong thing:
/// </para>
///
/// <para>
/// <b>A failure learns nothing.</b> An unreached lookup must not move <c>last_success_at</c>, the
/// counts, or either producer-asserted stamp — those describe the last lookup that was actually
/// reached, and reporting a refusal as though it refreshed them is exactly the
/// launder-an-outage-into-a-clean-bill failure the client's own <c>Reached</c> contract exists to
/// prevent.
/// </para>
///
/// <para>
/// <b>failing_since is where a streak began, not where it was last seen.</b> An operator needs
/// "failing for six hours"; a stamp that moves on every failure can only ever say "failing".
/// </para>
///
/// <para>
/// <b>A probe never moves the health row.</b> The row describes the scan path, so an
/// operator-initiated test that cleared the failure counters would let the one button pressed
/// when something is wrong paint false-green over a scan path that is still broken.
/// </para>
///
/// <para>
/// <b>An unmapped reason is stored as <c>unknown</c>, not raw.</b> Both reason columns carry a
/// CHECK that SQLite can never widen in place, so a raw enum member would start failing the write
/// the day a reason is added to the client — and health would silently stop being recorded at all.
/// </para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class VulnTrackerHealthRepositoryTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();
    public async Task DisposeAsync() => await _db.DisposeAsync();

    private VulnTrackerHealthRepository Repo() => new(_db, _clock);

    // StartedAt is stamped from the test clock, not from a constant: it is the fetch log's sort
    // key, so a fixed value would tie every row and leave the ordering — and therefore which rows
    // the ring keeps — decided by a random GUID.
    private VulnTrackerFetchOutcome Reached(
        int purls = 3,
        int advisories = 7,
        DateTimeOffset? nvd = null,
        DateTimeOffset? ssvc = null)
        => new(true, "none", purls, advisories, DurationMs: 42, StartedAt: _clock.GetUtcNow(),
               NvdAssertedAt: nvd, SsvcAssertedAt: ssvc);

    private VulnTrackerFetchOutcome Unreached(string reason = "rateLimited", int purls = 3)
        => new(false, reason, purls, 0, DurationMs: 11, StartedAt: _clock.GetUtcNow());

    // ── The health row ────────────────────────────────────────────────────────

    [Fact]
    public async Task NoLookupYet_ReportsNoHealthRowAtAll()
    {
        // Null is not "healthy" and not "failing" — it is "the scan has never attempted a lookup".
        // The read surfaces depend on being able to tell that apart from a failing connection.
        Assert.Null(await Repo().GetHealthAsync());
    }

    [Fact]
    public async Task ReachedLookup_RecordsSuccessAndItsCounts()
    {
        await Repo().RecordScanFetchAsync(Reached(purls: 5, advisories: 9));

        var health = await Repo().GetHealthAsync();
        Assert.NotNull(health);
        Assert.Equal("ok", health!.LastStatus);
        Assert.Equal("none", health.LastReason);
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), health.LastAttemptAt);
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), health.LastSuccessAt);
        Assert.Equal(5, health.LastPurlCount);
        Assert.Equal(9, health.LastAdvisoryCount);
        Assert.Equal(0, health.ConsecutiveFailures);
        Assert.Null(health.FailingSince);
    }

    [Fact]
    public async Task UnreachedLookup_RecordsTheRefusalWithoutClaimingContact()
    {
        await Repo().RecordScanFetchAsync(Unreached("unauthorized"));

        var health = await Repo().GetHealthAsync();
        Assert.Equal("failed", health!.LastStatus);
        Assert.Equal("unauthorized", health.LastReason);
        Assert.Equal(1, health.ConsecutiveFailures);
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), health.FailingSince);
        // The attempt happened; contact did not. Conflating the two is the whole hazard.
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), health.LastAttemptAt);
        Assert.Null(health.LastSuccessAt);
    }

    [Fact]
    public async Task FailureAfterSuccess_LeavesEverythingTheSuccessEstablished()
    {
        // The adversarial half of "a failure learns nothing": seed a real success carrying every
        // field a failure might plausibly overwrite, then fail and assert none of them moved.
        var asserted = TestTime.KnownNow.AddDays(-1);
        await Repo().RecordScanFetchAsync(Reached(purls: 5, advisories: 9, nvd: asserted, ssvc: asserted));

        _clock.Advance(TimeSpan.FromHours(3));
        await Repo().RecordScanFetchAsync(Unreached("serverError"));

        var health = await Repo().GetHealthAsync();
        Assert.Equal("failed", health!.LastStatus);
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), health.LastSuccessAt);
        Assert.Equal(5, health.LastPurlCount);
        Assert.Equal(9, health.LastAdvisoryCount);
        Assert.Equal(asserted.ToUtcIso(), health.NvdAssertedAt);
        Assert.Equal(asserted.ToUtcIso(), health.SsvcAssertedAt);
        // Only the attempt stamp and the failure fields moved.
        Assert.Equal(TestTime.KnownNow.AddHours(3).ToUtcIso(), health.LastAttemptAt);
    }

    [Fact]
    public async Task ConsecutiveFailures_KeepTheFirstFailingSinceAndKeepCounting()
    {
        await Repo().RecordScanFetchAsync(Unreached("transport"));
        _clock.Advance(TimeSpan.FromHours(6));
        await Repo().RecordScanFetchAsync(Unreached("transport"));
        _clock.Advance(TimeSpan.FromHours(6));
        await Repo().RecordScanFetchAsync(Unreached("timeout"));

        var health = await Repo().GetHealthAsync();
        Assert.Equal(3, health!.ConsecutiveFailures);
        Assert.Equal("timeout", health.LastReason);
        // Twelve hours later, the streak still reports where it BEGAN. A stamp that moved with
        // each failure would read as though the outage started moments ago.
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), health.FailingSince);
    }

    [Fact]
    public async Task RecoveryAfterAStreak_ClearsTheStreakEntirely()
    {
        await Repo().RecordScanFetchAsync(Unreached());
        await Repo().RecordScanFetchAsync(Unreached());
        _clock.Advance(TimeSpan.FromHours(1));
        await Repo().RecordScanFetchAsync(Reached());

        var health = await Repo().GetHealthAsync();
        Assert.Equal("ok", health!.LastStatus);
        Assert.Equal(0, health.ConsecutiveFailures);
        Assert.Null(health.FailingSince);
    }

    [Fact]
    public async Task ReachedResponseCarryingNoFreshness_KeepsTheLastAssertedAsOf()
    {
        // A response that asserts nothing about a source has told us nothing new about it. The
        // stored value is the only upper bound on that source's staleness we hold, and it is the
        // OLDER one — so keeping it can only make a staleness reading more conservative.
        var asserted = TestTime.KnownNow.AddDays(-2);
        await Repo().RecordScanFetchAsync(Reached(nvd: asserted, ssvc: asserted));

        _clock.Advance(TimeSpan.FromHours(1));
        await Repo().RecordScanFetchAsync(Reached(nvd: null, ssvc: null));

        var health = await Repo().GetHealthAsync();
        Assert.Equal(asserted.ToUtcIso(), health!.NvdAssertedAt);
        Assert.Equal(asserted.ToUtcIso(), health.SsvcAssertedAt);
    }

    // ── The probe boundary ────────────────────────────────────────────────────

    [Fact]
    public async Task Probe_IsLoggedButNeverMovesTheHealthRow()
    {
        // Establish a genuinely broken scan path first, then probe successfully. The panel must
        // still report the scan path as broken: a probe answers "can I reach it right now", not
        // "is enrichment working".
        await Repo().RecordScanFetchAsync(Unreached("serverError"));
        await Repo().RecordScanFetchAsync(Unreached("serverError"));

        _clock.Advance(TimeSpan.FromMinutes(5));
        await Repo().RecordProbeFetchAsync(Reached());

        var health = await Repo().GetHealthAsync();
        Assert.Equal("failed", health!.LastStatus);
        Assert.Equal(2, health.ConsecutiveFailures);
        Assert.Null(health.LastSuccessAt);
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), health.FailingSince);

        // ...and the probe is still visible, tagged as what it was.
        var log = await Repo().ListRecentFetchesAsync(10);
        Assert.Equal("probe", log[0].Kind);
        Assert.Equal("ok", log[0].Outcome);
        Assert.Equal(2, log.Count(r => r.Kind == "scan"));
    }

    [Fact]
    public async Task FailingProbe_AlsoLeavesTheHealthRowAlone()
    {
        // The mirror image, and the one that matters for a working deployment: a probe that fails
        // — a typo'd URL an operator is still editing, say — must not report the scan path as
        // failing when the scan path is fine.
        await Repo().RecordScanFetchAsync(Reached());

        _clock.Advance(TimeSpan.FromMinutes(5));
        await Repo().RecordProbeFetchAsync(Unreached("transport"));

        var health = await Repo().GetHealthAsync();
        Assert.Equal("ok", health!.LastStatus);
        Assert.Equal(0, health.ConsecutiveFailures);
        Assert.Null(health.FailingSince);
    }

    // ── The fetch log ─────────────────────────────────────────────────────────

    [Fact]
    public async Task FetchLog_IsNewestFirstAndCarriesTheOutcomeDetail()
    {
        await Repo().RecordScanFetchAsync(Unreached("rateLimited", purls: 4));
        _clock.Advance(TimeSpan.FromMinutes(1));
        await Repo().RecordScanFetchAsync(
            new VulnTrackerFetchOutcome(true, "none", 6, 12, 55, _clock.GetUtcNow()));

        var log = await Repo().ListRecentFetchesAsync(10);
        Assert.Equal(2, log.Count);
        Assert.Equal("ok", log[0].Outcome);
        Assert.Equal(6, log[0].PurlCount);
        Assert.Equal(12, log[0].AdvisoryCount);
        Assert.Equal(55, log[0].DurationMs);
        Assert.Equal("failed", log[1].Outcome);
        Assert.Equal("rateLimited", log[1].Reason);
        Assert.Equal(4, log[1].PurlCount);
    }

    [Fact]
    public async Task FetchLog_IsRingBoundedToTheRetainedCount()
    {
        // Ten past the bound, each a minute apart so the ordering is unambiguous.
        for (int i = 0; i < VulnTrackerHealthRepository.FetchLogRetained + 10; i++)
        {
            await Repo().RecordScanFetchAsync(Unreached(purls: i));
            _clock.Advance(TimeSpan.FromMinutes(1));
        }

        await using var conn = await _db.OpenAsync();
        int stored = await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM vuln_tracker_fetch_log");
        Assert.Equal(VulnTrackerHealthRepository.FetchLogRetained, stored);

        // The rows that survived are the NEWEST ones, not an arbitrary hundred.
        var log = await Repo().ListRecentFetchesAsync(VulnTrackerHealthRepository.FetchLogRetained);
        Assert.Equal(VulnTrackerHealthRepository.FetchLogRetained + 9, log[0].PurlCount);
        Assert.Equal(10, log[^1].PurlCount);
    }

    [Fact]
    public async Task ListRecentFetches_CannotBeAskedForMoreThanIsRetained()
    {
        await Repo().RecordScanFetchAsync(Reached());
        // A caller asking for a thousand gets what exists, not an error and not an unbounded read.
        Assert.Single(await Repo().ListRecentFetchesAsync(10_000));
    }

    // ── Reason normalization ──────────────────────────────────────────────────

    [Theory]
    [InlineData(EnrichmentUnreachedReason.None, "none")]
    [InlineData(EnrichmentUnreachedReason.NotConfigured, "notConfigured")]
    [InlineData(EnrichmentUnreachedReason.Unauthorized, "unauthorized")]
    [InlineData(EnrichmentUnreachedReason.RateLimited, "rateLimited")]
    [InlineData(EnrichmentUnreachedReason.MalformedResponse, "malformedResponse")]
    public void EveryKnownReason_MapsToItsOwnToken(EnrichmentUnreachedReason reason, string expected)
        => Assert.Equal(expected, VulnTrackerHealthReasons.Normalize(reason));

    [Fact]
    public void EveryDeclaredReason_HasAMappingOfItsOwn()
    {
        // The mapping is a closed set with an `unknown` fallback, which means a reason added to
        // the client would silently collapse into `unknown` rather than fail to compile. This
        // catches that at the only moment it is cheap to fix.
        var mapped = Enum.GetValues<EnrichmentUnreachedReason>()
            .Select(VulnTrackerHealthReasons.Normalize)
            .ToList();

        Assert.DoesNotContain(VulnTrackerHealthReasons.Unknown, mapped);
        Assert.Equal(mapped.Count, mapped.Distinct().Count());
    }

    [Fact]
    public async Task AnUnmappedReason_IsStoredAsUnknownRatherThanFailingTheWrite()
    {
        // The whole reason Normalize exists. Writing an unrecognised value raw would violate the
        // column CHECK, and because health recording is deliberately failure-tolerant, the write
        // would be swallowed and the panel would go quietly blank.
        string reason = VulnTrackerHealthReasons.Normalize((EnrichmentUnreachedReason)9999);
        Assert.Equal("unknown", reason);

        await Repo().RecordScanFetchAsync(Unreached(reason));

        var health = await Repo().GetHealthAsync();
        Assert.Equal("unknown", health!.LastReason);
    }

    // ── The configuration boundary ────────────────────────────────────────────

    [Fact]
    public async Task RecordingHealth_NeverWritesTrackerConfiguration()
    {
        // Health is observation; instance_settings is intent. A failing tracker must not switch
        // itself off, and a reached one must not switch itself on — the same posture the shared
        // SMTP relay takes with email_enabled.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO instance_settings (key, value) VALUES ('vuln_tracker_enabled', '1')");
        }

        for (int i = 0; i < 5; i++)
        {
            await Repo().RecordScanFetchAsync(Unreached("serverError"));
        }
        await Repo().RecordProbeFetchAsync(Unreached("transport"));

        await using var check = await _db.OpenAsync();
        var rows = (await check.QueryAsync<(string Key, string Value)>(
            "SELECT key, value FROM instance_settings WHERE key LIKE 'vuln_tracker%'")).ToList();

        Assert.Equal(("vuln_tracker_enabled", "1"), Assert.Single(rows));
    }
}
