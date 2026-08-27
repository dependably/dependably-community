using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Covers <see cref="ThreatFeedRefreshService"/>'s refresh pass against a fake
/// <see cref="IThreatFeedSource"/>: KEV recompute (set AND clear), EPSS max-over-aliases
/// stamping, the partial-failure contract (rows whose CVEs sat in failed batches stay
/// unstamped for retry), feed-failure fail-soft, the air-gap skip, and CVE extraction.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ThreatFeedRefreshServiceTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly VulnerabilityRepository _repo;

    public ThreatFeedRefreshServiceTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _repo = new VulnerabilityRepository(_fixture.Store, TimeProvider.System);
    }

    private ThreatFeedRefreshService BuildService(IThreatFeedSource source, bool jobDisabled = false)
    {
        return new ThreatFeedRefreshService(
            _repo,
            source,
            new ConfigurationBuilder().Build(),
            new FakeAirGap(jobDisabled),
            NullLogger<ThreatFeedRefreshService>.Instance,
            TimeProvider.System,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(TimeProvider.System));
    }

    [Fact]
    public async Task KevPass_FlagsAliasedRow_AndClearsOnRemoval()
    {
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-kev-{Guid.NewGuid():N}", aliases: """["CVE-2024-0001"]""");

        var source = new FakeFeedSource { Kev = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CVE-2024-0001" } };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);
        Assert.True(await GetIsKevAsync(vulnId));

        // Catalog removal: the next pass recomputes against the new set and clears the flag.
        source.Kev = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);
        Assert.False(await GetIsKevAsync(vulnId));
    }

    [Fact]
    public async Task KevPass_FeedFailure_KeepsExistingFlags()
    {
        // Fail-soft contract: a broken KEV feed skips the pass instead of clearing every flag
        // against an empty set.
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-kevfail-{Guid.NewGuid():N}",
            aliases: """["CVE-2024-0002"]""", isKev: true);

        var source = new FakeFeedSource { KevThrows = true };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        Assert.True(await GetIsKevAsync(vulnId));
    }

    [Fact]
    public async Task EpssPass_StampsMaxAcrossAliases_AndNullForUnknown()
    {
        string scored = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-epss-{Guid.NewGuid():N}",
            aliases: """["CVE-2024-1000","CVE-2024-1001"]""");
        string unknown = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-epss-unknown-{Guid.NewGuid():N}",
            aliases: """["CVE-2024-2000"]""");

        var source = new FakeFeedSource
        {
            EpssScores = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase)
            {
                ["CVE-2024-1000"] = new EpssScore(0.12, null),
                ["CVE-2024-1001"] = new EpssScore(0.83, null),
            },
            // All three CVEs were queried successfully; the third just has no EPSS entry.
            EpssQueriedAll = true,
        };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(0.83, await GetEpssAsync(scored));
        Assert.Null(await GetEpssAsync(unknown));
        // Queried-but-unknown still advances the stamp — a real "no score" answer.
        Assert.NotNull(await GetEpssCheckedAtAsync(unknown));
    }

    [Fact]
    public async Task EpssPass_FailedBatchRows_StayUnstamped_ForRetry()
    {
        // Mixed outcome in one pass: rows whose CVEs sat in a failed batch keep a NULL
        // checked-at stamp so the next pass retries them; successful rows are stamped.
        string okRow = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-epss-ok-{Guid.NewGuid():N}", aliases: """["CVE-2024-3000"]""");
        string failedRow = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-epss-failed-{Guid.NewGuid():N}", aliases: """["CVE-2024-4000"]""");

        var source = new FakeFeedSource
        {
            EpssScores = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase) { ["CVE-2024-3000"] = new EpssScore(0.5, null) },
            EpssQueried = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CVE-2024-3000" },
        };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(0.5, await GetEpssAsync(okRow));
        Assert.NotNull(await GetEpssCheckedAtAsync(okRow));
        Assert.Null(await GetEpssCheckedAtAsync(failedRow));
    }

    [Fact]
    public async Task Pass_JobDisabled_TouchesNothing()
    {
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-airgap-{Guid.NewGuid():N}", aliases: """["CVE-2024-5000"]""");

        var source = new FakeFeedSource
        {
            Kev = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CVE-2024-5000" },
            EpssScores = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase) { ["CVE-2024-5000"] = new EpssScore(0.9, null) },
            EpssQueriedAll = true,
        };
        await BuildService(source, jobDisabled: true).RunRefreshPassAsync(CancellationToken.None);

        Assert.False(await GetIsKevAsync(vulnId));
        Assert.Null(await GetEpssAsync(vulnId));
        Assert.Equal(0, source.KevCalls);
    }

    [Theory]
    [InlineData("CVE-2024-9999", null, new[] { "CVE-2024-9999" })]                         // osv_id IS the CVE
    [InlineData("GHSA-x", """["CVE-2024-1","GHSA-y","cve-2024-2"]""", new[] { "CVE-2024-1", "cve-2024-2" })] // aliases filtered to CVEs, case-insensitive
    [InlineData("GHSA-x", "not-json", new string[0])]                                       // malformed alias JSON = no aliases
    [InlineData("MAL-2026-1", null, new string[0])]                                         // no CVE anywhere
    public void ExtractCves_CoversAliasShapes(string osvId, string? aliasesJson, string[] expected)
    {
        Assert.Equal(expected, ThreatFeedRefreshService.ExtractCves(aliasesJson, osvId));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private async Task<bool> GetIsKevAsync(string vulnId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT is_kev FROM vulnerabilities WHERE id = @vulnId", new { vulnId }) == 1;
    }

    private async Task<double?> GetEpssAsync(string vulnId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<double?>(
            "SELECT epss_score FROM vulnerabilities WHERE id = @vulnId", new { vulnId });
    }

    // ── The KEV entry context, end to end ─────────────────────────────────────────────────

    [Fact]
    public async Task KevPass_PersistsTheEntryContext()
    {
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-ctx-{Guid.NewGuid():N}", aliases: """["CVE-2024-2000"]""");

        var source = new FakeFeedSource
        {
            KevCatalog = new(StringComparer.OrdinalIgnoreCase)
            {
                ["CVE-2024-2000"] = new KevEntry(
                    true, "2024-01-15", "2024-02-05",
                    RequiredAction: "Apply the vendor patch.",
                    Cwes: ["CWE-502"],
                    Notes: "https://vendor.example/advisory"),
            },
        };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        var (ransomware, dateAdded, dueDate) = await GetKevContextAsync(vulnId);
        Assert.Equal(1, ransomware);
        Assert.Equal("2024-01-15", dateAdded);
        Assert.Equal("2024-02-05", dueDate);

        var (requiredAction, cwesJson, notes) = await GetKevRemainingFieldsAsync(vulnId);
        Assert.Equal("Apply the vendor patch.", requiredAction);
        Assert.Equal("""["CWE-502"]""", cwesJson);
        Assert.Equal("https://vendor.example/advisory", notes);
    }

    [Fact]
    public async Task KevPass_UnknownRansomwareUse_StoresZero_NotNull()
    {
        // CISA's "Unknown" is an assertion of no known use, so it is a real 0 — distinguishable
        // from an entry that carried no such field, which is the next test.
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-unk-{Guid.NewGuid():N}", aliases: """["CVE-2024-2001"]""");

        var source = new FakeFeedSource
        {
            KevCatalog = new(StringComparer.OrdinalIgnoreCase)
            {
                ["CVE-2024-2001"] = new KevEntry(false, null, null),
            },
        };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(0, (await GetKevContextAsync(vulnId)).Ransomware);
    }

    [Fact]
    public async Task KevPass_NoRansomwareAssertion_StoresNull_NotZero()
    {
        // The adversarial twin of the previous test, and the one that matters: a gate arm reading
        // "the source never said" as "the source said no" is a fail-open. These two tests together
        // are what make the tri-state real rather than a comment.
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-null-{Guid.NewGuid():N}", aliases: """["CVE-2024-2002"]""");

        var source = new FakeFeedSource
        {
            KevCatalog = new(StringComparer.OrdinalIgnoreCase)
            {
                ["CVE-2024-2002"] = new KevEntry(null, null, null),
            },
        };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        Assert.Null((await GetKevContextAsync(vulnId)).Ransomware);
    }

    [Fact]
    public async Task KevPass_LeavingTheCatalogue_ClearsTheContextWithTheFlag()
    {
        // Context is recomputed wholesale each pass, like is_kev itself. A stale ransomware
        // verdict surviving on a row the catalogue no longer lists would be worse than no verdict.
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-gone-{Guid.NewGuid():N}", aliases: """["CVE-2024-2003"]""");

        var present = new FakeFeedSource
        {
            KevCatalog = new(StringComparer.OrdinalIgnoreCase)
            {
                ["CVE-2024-2003"] = new KevEntry(
                    true, "2024-01-15", "2024-02-05",
                    RequiredAction: "Apply the vendor patch.",
                    Cwes: ["CWE-502"],
                    Notes: "https://vendor.example/advisory"),
            },
        };
        await BuildService(present).RunRefreshPassAsync(CancellationToken.None);
        Assert.Equal(1, (await GetKevContextAsync(vulnId)).Ransomware);
        Assert.Equal("Apply the vendor patch.", (await GetKevRemainingFieldsAsync(vulnId)).RequiredAction);

        await BuildService(new FakeFeedSource()).RunRefreshPassAsync(CancellationToken.None);

        var (ransomware, dateAdded, dueDate) = await GetKevContextAsync(vulnId);
        Assert.False(await GetIsKevAsync(vulnId));
        Assert.Null(ransomware);
        Assert.Null(dateAdded);
        Assert.Null(dueDate);

        // Wholesale recompute clears the three remaining fields too, not just the pre-existing
        // ones — a catalogue removal must not leave requiredAction/cwes/notes stale on a row the
        // catalogue no longer flags.
        var (requiredAction, cwesJson, notes) = await GetKevRemainingFieldsAsync(vulnId);
        Assert.Null(requiredAction);
        Assert.Null(cwesJson);
        Assert.Null(notes);
    }

    [Fact]
    public async Task KevPass_AliasingSeveralEntries_PrefersTheRansomwareVerdict()
    {
        // One advisory can alias several CVEs. Without a deliberate choice the stored verdict
        // would depend on dictionary ordering, which is the kind of non-determinism that produces
        // a gate decision that differs between two runs over identical data.
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-multi-{Guid.NewGuid():N}",
            aliases: """["CVE-2024-2010","CVE-2024-2011"]""");

        var source = new FakeFeedSource
        {
            KevCatalog = new(StringComparer.OrdinalIgnoreCase)
            {
                ["CVE-2024-2010"] = new KevEntry(false, "2024-01-01", null),
                ["CVE-2024-2011"] = new KevEntry(true, "2024-02-02", null),
            },
        };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        var (ransomware, dateAdded, _) = await GetKevContextAsync(vulnId);
        Assert.Equal(1, ransomware);
        Assert.Equal("2024-02-02", dateAdded);
    }

    [Fact]
    public async Task KevPass_AliasingSeveralEntries_RequiredActionCwesNotes_ComeFromTheSameSelectedEntry()
    {
        // The two candidate entries deliberately disagree on every one of requiredAction/cwes/notes
        // AND on the ransomware verdict the selection loop already picks by. If the new fields were
        // read from a second, independent lookup rather than riding the same selected entry, this
        // test would observe values from CVE-2024-2010 (the non-ransomware entry, which a naive
        // "first match" or independent re-lookup could easily land on) instead of CVE-2024-2011 (the
        // one the existing ransomware-preference loop actually selects) — a fixture where both
        // candidates agreed would not be able to tell the two implementations apart.
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-multi-fields-{Guid.NewGuid():N}",
            aliases: """["CVE-2024-2012","CVE-2024-2013"]""");

        var source = new FakeFeedSource
        {
            KevCatalog = new(StringComparer.OrdinalIgnoreCase)
            {
                ["CVE-2024-2012"] = new KevEntry(
                    false, "2024-01-01", null,
                    RequiredAction: "Non-ransomware remediation.",
                    Cwes: ["CWE-79"],
                    Notes: "non-ransomware notes"),
                ["CVE-2024-2013"] = new KevEntry(
                    true, "2024-02-02", null,
                    RequiredAction: "Ransomware-flagged remediation.",
                    Cwes: ["CWE-502", "CWE-400"],
                    Notes: "ransomware-flagged notes"),
            },
        };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        var (ransomware, dateAdded, _) = await GetKevContextAsync(vulnId);
        Assert.Equal(1, ransomware);
        Assert.Equal("2024-02-02", dateAdded);

        var (requiredAction, cwesJson, notes) = await GetKevRemainingFieldsAsync(vulnId);
        Assert.Equal("Ransomware-flagged remediation.", requiredAction);
        Assert.Equal("""["CWE-502","CWE-400"]""", cwesJson);
        Assert.Equal("ransomware-flagged notes", notes);
    }

    // ── EPSS percentile ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task EpssPass_StoresThePercentilePairedWithTheWinningScore()
    {
        // The pair must describe one CVE. Maximising the two independently would pair one CVE's
        // probability with another's rank and store something that is true of neither.
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-pct-{Guid.NewGuid():N}",
            aliases: """["CVE-2024-2020","CVE-2024-2021"]""");

        var source = new FakeFeedSource
        {
            EpssScores = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase)
            {
                ["CVE-2024-2020"] = new EpssScore(0.20, 0.99),
                ["CVE-2024-2021"] = new EpssScore(0.80, 0.42),
            },
            EpssQueriedAll = true,
        };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _fixture.Store.OpenAsync();
        var (score, percentile) = await conn.QuerySingleAsync<(double?, double?)>(
            "SELECT epss_score, epss_percentile FROM vulnerabilities WHERE id = @vulnId",
            new { vulnId });

        Assert.Equal(0.80, score);
        // 0.42, not 0.99: the rank belonging to the winning probability.
        Assert.Equal(0.42, percentile);
    }

    [Fact]
    public async Task EpssPass_ScoreWithoutAPercentile_StillStampsTheScore()
    {
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-nopct-{Guid.NewGuid():N}", aliases: """["CVE-2024-2030"]""");

        var source = new FakeFeedSource
        {
            EpssScores = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase)
            {
                ["CVE-2024-2030"] = new EpssScore(0.55, null),
            },
            EpssQueriedAll = true,
        };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        await using var conn = await _fixture.Store.OpenAsync();
        var (score, percentile) = await conn.QuerySingleAsync<(double?, double?)>(
            "SELECT epss_score, epss_percentile FROM vulnerabilities WHERE id = @vulnId",
            new { vulnId });

        Assert.Equal(0.55, score);
        Assert.Null(percentile);
    }

    private async Task<(int? Ransomware, string? DateAdded, string? DueDate)> GetKevContextAsync(string vulnId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        var (ransomware, dateAdded, dueDate) = await conn.QuerySingleAsync<(int?, string?, string?)>(
            "SELECT kev_known_ransomware, kev_date_added, kev_due_date FROM vulnerabilities WHERE id = @vulnId",
            new { vulnId });
        return (ransomware, dateAdded, dueDate);
    }

    private async Task<(string? RequiredAction, string? Cwes, string? Notes)> GetKevRemainingFieldsAsync(string vulnId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.QuerySingleAsync<(string?, string?, string?)>(
            "SELECT kev_required_action, kev_cwes, kev_notes FROM vulnerabilities WHERE id = @vulnId",
            new { vulnId });
    }

    private async Task<string?> GetEpssCheckedAtAsync(string vulnId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT epss_checked_at FROM vulnerabilities WHERE id = @vulnId", new { vulnId });
    }

    private sealed class FakeFeedSource : IThreatFeedSource
    {
        /// <summary>Membership only, for the many tests that do not care about entry context.</summary>
        public IReadOnlySet<string> Kev
        {
            set => KevCatalog = value.ToDictionary(
                cve => cve, _ => new KevEntry(null, null, null), StringComparer.OrdinalIgnoreCase);
        }

        public Dictionary<string, KevEntry> KevCatalog { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public bool KevThrows { get; set; }
        public int KevCalls { get; private set; }
        public Dictionary<string, EpssScore> EpssScores { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string>? EpssQueried { get; set; }
        public bool EpssQueriedAll { get; set; }

        public Task<IReadOnlyDictionary<string, KevEntry>> GetKevCatalogAsync(CancellationToken ct = default)
        {
            KevCalls++;
            return KevThrows
                ? throw new HttpRequestException("KEV feed unavailable")
                : Task.FromResult<IReadOnlyDictionary<string, KevEntry>>(KevCatalog);
        }

        public Task<EpssQueryResult> GetEpssScoresAsync(IReadOnlyCollection<string> cveIds, CancellationToken ct = default)
        {
            IReadOnlySet<string> queried = EpssQueriedAll
                ? new HashSet<string>(cveIds, StringComparer.OrdinalIgnoreCase)
                : EpssQueried ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            return Task.FromResult(new EpssQueryResult(EpssScores, queried));
        }
    }

    private sealed class FakeAirGap : IAirGapMode
    {
        public FakeAirGap(bool disabled) => IsEnabled = disabled;
        public bool IsEnabled { get; }
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => IsEnabled;
    }
}
