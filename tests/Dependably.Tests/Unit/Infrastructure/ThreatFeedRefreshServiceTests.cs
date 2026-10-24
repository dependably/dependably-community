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
// FeedSignals attaches a MeterListener that enables dependably.threat_feed.rejections and
// dependably.background_job.duration by instrument name, which matches emissions from every
// parallel test against the process-wide static meter, so the class runs alone.
// See MeterSensitiveCollection.
[Trait("Category", "Unit")]
[Collection("MeterSensitive")]
public sealed class ThreatFeedRefreshServiceTests : IClassFixture<InMemoryDbFixture>, IAsyncLifetime
{
    private readonly InMemoryDbFixture _fixture;
    private readonly VulnerabilityRepository _repo;

    public ThreatFeedRefreshServiceTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _repo = new VulnerabilityRepository(_fixture.Store, TimeProvider.System);
    }

    public async Task InitializeAsync()
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync("DELETE FROM kev_catalog");
        await conn.ExecuteAsync("DELETE FROM epss_scores");
        // Flags left by other tests in this class would otherwise be the bootstrap baseline.
        await conn.ExecuteAsync("UPDATE vulnerabilities SET is_kev = 0");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private ThreatFeedRefreshService BuildService(
        IThreatFeedSource source, bool jobDisabled = false, VulnerabilityRepository? repo = null)
    {
        return new ThreatFeedRefreshService(
            repo ?? _repo,
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

        var source = new FakeFeedSource { Kev = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CVE-2024-0001", "CVE-2024-0900" } };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);
        Assert.True(await GetIsKevAsync(vulnId));

        // Catalog removal: the next pass recomputes against the new set and clears the flag.
        source.Kev = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CVE-2024-0900" };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);
        Assert.False(await GetIsKevAsync(vulnId));
    }

    [Fact]
    public async Task KevPass_PersistsCatalogue_AndReplacesItOnTheNextSuccessfulFetch()
    {
        string a = $"CVE-2031-{Random.Shared.Next(100000, 999999)}";
        string b = $"CVE-2032-{Random.Shared.Next(100000, 999999)}";
        var source = new FakeFeedSource();
        source.KevCatalog[a] = new KevEntry(true, "2031-01-01", null);
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        var stored = await _repo.GetKevCatalogEntriesAsync([a, b]);
        Assert.True(stored.ContainsKey(a));
        Assert.True(stored[a]);
        Assert.False(stored.ContainsKey(b));

        source.KevCatalog.Clear();
        source.KevCatalog[b] = new KevEntry(null, null, null);
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        stored = await _repo.GetKevCatalogEntriesAsync([a, b]);
        Assert.False(stored.ContainsKey(a));
        Assert.True(stored.ContainsKey(b));
        Assert.Null(stored[b]);
    }

    [Fact]
    public async Task ReplaceKevCatalog_LargerThanOneInsertChunk_StoresEveryEntry()
    {
        var catalog = new Dictionary<string, KevEntry>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < 450; i++)
        {
            catalog[$"CVE-2038-{1000 + i}"] = new KevEntry(i % 2 == 0, "2038-01-01", null);
        }

        await _repo.ReplaceKevCatalogAsync(catalog);

        Assert.Equal(450, await _repo.CountKevCatalogAsync());
        var sample = await _repo.GetKevCatalogEntriesAsync(["CVE-2038-1000", "CVE-2038-1001", "CVE-2038-1449"]);
        Assert.Equal(3, sample.Count);
        Assert.True(sample["CVE-2038-1000"]);
        Assert.False(sample["CVE-2038-1001"]);
    }

    [Fact]
    public async Task KevPass_FeedFailure_LeavesThePreviousCatalogueIntact()
    {
        string cve = $"CVE-2033-{Random.Shared.Next(100000, 999999)}";
        var source = new FakeFeedSource();
        source.KevCatalog[cve] = new KevEntry(false, null, null);
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        source.KevThrows = true;
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        Assert.True((await _repo.GetKevCatalogEntriesAsync([cve])).ContainsKey(cve));
    }

    [Fact]
    public async Task KevPass_AirGappedJobDisabled_FetchesNothingAndStoresNothing()
    {
        string cve = $"CVE-2034-{Random.Shared.Next(100000, 999999)}";
        var source = new FakeFeedSource();
        source.KevCatalog[cve] = new KevEntry(null, null, null);

        await BuildService(source, jobDisabled: true).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(0, source.KevCalls);
        Assert.Empty(await _repo.GetKevCatalogEntriesAsync([cve]));
    }

    [Fact]
    public async Task KevPass_EmptyCatalogue_IsTreatedAsFailedFetch_KeepsCatalogueAndFlags()
    {
        string cve = $"CVE-2035-{Random.Shared.Next(100000, 999999)}";
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-kevempty-{Guid.NewGuid():N}", aliases: $"[\"{cve}\"]");
        var source = new FakeFeedSource();
        source.KevCatalog[cve] = new KevEntry(null, null, null);
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);
        Assert.True(await GetIsKevAsync(vulnId));

        source.KevCatalog.Clear();
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        Assert.True(await GetIsKevAsync(vulnId));
        Assert.True((await _repo.GetKevCatalogEntriesAsync([cve])).ContainsKey(cve));
    }

    [Fact]
    public async Task KevPass_DrasticShrink_IsTreatedAsFailedFetch_ButNormalUpdateIsApplied()
    {
        var source = new FakeFeedSource();
        for (int i = 0; i < 10; i++)
        {
            source.KevCatalog[$"CVE-2036-{1000 + i}"] = new KevEntry(null, null, null);
        }

        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);
        Assert.Equal(10, await _repo.CountKevCatalogAsync());

        // 4 of 10 is under half: rejected, previous copy kept.
        source.KevCatalog = source.KevCatalog.Take(4).ToDictionary(p => p.Key, p => p.Value, StringComparer.OrdinalIgnoreCase);
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);
        Assert.Equal(10, await _repo.CountKevCatalogAsync());

        // 6 of 10 (and one new entry) is an ordinary update: applied.
        source.KevCatalog["CVE-2036-9999"] = new KevEntry(null, null, null);
        source.KevCatalog["CVE-2036-1005"] = new KevEntry(null, null, null);
        source.KevCatalog["CVE-2036-1006"] = new KevEntry(null, null, null);
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);
        Assert.Equal(7, await _repo.CountKevCatalogAsync());
    }

    // ── The EPSS bulk file ────────────────────────────────────────────────────────────────

    private static Dictionary<string, EpssScore> Bulk(int count, int year = 2040, double probability = 0.1)
    {
        var scores = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < count; i++)
        {
            scores[$"CVE-{year}-{1000 + i}"] = new EpssScore(probability, 0.5);
        }

        return scores;
    }

    [Fact]
    public async Task EpssBulk_PersistsEveryScore_ForCvesNoAdvisoryRowNames_AndReplacesThemOnTheNextFetch()
    {
        // More than one insert chunk, so the multi-row insert path is exercised, not just the first.
        var source = new FakeFeedSource { BulkScores = Bulk(600) };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(600, await _repo.CountEpssScoresAsync());
        var stored = await _repo.GetStoredEpssScoresAsync(["cve-2040-1000", "CVE-2040-1599", "CVE-2040-9999"]);
        Assert.Equal(2, stored.Count);
        Assert.Equal(0.1, stored["CVE-2040-1000"].Probability);
        Assert.Equal(0.5, stored["CVE-2040-1000"].Percentile);

        source.BulkScores = Bulk(600, probability: 0.7);
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);
        Assert.Equal(600, await _repo.CountEpssScoresAsync());
        Assert.Equal(0.7, (await _repo.GetStoredEpssScoresAsync(["CVE-2040-1000"]))["CVE-2040-1000"].Probability);
    }

    [Fact]
    public async Task EpssBulk_Replace_RewritesOnlyRowsWhoseScoreOrPercentileChanged()
    {
        var first = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase)
        {
            ["CVE-2052-0001"] = new EpssScore(0.1, 0.2),
            ["CVE-2052-0002"] = new EpssScore(0.3, 0.4),
            ["CVE-2052-0003"] = new EpssScore(0.5, null),
            ["CVE-2052-0004"] = new EpssScore(0.6, 0.7),
        };
        await _repo.ReplaceEpssScoresAsync(first, "2026-10-05");

        var second = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase)
        {
            ["CVE-2052-0001"] = new EpssScore(0.1, 0.2),
            ["CVE-2052-0002"] = new EpssScore(0.35, 0.4),
            ["CVE-2052-0003"] = new EpssScore(0.5, 0.9),
            ["CVE-2052-0005"] = new EpssScore(0.8, 0.8),
        };
        await _repo.ReplaceEpssScoresAsync(second, "2026-10-06");

        await using var conn = await _fixture.Store.OpenAsync();
        var rows = (await conn.QueryAsync<(string Cve, double Epss, double? Pct, string? Date)>(
            "SELECT cve_id, epss, percentile, score_date FROM epss_scores ORDER BY cve_id")).ToList();
        Assert.Equal(
            [
                ("CVE-2052-0001", 0.1, (double?)0.2, (string?)"2026-10-05"),
                ("CVE-2052-0002", 0.35, 0.4, "2026-10-06"),
                ("CVE-2052-0003", 0.5, 0.9, "2026-10-06"),
                ("CVE-2052-0005", 0.8, 0.8, "2026-10-06"),
            ],
            rows);
    }

    [Fact]
    public async Task EpssBulk_EmptyFetch_KeepsTheLastGoodScores()
    {
        var source = new FakeFeedSource { BulkScores = Bulk(10) };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        source.BulkScores = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase);
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(10, await _repo.CountEpssScoresAsync());
    }

    [Fact]
    public async Task EpssBulk_DrasticShrink_IsRejected_ButANormalUpdateIsApplied()
    {
        var source = new FakeFeedSource { BulkScores = Bulk(10) };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        // 4 of 10 is under half: rejected.
        source.BulkScores = Bulk(4, probability: 0.9);
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);
        Assert.Equal(10, await _repo.CountEpssScoresAsync());
        Assert.Equal(0.1, (await _repo.GetStoredEpssScoresAsync(["CVE-2040-1000"]))["CVE-2040-1000"].Probability);

        // 6 of 10 is an ordinary update: applied.
        source.BulkScores = Bulk(6, probability: 0.9);
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);
        Assert.Equal(6, await _repo.CountEpssScoresAsync());
    }

    [Fact]
    public async Task EpssBulk_FetchFailure_KeepsTheLastGoodScores_AndDoesNotAbortTheRestOfThePass()
    {
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-bulkfail-{Guid.NewGuid():N}", aliases: """["CVE-2024-6000"]""");
        var source = new FakeFeedSource { BulkScores = Bulk(10) };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        source.BulkThrows = true;
        source.Kev = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CVE-2024-6000" };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(10, await _repo.CountEpssScoresAsync());
        Assert.True(await GetIsKevAsync(vulnId));
    }

    [Fact]
    public async Task EpssBulk_ReplaceFailure_IsADegradedRun_KeepsTheLastGoodScores_AndKevStillApplies()
    {
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-replfail-{Guid.NewGuid():N}", aliases: """["CVE-2024-6100"]""");
        var source = new FakeFeedSource { BulkScores = Bulk(10) };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);
        Assert.Equal(10, await _repo.CountEpssScoresAsync());

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "CREATE TRIGGER epss_staging_fail BEFORE INSERT ON epss_scores_staging BEGIN SELECT RAISE(ABORT, 'staging unavailable'); END");
        }

        try
        {
            using var signals = new FeedSignals();
            source.BulkScores = Bulk(12, probability: 0.9);
            source.Kev = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CVE-2024-6100" };
            await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

            Assert.Contains("epss_replace_failed", signals.Reasons);
            Assert.Equal(["degraded"], signals.ThreatFeedOutcomes);
            Assert.Equal(10, await _repo.CountEpssScoresAsync());
            Assert.True(await GetIsKevAsync(vulnId));
        }
        finally
        {
            await using var conn = await _fixture.Store.OpenAsync();
            await conn.ExecuteAsync("DROP TRIGGER IF EXISTS epss_staging_fail");
        }
    }

    private async Task<(double? Epss, double? Percentile)> GetEpssPairAsync(string vulnId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.QuerySingleAsync<(double?, double?)>(
            "SELECT epss_score, epss_percentile FROM vulnerabilities WHERE id = @vulnId", new { vulnId });
    }

    [Fact]
    public async Task EpssBulk_FillsAnAdvisoryStoredBeforeTheFile_AndTheGateAndTheLookupAgree()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"epss-fill-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", $"fill-{Guid.NewGuid():N}");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", $"pkg:npm/{Guid.NewGuid():N}@1.0.0");
        string cve = $"CVE-2061-{Random.Shared.Next(100000, 999999)}";
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-fill-{Guid.NewGuid():N}", aliases: $"""["{cve}"]""");
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, verId, vulnId);
        Assert.Equal((null, null), await GetEpssPairAsync(vulnId));

        // The per-CVE API pass scores nothing: only the bulk file knows this CVE.
        var source = new FakeFeedSource { BulkScores = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase) { [cve] = new EpssScore(0.8, 0.97) } };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal((0.8, 0.97), await GetEpssPairAsync(vulnId));
        var signals = await _repo.GetGateSignalsForVersionAsync(verId);
        var verdict = BlockGateService.Evaluate(
            new VersionFacts(
                ManualState: null,
                Deprecated: null,
                PublishedAt: null,
                Scanned: true,
                // vuln-facts-ok: the gate verdict is evaluated over the repository's own aggregate.
                Vulnerability: signals.Facts,
                Origin: "proxy",
                HasInstallScript: false,
                ProvenanceStatus: null,
                InstallScriptAllowlisted: false,
                RevokedAt: null),
            new BlockPolicy(
                MinReleaseAgeHours: null,
                BlockDeprecatedMode: null,
                BlockMaliciousMode: null,
                BlockKevMode: null,
                MaxEpssTolerance: 0.5,
                MaxOsvScoreTolerance: 10.0),
            TimeProvider.System.GetUtcNow());
        Assert.False(verdict.Servable);
        Assert.Equal(BlockArm.Epss, verdict.Arm);
        var lookup = await _repo.GetStoredEpssScoresAsync([cve]);
        Assert.Equal(lookup[cve].Probability, signals.Facts.Epss);
    }

    [Fact]
    public async Task EpssBulk_Fill_TakesTheHighestProbabilityAcrossIdAndAliases_WithItsOwnPercentile_AndNeverOverwrites()
    {
        string suffix = Random.Shared.Next(100000, 999999).ToString();
        string own = $"CVE-2062-{suffix}";
        string other = $"CVE-2063-{suffix}";
        string unscoredAlias = $"CVE-2064-{suffix}";
        string paired = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, own, aliases: $"""["{other}","{unscoredAlias}"]""");
        string known = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-known-{suffix}", aliases: $"""["{other}"]""", epssScore: 0.2);
        string unknown = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-unknown-{suffix}", aliases: $"""["CVE-2065-{suffix}"]""");

        var source = new FakeFeedSource
        {
            BulkScores = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase)
            {
                [own] = new EpssScore(0.3, 0.99),
                [other] = new EpssScore(0.7, 0.60),
            },
        };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal((0.7, 0.60), await GetEpssPairAsync(paired));
        Assert.Equal(0.2, (await GetEpssPairAsync(known)).Epss);
        Assert.Equal((null, null), await GetEpssPairAsync(unknown));
    }

    [Fact]
    public async Task EpssBulk_FillFailure_IsADegradedRun_KeepsTheNewScores_AndLeavesTheAdvisoryUnscored()
    {
        string cve = $"CVE-2066-{Random.Shared.Next(100000, 999999)}";
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-fillfail-{Guid.NewGuid():N}", aliases: $"""["{cve}"]""");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "CREATE TRIGGER epss_fill_fail BEFORE UPDATE OF epss_score ON vulnerabilities BEGIN SELECT RAISE(ABORT, 'fill unavailable'); END");
        }

        try
        {
            using var signals = new FeedSignals();
            var source = new FakeFeedSource { BulkScores = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase) { [cve] = new EpssScore(0.8, 0.97) } };
            await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

            Assert.Contains("epss_fill_failed", signals.Reasons);
            Assert.Equal(["degraded"], signals.ThreatFeedOutcomes);
            Assert.Equal(1, await _repo.CountEpssScoresAsync());
            Assert.Equal((null, null), await GetEpssPairAsync(vulnId));
        }
        finally
        {
            await using var conn = await _fixture.Store.OpenAsync();
            await conn.ExecuteAsync("DROP TRIGGER IF EXISTS epss_fill_fail");
        }

        await BuildService(new FakeFeedSource { BulkScores = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase) { [cve] = new EpssScore(0.8, 0.97) } })
            .RunRefreshPassAsync(CancellationToken.None);
        Assert.Equal((0.8, 0.97), await GetEpssPairAsync(vulnId));
    }

    [Fact]
    public async Task EpssBulk_AirGapped_MakesNoCall_AndLeavesTheTableAsItWas()
    {
        var source = new FakeFeedSource { BulkScores = Bulk(10) };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        source.BulkScores = Bulk(20, probability: 0.9);
        await BuildService(source, jobDisabled: true).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(1, source.BulkCalls);
        Assert.Equal(10, await _repo.CountEpssScoresAsync());
    }

    [Fact]
    public async Task EpssBulk_AirGappedFromTheStart_LeavesTheTableEmpty()
    {
        var source = new FakeFeedSource { BulkScores = Bulk(10) };
        await BuildService(source, jobDisabled: true).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(0, source.BulkCalls);
        Assert.Equal(0, await _repo.CountEpssScoresAsync());
    }

    // ── A rejected feed is visible beyond a log line ─────────────────────────────────────

    // Captures what the pass emits for the job outcome and the rejection counter.
    private sealed class FeedSignals : IDisposable
    {
        private readonly System.Diagnostics.Metrics.MeterListener _listener = new();
        public List<string> Reasons { get; } = [];
        public List<string> ThreatFeedOutcomes { get; } = [];

        public FeedSignals()
        {
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Name is "dependably.threat_feed.rejections" or "dependably.background_job.duration")
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            };
            _listener.SetMeasurementEventCallback<long>((instrument, _, tags, _) =>
            {
                foreach (var tag in tags)
                {
                    if (tag.Key == "reason")
                    {
                        lock (Reasons)
                        {
                            Reasons.Add((string)tag.Value!);
                        }
                    }
                }
            });
            _listener.SetMeasurementEventCallback<double>((instrument, _, tags, _) =>
            {
                string? job = null, outcome = null;
                foreach (var tag in tags)
                {
                    if (tag.Key == "job_name")
                    {
                        job = (string?)tag.Value;
                    }
                    else if (tag.Key == "outcome")
                    {
                        outcome = (string?)tag.Value;
                    }
                }

                if (job == "threat-feed" && outcome is not null)
                {
                    lock (ThreatFeedOutcomes)
                    {
                        ThreatFeedOutcomes.Add(outcome);
                    }
                }
            });
            _listener.Start();
        }

        public void Dispose() => _listener.Dispose();
    }

    [Fact]
    public async Task EmptyKevFetch_IsRecordedAsADegradedRun_AndCounted()
    {
        using var signals = new FeedSignals();
        var source = new FakeFeedSource { BulkScores = Bulk(5) };
        source.KevCatalog.Clear();

        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        Assert.Contains("kev_empty", signals.Reasons);
        Assert.Equal(["degraded"], signals.ThreatFeedOutcomes);
    }

    [Fact]
    public async Task ShrunkKevFetch_IsRecordedAsADegradedRun_WithItsOwnReason()
    {
        var source = new FakeFeedSource { BulkScores = Bulk(5) };
        for (int i = 0; i < 10; i++)
        {
            source.KevCatalog[$"CVE-2041-{1000 + i}"] = new KevEntry(null, null, null);
        }

        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        using var signals = new FeedSignals();
        source.KevCatalog = source.KevCatalog.Take(3).ToDictionary(p => p.Key, p => p.Value, StringComparer.OrdinalIgnoreCase);
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        Assert.Contains("kev_shrunk", signals.Reasons);
        Assert.Equal(["degraded"], signals.ThreatFeedOutcomes);
    }

    [Fact]
    public async Task KevFetchFailure_AndEpssBulkRejection_AreBothReported_InOneRun()
    {
        // Mixed outcome: the KEV fetch throws, the EPSS file is empty. Neither feed is applied and
        // both are named, rather than the first masking the second.
        using var signals = new FeedSignals();
        var source = new FakeFeedSource { KevThrows = true };

        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        Assert.Contains("kev_fetch_failed", signals.Reasons);
        Assert.Contains("epss_empty", signals.Reasons);
        Assert.Equal(["degraded"], signals.ThreatFeedOutcomes);
    }

    [Fact]
    public async Task AcceptedFeeds_AreRecordedAsASuccess_AndCountNothing()
    {
        using var signals = new FeedSignals();
        var source = new FakeFeedSource { BulkScores = Bulk(5) };
        source.KevCatalog["CVE-2042-1000"] = new KevEntry(null, null, null);

        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        Assert.Empty(signals.Reasons);
        Assert.Equal(["success"], signals.ThreatFeedOutcomes);
    }

    // ── Bootstrap: an empty stored catalogue is not an unguarded first fetch ──────────────

    [Fact]
    public async Task KevBootstrap_FirstFetchFarBelowTheAlreadyFlaggedRows_IsRejected_AndFlagsSurvive()
    {
        var flagged = new List<string>();
        for (int i = 0; i < 10; i++)
        {
            flagged.Add(await VulnerabilitySeeder.InsertVulnAsync(
                _fixture.Store, $"GHSA-boot-{Guid.NewGuid():N}", aliases: $"[\"CVE-2043-{1000 + i}\"]", isKev: true));
        }

        Assert.Equal(0, await _repo.CountKevCatalogAsync());
        var source = new FakeFeedSource { BulkScores = Bulk(5) };
        source.KevCatalog["CVE-2043-9999"] = new KevEntry(null, null, null);

        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        // One degenerate entry against ten flagged rows: nothing written, no flag cleared.
        Assert.Equal(0, await _repo.CountKevCatalogAsync());
        foreach (string id in flagged)
        {
            Assert.True(await GetIsKevAsync(id));
        }
    }

    [Fact]
    public async Task KevBootstrap_SeveralAdvisoryRowsPerCve_AreNotMistakenForAShrunkCatalogue()
    {
        // Three CVEs, each reached through five advisory rows (the CVE record, a GHSA record and
        // distro records): fifteen flagged rows behind three catalogue entries. The guard compares
        // CVEs with CVEs, so the legitimate three-entry fetch is applied.
        var flagged = new List<string>();
        for (int cve = 0; cve < 3; cve++)
        {
            string cveId = $"CVE-2046-{1000 + cve}";
            flagged.Add(await VulnerabilitySeeder.InsertVulnAsync(_fixture.Store, cveId, isKev: true));
            for (int row = 0; row < 4; row++)
            {
                flagged.Add(await VulnerabilitySeeder.InsertVulnAsync(
                    _fixture.Store, $"GHSA-multi-{cve}-{row}-{Guid.NewGuid():N}", aliases: $"[\"{cveId}\"]", isKev: true));
            }
        }

        Assert.Equal(3, await _repo.CountKevFlaggedCvesAsync());
        var source = new FakeFeedSource { BulkScores = Bulk(5) };
        for (int cve = 0; cve < 3; cve++)
        {
            source.KevCatalog[$"CVE-2046-{1000 + cve}"] = new KevEntry(null, null, null);
        }

        using var signals = new FeedSignals();
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        Assert.DoesNotContain("kev_shrunk", signals.Reasons);
        Assert.Equal(3, await _repo.CountKevCatalogAsync());
        foreach (string id in flagged)
        {
            Assert.True(await GetIsKevAsync(id));
        }
    }

    [Fact]
    public async Task CountKevFlaggedCves_CountsEachCveOnce_AcrossIdsAndAliases_AndIgnoresUnflaggedRows()
    {
        await VulnerabilitySeeder.InsertVulnAsync(_fixture.Store, "CVE-2047-0001", isKev: true);
        await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-cnt-{Guid.NewGuid():N}", aliases: """["CVE-2047-0001","cve-2047-0002"]""", isKev: true);
        await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-cnt-{Guid.NewGuid():N}", aliases: """["CVE-2047-0003"]""", isKev: false);
        await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-cnt-{Guid.NewGuid():N}", aliases: """["GHSA-other-0001"]""", isKev: true);

        Assert.Equal(2, await _repo.CountKevFlaggedCvesAsync());
    }

    [Fact]
    public async Task CountKevFlaggedCves_OnceTheCatalogueIsPopulated_CountsOnlyCvesTheCatalogueHolds()
    {
        // A flagged GHSA aliases one catalogued CVE and one that is not in the catalogue.
        await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-base-{Guid.NewGuid():N}",
            aliases: """["CVE-2048-0001","CVE-2048-0002"]""", isKev: true);
        await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-base-{Guid.NewGuid():N}", aliases: """["cve-2048-0003"]""", isKev: true);

        // Bootstrap: the catalogue is empty, so every flagged CVE is the baseline.
        Assert.Equal(3, await _repo.CountKevFlaggedCvesAsync());

        await _repo.ReplaceKevCatalogAsync(
            new Dictionary<string, KevEntry>(StringComparer.OrdinalIgnoreCase)
            {
                ["CVE-2048-0001"] = new KevEntry(null, null, null),
                ["CVE-2048-0003"] = new KevEntry(null, null, null),
                ["CVE-2048-0009"] = new KevEntry(null, null, null),
            });

        // Populated: the non-catalogued CVE-2048-0002 no longer counts.
        Assert.Equal(2, await _repo.CountKevFlaggedCvesAsync());
    }

    // ── Alias-index reconcile failure ─────────────────────────────────────────────────────

    [Fact]
    public async Task AliasReconcileFailure_DoesNotSkipTheFeeds_AndIsReportedAsADegradedRun()
    {
        // A store of its own: the fault is a trigger that makes the reconcile's alias-row delete
        // fail, the shape of a database deadlock between the reconcile and a concurrent upsert.
        var store = new TestMetadataStore();
        await new SchemaInitializer(store).InitializeAsync();
        var repo = new VulnerabilityRepository(store, TimeProvider.System);
        await VulnerabilitySeeder.InsertVulnAsync(store, "GHSA-recon-0001", aliases: """["CVE-2048-0001"]""");
        await using (var conn = await store.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE vulnerabilities SET aliases = '[\"CVE-2048-0002\"]' WHERE osv_id = 'GHSA-recon-0001'");
            await conn.ExecuteAsync(
                "CREATE TRIGGER fail_alias_delete BEFORE DELETE ON vulnerability_aliases BEGIN SELECT RAISE(ABORT, 'simulated deadlock'); END");
        }

        await Assert.ThrowsAnyAsync<Exception>(() => repo.ReconcileAliasIndexAsync());

        var source = new FakeFeedSource { BulkScores = Bulk(5) };
        source.KevCatalog["CVE-2048-0002"] = new KevEntry(null, null, null);
        using var signals = new FeedSignals();

        await BuildService(source, repo: repo).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(1, source.KevCalls);
        Assert.Equal(1, source.BulkCalls);
        Assert.Equal(1, await repo.CountKevCatalogAsync());
        Assert.Equal(5, await repo.CountEpssScoresAsync());
        Assert.Contains("alias_reconcile_failed", signals.Reasons);
        Assert.Equal(["degraded"], signals.ThreatFeedOutcomes);
    }

    [Fact]
    public async Task KevBootstrap_APlausibleFirstFetch_IsApplied()
    {
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-bootok-{Guid.NewGuid():N}", aliases: """["CVE-2044-1000"]""", isKev: true);
        var source = new FakeFeedSource { BulkScores = Bulk(5) };
        source.KevCatalog["CVE-2044-1000"] = new KevEntry(null, null, null);
        source.KevCatalog["CVE-2044-1001"] = new KevEntry(null, null, null);

        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(2, await _repo.CountKevCatalogAsync());
        Assert.True(await GetIsKevAsync(vulnId));
    }

    [Fact]
    public async Task KevBootstrap_WithNothingFlaggedAndNothingStored_AppliesTheFirstFetch()
    {
        var source = new FakeFeedSource { BulkScores = Bulk(5) };
        source.KevCatalog["CVE-2045-1000"] = new KevEntry(null, null, null);

        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        Assert.Equal(1, await _repo.CountKevCatalogAsync());
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
    public async Task EpssPass_NoApiScore_NeverReplacesAKnownScoreAndPercentileWithNull()
    {
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-epss-keep-{Guid.NewGuid():N}", aliases: """["CVE-2024-7000"]""");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            // The state the upsert leaves behind when the stored EPSS file already knew the CVE.
            await conn.ExecuteAsync(
                "UPDATE vulnerabilities SET epss_score = 0.7, epss_percentile = 0.9 WHERE id = @vulnId", new { vulnId });
        }

        // FIRST's API was reached and has no score for the CVE.
        var source = new FakeFeedSource { EpssQueriedAll = true };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        await using var read = await _fixture.Store.OpenAsync();
        var (score, percentile) = await read.QuerySingleAsync<(double?, double?)>(
            "SELECT epss_score, epss_percentile FROM vulnerabilities WHERE id = @vulnId", new { vulnId });
        Assert.Equal(0.7, score);
        Assert.Equal(0.9, percentile);
        // The pass still records that it asked, so the row is not retried forever.
        Assert.NotNull(await GetEpssCheckedAtAsync(vulnId));
    }

    [Fact]
    public async Task EpssPass_AnApiScore_ReplacesTheStoredPair_Together()
    {
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, $"GHSA-epss-pair-{Guid.NewGuid():N}", aliases: """["CVE-2024-7001"]""");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE vulnerabilities SET epss_score = 0.7, epss_percentile = 0.9 WHERE id = @vulnId", new { vulnId });
        }

        var source = new FakeFeedSource
        {
            EpssScores = new Dictionary<string, EpssScore>(StringComparer.OrdinalIgnoreCase)
            {
                ["CVE-2024-7001"] = new EpssScore(0.2, null),
            },
            EpssQueriedAll = true,
        };
        await BuildService(source).RunRefreshPassAsync(CancellationToken.None);

        await using var read = await _fixture.Store.OpenAsync();
        var (score, percentile) = await read.QuerySingleAsync<(double?, double?)>(
            "SELECT epss_score, epss_percentile FROM vulnerabilities WHERE id = @vulnId", new { vulnId });
        Assert.Equal(0.2, score);
        Assert.Null(percentile);
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
                ["CVE-2024-2999"] = new KevEntry(null, null, null),
            },
        };
        await BuildService(present).RunRefreshPassAsync(CancellationToken.None);
        Assert.Equal(1, (await GetKevContextAsync(vulnId)).Ransomware);
        Assert.Equal("Apply the vendor patch.", (await GetKevRemainingFieldsAsync(vulnId)).RequiredAction);

        await BuildService(new FakeFeedSource { Kev = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "CVE-2024-2999" } })
            .RunRefreshPassAsync(CancellationToken.None);

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

        public Dictionary<string, EpssScore> BulkScores { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public string? BulkScoreDate { get; set; } = "2031-05-01";
        public bool BulkThrows { get; set; }
        public int BulkCalls { get; private set; }

        public Task<EpssBulkFile> GetEpssBulkAsync(CancellationToken ct = default)
        {
            BulkCalls++;
            return BulkThrows
                ? throw new HttpRequestException("EPSS bulk file unavailable")
                : Task.FromResult(new EpssBulkFile(BulkScores, BulkScoreDate));
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
