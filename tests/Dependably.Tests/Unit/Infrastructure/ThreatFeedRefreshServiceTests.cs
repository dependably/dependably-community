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
        _repo = new VulnerabilityRepository(_fixture.Store);
    }

    private ThreatFeedRefreshService BuildService(IThreatFeedSource source, bool jobDisabled = false)
    {
        return new ThreatFeedRefreshService(
            _repo,
            source,
            new ConfigurationBuilder().Build(),
            new FakeAirGap(jobDisabled),
            NullLogger<ThreatFeedRefreshService>.Instance);
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
            EpssScores = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase)
            {
                ["CVE-2024-1000"] = 0.12,
                ["CVE-2024-1001"] = 0.83,
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
            EpssScores = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase) { ["CVE-2024-3000"] = 0.5 },
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
            EpssScores = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase) { ["CVE-2024-5000"] = 0.9 },
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

    private async Task<string?> GetEpssCheckedAtAsync(string vulnId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT epss_checked_at FROM vulnerabilities WHERE id = @vulnId", new { vulnId });
    }

    private sealed class FakeFeedSource : IThreatFeedSource
    {
        public IReadOnlySet<string> Kev { get; set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public bool KevThrows { get; set; }
        public int KevCalls { get; private set; }
        public Dictionary<string, double> EpssScores { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string>? EpssQueried { get; set; }
        public bool EpssQueriedAll { get; set; }

        public Task<IReadOnlySet<string>> GetKevCveIdsAsync(CancellationToken ct = default)
        {
            KevCalls++;
            return KevThrows
                ? throw new HttpRequestException("KEV feed unavailable")
                : Task.FromResult(Kev);
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
