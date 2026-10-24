using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Startup;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The apply marker that keeps the upsert-time EPSS stamp off while a refresh applies the file
/// must stay fresh for as long as the apply runs, and a failed apply must not leave the
/// advisories whose stamp it skipped unscored. Runs on a file-backed database with a clock that
/// jumps at every pause, so a long apply is exercised without waiting for one.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EpssApplyMarkerTests : IAsyncLifetime
{
    private const int Rows = 3_000;

    private readonly string _dbFile = Path.Combine(Path.GetTempPath(), $"dependably_epss_marker_{Guid.NewGuid():N}.db");
    private SqliteMetadataStore _store = null!;

    public async Task InitializeAsync()
    {
        _store = new SqliteMetadataStore(StorageStartupExtensions.BuildSqliteConnectionString(_dbFile));
        await new SchemaInitializer(_store).InitializeAsync();
    }

    public Task DisposeAsync()
    {
        SqliteConnection.ClearAllPools();
        foreach (string suffix in new[] { "", "-wal", "-shm" })
        {
            File.Delete(_dbFile + suffix);
        }

        return Task.CompletedTask;
    }

    private static Dictionary<string, EpssScore> Scores(double probability)
    {
        var scores = new Dictionary<string, EpssScore>(Rows, StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < Rows; i++)
        {
            scores[$"CVE-2050-{i}"] = new EpssScore(probability, 0.5);
        }

        return scores;
    }

    private string? ReadMarker()
    {
        using var conn = _store.OpenAsync().GetAwaiter().GetResult();
        return conn.ExecuteScalar<string?>(
            "SELECT value FROM instance_settings WHERE key = @key", new { key = VulnerabilityRepository.EpssApplyMarkerKey });
    }

    [Fact]
    public async Task ALongApply_RefreshesTheMarkerAtTheRefreshInterval_AndClearsItAtTheEnd()
    {
        await using (var conn = await _store.OpenAsync())
        {
            await conn.ExecuteAsync("CREATE TABLE marker_writes (n INTEGER PRIMARY KEY AUTOINCREMENT)");
            await conn.ExecuteAsync(
                """
                CREATE TRIGGER marker_inserted AFTER INSERT ON instance_settings
                WHEN NEW.key = 'epss_apply_in_progress_since' BEGIN INSERT INTO marker_writes (n) VALUES (NULL); END
                """);
            await conn.ExecuteAsync(
                """
                CREATE TRIGGER marker_updated AFTER UPDATE ON instance_settings
                WHEN NEW.key = 'epss_apply_in_progress_since' BEGIN INSERT INTO marker_writes (n) VALUES (NULL); END
                """);
        }

        var fake = TestTime.Frozen();
        int pausesWhileMarked = 0;
        var clock = new SteppingClock(fake, TimeSpan.FromMinutes(2), () =>
        {
            if (ReadMarker() is not null)
            {
                pausesWhileMarked++;
            }
        });
        var repo = new VulnerabilityRepository(_store, clock);
        await new VulnerabilityRepository(_store, TimeProvider.System).ReplaceEpssScoresAsync(Scores(0.1), "2026-10-05");
        await using var counter = await _store.OpenAsync();
        int before = await counter.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM marker_writes");

        await repo.ReplaceEpssScoresAsync(Scores(0.9), "2026-10-06");

        // The apply paused for longer than the marker's expiry, and every two-minute pause that
        // found the marker present was followed by a re-stamp.
        Assert.True(TimeSpan.FromMinutes(2) * pausesWhileMarked > VulnerabilityRepository.EpssApplyMarkerExpiry);
        int writes = await counter.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM marker_writes") - before;
        Assert.True(writes >= 1 + pausesWhileMarked, $"marker was written {writes} times over {pausesWhileMarked} pauses");
        Assert.Null(ReadMarker());
    }

    [Theory]
    [InlineData(-10)]
    [InlineData(10)]
    public async Task AReplicaWhoseClockDiffers_StillSeesTheApplyMarker(int writerSkewMinutes)
    {
        await new VulnerabilityRepository(_store, TimeProvider.System).ReplaceEpssScoresAsync(Scores(0.1), "2026-10-05");

        var readerClock = TestTime.Frozen();
        var reader = new VulnerabilityRepository(_store, readerClock);
        var writerFake = TestTime.Frozen(readerClock.GetUtcNow().AddMinutes(writerSkewMinutes));
        double? scoredDuringApply = -1;
        int pause = 0;
        var writerClock = new SteppingClock(writerFake, TimeSpan.FromSeconds(1), () =>
        {
            if (pause > 0 || ReadMarker() is null)
            {
                return;
            }

            pause++;

            reader.UpsertVulnerabilityAsync(Advisory("CVE-2050-9"), "npm", "pkg").GetAwaiter().GetResult();
            using var conn = _store.OpenAsync().GetAwaiter().GetResult();
            scoredDuringApply = conn.ExecuteScalar<double?>(
                "SELECT epss_score FROM vulnerabilities WHERE osv_id = 'CVE-2050-9'");
        });
        var writer = new VulnerabilityRepository(_store, writerClock);

        await writer.ReplaceEpssScoresAsync(Scores(0.9), "2026-10-06");

        // The other replica's upsert ran mid-apply: a marker it can read must keep the stamp off,
        // however far apart the two app clocks are.
        Assert.NotEqual(-1, scoredDuringApply);
        Assert.Null(scoredDuringApply);
    }

    private static OsvAdvisory Advisory(string id) => new(
        Id: id,
        Aliases: [],
        Summary: "advisory",
        Severity: "LOW",
        CvssScore: 2.0,
        AffectedPackages: [new OsvAffectedPackage("pkg:npm/pkg", "npm", "pkg", ["1.0.0"])],
        Published: "2026-01-01T00:00:00Z",
        Modified: "2026-01-02T00:00:00Z",
        IsHydrated: true);

    [Fact]
    public async Task AnApplyThatFailsMidWay_ScoresTheAdvisoriesItSkipped_AndStillThrows()
    {
        var repoSetup = new VulnerabilityRepository(_store, TimeProvider.System);
        await repoSetup.ReplaceEpssScoresAsync(Scores(0.1), "2026-10-05");
        await using (var conn = await _store.OpenAsync())
        {
            // An advisory saved while the apply was running: its stamp was skipped, so it is unscored.
            await conn.ExecuteAsync(
                "INSERT INTO vulnerabilities (id, osv_id, ecosystem, package_name) VALUES ('CVE-2050-7', 'CVE-2050-7', 'npm', 'pkg')");
        }

        var fake = TestTime.Frozen();
        int applyPauses = 0;
        bool thrown = false;
        var clock = new SteppingClock(fake, TimeSpan.FromSeconds(1), () =>
        {
            if (!thrown && ReadMarker() is not null && ++applyPauses == 2)
            {
                thrown = true;
                throw new InvalidOperationException("injected apply failure");
            }
        });
        var repo = new VulnerabilityRepository(_store, clock);

        await Assert.ThrowsAsync<InvalidOperationException>(() => repo.ReplaceEpssScoresAsync(Scores(0.9), "2026-10-06"));

        Assert.True(thrown);
        Assert.Null(ReadMarker());
        await using var check = await _store.OpenAsync();
        Assert.NotNull(await check.ExecuteScalarAsync<double?>("SELECT epss_score FROM vulnerabilities WHERE osv_id = 'CVE-2050-7'"));
    }

    // Jumps the fake clock at every pause and lets the pause finish at once; once a hook has thrown
    // (or after it runs) waits are real, so budgets that use the clock are not fired instantly.
    private sealed class SteppingClock(FakeTimeProvider fake, TimeSpan step, Action atPause) : TimeProvider
    {
        private bool _passthrough;

        public override DateTimeOffset GetUtcNow() => fake.GetUtcNow();
        public override long GetTimestamp() => fake.GetTimestamp();
        public override long TimestampFrequency => fake.TimestampFrequency;
        public override TimeZoneInfo LocalTimeZone => fake.LocalTimeZone;

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            if (_passthrough)
            {
                return System.CreateTimer(callback, state, dueTime, period);
            }

            try
            {
                atPause();
            }
            catch
            {
                _passthrough = true;
                throw;
            }

            fake.Advance(step);
            return System.CreateTimer(callback, state, TimeSpan.Zero, period);
        }
    }
}
