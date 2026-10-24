using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The rescan runs on its own short schedule, ticking until the completion marker exists and then
/// ending, instead of one bounded tick per daily licence-backfill pass.
/// </summary>
[Trait("Category", "Unit")]
public sealed class NpmManifestRescanServiceTests : IAsyncLifetime
{
    private const string Clean = """{"name":"p","version":"1.0.0","license":"MIT"}""";
    private const string Evil = """{"name":"p","version":"1.0.0","scripts":{"postinstall":"x"}}""";
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly InMemoryBlobStore _blobs = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private NpmManifestRescanService Build(
        IBlobStore store, RecordingLogger<NpmManifestRescan> rescanLog, IDictionary<string, string?>? settings = null)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(settings ?? new Dictionary<string, string?>()).Build();
        return new NpmManifestRescanService(
            new NpmManifestRescan(_db, new TieredBlobStorage(store, store), _clock, rescanLog),
            new AirGapMode(config),
            config,
            NullLogger<NpmManifestRescanService>.Instance,
            _clock,
            new InProcessDistributedLock(_clock));
    }

    private async Task<string> SeedCacheAsync(string name, string key, byte[] bytes)
    {
        await _blobs.PutAsync(key, new MemoryStream(bytes));
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, license_checked_at)
            VALUES (@id, 'npm', @name, '1.0.0', @name || '-1.0.0.tgz', @key, 'h', '2026-01-01T00:00:00Z')
            """, new { id, name, key });
        return id;
    }

    private async Task<string?> KindAsync(string id)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<string?>("SELECT install_script_kind FROM cache_artifact WHERE id = @id", new { id });
    }

    private async Task<bool> MarkerExistsAsync()
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM instance_settings WHERE key = @key", new { key = NpmManifestRescan.MarkerKey }) > 0;
    }

    // Advances the fake clock one schedule interval at a time until the condition holds. A tick runs
    // on the thread pool after the advance releases its wait, so the condition is polled against real
    // time between advances; the bound only keeps a regression from hanging the suite.
    private async Task AdvanceUntilAsync(Func<Task<bool>> condition)
    {
        for (int attempt = 0; attempt < 400; attempt++)
        {
            if (await condition())
            {
                return;
            }

            _clock.Advance(Interval);
            for (int poll = 0; poll < 5; poll++)
            {
                // now-ok: waits for a tick running on another thread after the fake clock advanced.
                await Task.Delay(10);
                if (await condition())
                {
                    return;
                }
            }
        }

        Assert.Fail("The condition did not hold after repeated schedule intervals.");
    }

    [Fact]
    public async Task Service_KeepsTickingUntilTheMarkerExists_ThenEnds()
    {
        string ambiguousId = await SeedCacheAsync("amb", "proxy/" + new string('a', 64),
            NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean), ("other/package.json", Evil)));
        await SeedCacheAsync("ok", "proxy/" + new string('b', 64),
            NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean)));
        var store = new MidStreamFaultBlobStore(_blobs) { ThrowOnEveryRead = true };
        var log = new RecordingLogger<NpmManifestRescan>();
        var service = Build(store, log);

        await service.StartAsync(CancellationToken.None);
        try
        {
            await service.StartupPassCompleted;
            Assert.False(await MarkerExistsAsync());

            await AdvanceUntilAsync(() => Task.FromResult(log.Warnings.Count(w => w.Message.Contains("blob store unavailable")) >= 3));
            Assert.False(await MarkerExistsAsync());
            Assert.False(service.ExecuteTask!.IsCompleted);

            store.ThrowOnEveryRead = false;
            await AdvanceUntilAsync(MarkerExistsAsync);
            await AdvanceUntilAsync(() => Task.FromResult(service.ExecuteTask!.IsCompleted));

            Assert.Equal(NpmManifestRescan.AmbiguousKind, await KindAsync(ambiguousId));
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task Service_WhenAlreadyComplete_RunsNoTick()
    {
        await SeedCacheAsync("amb", "proxy/" + new string('a', 64),
            NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean), ("other/package.json", Evil)));
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO instance_settings (key, value) VALUES (@key, '1')", new { key = NpmManifestRescan.MarkerKey });
        }

        var service = Build(_blobs, new RecordingLogger<NpmManifestRescan>());
        await service.StartAsync(CancellationToken.None);
        await service.ExecuteTask!;
        await service.StopAsync(CancellationToken.None);

        await using var check = await _db.OpenAsync();
        Assert.Equal(0, await check.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM cache_artifact WHERE has_install_script = 1"));
    }

    [Theory]
    [InlineData("AIR_GAPPED", "true", true)]
    [InlineData("DISABLE_BACKGROUND_JOBS", "true", true)]
    [InlineData("DISABLE_BACKGROUND_JOBS", "license-backfill", true)]
    [InlineData("DISABLE_BACKGROUND_JOBS", "npm-manifest-rescan", false)]
    public async Task Service_RunsWhenAirGappedOrJobsDisabled_UnlessItIsNamed(string key, string value, bool runs)
    {
        string ambiguousId = await SeedCacheAsync("amb", "proxy/" + new string('a', 64),
            NpmFixtures.BuildTarballFromEntries(("package/package.json", Clean), ("other/package.json", Evil)));
        var service = Build(_blobs, new RecordingLogger<NpmManifestRescan>(), new Dictionary<string, string?> { [key] = value });

        await service.StartAsync(CancellationToken.None);
        try
        {
            await service.StartupPassCompleted;
            await service.ExecuteTask!;
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
        }

        Assert.Equal(runs ? NpmManifestRescan.AmbiguousKind : null, await KindAsync(ambiguousId));
        Assert.Equal(runs, await MarkerExistsAsync());
    }
}
