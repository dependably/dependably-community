using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Edge;
using Dependably.Infrastructure.Startup;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// An edge trusts a recorded <c>off</c> posture only for a bounded time, keeps that confirmation
/// across a restart, and records only a posture the master stated. The test master stub classifies
/// manifest requests structurally, so a repository name containing a <c>manifests</c> segment is not
/// mistaken for one.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EdgeOciScanPostureStoreTests : IAsyncLifetime
{
    private readonly string _dbFile = Path.Combine(Path.GetTempPath(), $"dependably_edge_posture_{Guid.NewGuid():N}.db");
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private SqliteMetadataStore _db = null!;
    private EdgeOciScanPostureStore _store = null!;

    public async Task InitializeAsync()
    {
        _db = new SqliteMetadataStore(StorageStartupExtensions.BuildSqliteConnectionString(_dbFile));
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org-1', 'acme')");
        }

        _store = new EdgeOciScanPostureStore(_db, _clock);
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

    [Fact]
    public async Task Off_IsServedFromCacheWithinFreshness_ThenReadsAsUnknown()
    {
        await _store.RecordAsync("org-1", "off");

        _clock.Advance(EdgeOciScanPostureStore.OffFreshness - TimeSpan.FromSeconds(1));
        Assert.True(await _store.MayServeFromCacheAsync("org-1"));

        _clock.Advance(TimeSpan.FromSeconds(2));
        Assert.Null(await _store.GetAsync("org-1"));
        Assert.False(await _store.MayServeFromCacheAsync("org-1"));
    }

    [Fact]
    public async Task ARepeatedOffFromTheMaster_RenewsFreshnessWithoutAChange()
    {
        await _store.RecordAsync("org-1", "off");
        _clock.Advance(EdgeOciScanPostureStore.OffFreshness + TimeSpan.FromSeconds(1));
        Assert.False(await _store.MayServeFromCacheAsync("org-1"));

        await _store.RecordAsync("org-1", "off");

        Assert.True(await _store.MayServeFromCacheAsync("org-1"));
    }

    [Fact]
    public async Task OffThatMovedToBlockOnTheMaster_IsNeverServedFromCacheAfterwards()
    {
        await _store.RecordAsync("org-1", "off");
        _clock.Advance(EdgeOciScanPostureStore.OffFreshness + TimeSpan.FromSeconds(1));
        Assert.False(await _store.MayServeFromCacheAsync("org-1"));

        await _store.RecordAsync("org-1", "block");
        _clock.Advance(TimeSpan.FromDays(1));

        Assert.Equal("block", await _store.GetAsync("org-1"));
        Assert.False(await _store.MayServeFromCacheAsync("org-1"));
    }

    [Fact]
    public async Task OffLoadedFromTheDatabaseAfterARestart_KeepsItsConfirmationTime()
    {
        await _store.RecordAsync("org-1", "off");
        _clock.Advance(EdgeOciScanPostureStore.OffFreshness - TimeSpan.FromSeconds(1));

        var restarted = new EdgeOciScanPostureStore(_db, _clock);
        Assert.True(await restarted.MayServeFromCacheAsync("org-1"));

        _clock.Advance(TimeSpan.FromSeconds(2));
        var restartedLater = new EdgeOciScanPostureStore(_db, _clock);
        Assert.False(await restartedLater.MayServeFromCacheAsync("org-1"));
        Assert.Equal("off", await restartedLater.GetLastKnownAsync("org-1"));
    }

    // A repeated 'off' is persisted at most once per interval, so a steady stream of responses
    // costs few writes, yet a restart still sees a confirmation that recent.
    [Fact]
    public async Task ARepeatedOff_IsPersistedOnlyOnceItsLastPersistedConfirmationHasAged()
    {
        await _store.RecordAsync("org-1", "off");
        string? first = await RecordedAtAsync();

        _clock.Advance(EdgeOciScanPostureStore.OffPersistInterval - TimeSpan.FromSeconds(1));
        await _store.RecordAsync("org-1", "off");
        Assert.Equal(first, await RecordedAtAsync());

        _clock.Advance(TimeSpan.FromSeconds(2));
        await _store.RecordAsync("org-1", "off");
        Assert.NotEqual(first, await RecordedAtAsync());

        _clock.Advance(EdgeOciScanPostureStore.OffFreshness - TimeSpan.FromSeconds(1));
        Assert.True(await new EdgeOciScanPostureStore(_db, _clock).MayServeFromCacheAsync("org-1"));
    }

    [Theory]
    [InlineData("off", false)]
    [InlineData(null, false)]
    [InlineData("warn", true)]
    [InlineData("block", true)]
    public async Task OnlyAGatedLastKnownPosture_RefusesDuringAnOutage(string? posture, bool refuses)
    {
        if (posture is not null)
        {
            await _store.RecordAsync("org-1", posture);
        }

        _clock.Advance(TimeSpan.FromDays(1));
        var restarted = new EdgeOciScanPostureStore(_db, _clock);

        Assert.Equal(refuses ? posture : null, await restarted.LastKnownGatedPostureAsync("org-1"));
    }

    private async Task<string?> RecordedAtAsync()
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>("SELECT recorded_at FROM edge_oci_scan_postures WHERE org_id = 'org-1'");
    }

    [Theory]
    [InlineData("https://reg.example/v2/team/app/manifests/latest", true)]
    [InlineData("https://reg.example/v2/team/app/manifests/sha256:abc", true)]
    [InlineData("https://reg.example/v2/team/app/blobs/sha256:abc", false)]
    [InlineData("https://reg.example/v2/team/manifests/x/blobs/sha256:abc", false)]
    [InlineData("https://reg.example/v2/team/blobs/x/manifests/latest", true)]
    [InlineData("https://reg.example/v2/team/manifests/x/manifests/latest?ns=a", true)]
    [InlineData("https://reg.example/v2/manifests/blobs/sha256:abc", false)]
    public void ManifestRequests_AreClassifiedFromTheEndOfThePath(string url, bool expected) =>
        Assert.Equal(expected, FakeOciRegistry.IsManifestUrl(url));

    // A response that states no posture says nothing about the org, a manifest response included:
    // a master answering anonymously, or one that predates the header, is not a master at 'off'.
    [Fact]
    public async Task ASuccessfulHeaderlessResponse_RecordsNothing()
    {
        using var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK);

        await OciUpstreamResolver.ObserveMasterVerdictAsync(_store, "org-1", response, default);

        Assert.Null(await _store.GetLastKnownAsync("org-1"));
    }

    [Fact]
    public async Task AStatedOff_IsRecorded()
    {
        using var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        response.Headers.TryAddWithoutValidation(EdgeOciScanPostureStore.Header, "off");

        await OciUpstreamResolver.ObserveMasterVerdictAsync(_store, "org-1", response, default);

        Assert.True(await _store.MayServeFromCacheAsync("org-1"));
    }

    [Fact]
    public async Task AStatedPosture_IsRecordedFromAnyResponse()
    {
        using var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        response.Headers.TryAddWithoutValidation(EdgeOciScanPostureStore.Header, "block");

        await OciUpstreamResolver.ObserveMasterVerdictAsync(_store, "org-1", response, default);

        Assert.Equal("block", await _store.GetLastKnownAsync("org-1"));
    }
}
