using System.Net;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Verifies that host shutdown cancels an in-flight upstream fetch while client disconnects
/// do not. The single-flight waiter path is kept separate: only the HTTP fetch itself carries
/// the linked (host-stopping + request) token; waiters use WaitAsync(requestCt) so they
/// can still be cancelled by their own client disconnect without affecting the shared fetch.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UpstreamClientShutdownTests
{
    // ── Shutdown cancels a hung fetch ─────────────────────────────────────────

    [Fact]
    public async Task GetOrFetchStreamAsync_HostShutdown_CancelsFetch()
    {
        // Arrange: an HTTP handler that never completes — simulates a slow upstream (e.g. large
        // OCI blob from a distant registry that outlives the 30-second drain window).
        var neverCompletes = new TaskCompletionSource<HttpResponseMessage>();
        var handler = new TcsHandler(neverCompletes.Task);
        var lifetime = new FakeLifetime();
        var (client, _) = Build(handler, lifetime);

        // Act: start the fetch on a background task, then trigger host shutdown.
        using var requestCts = new CancellationTokenSource();
        var fetchTask = client.GetOrFetchStreamAsync(
            "blobs/shutdown-test", "http://upstream.invalid/blob",
            checksumSpec: null, ecosystem: "oci",
            ct: requestCts.Token);

        // Give the background fetch time to reach the HTTP call before we fire shutdown.
        await Task.Delay(50);
        lifetime.TriggerStopping();

        // Assert: the fetch completes (cancels) within the drain window, not after a 30-min timeout.
        var completed = await Task.WhenAny(fetchTask, Task.Delay(TimeSpan.FromSeconds(5)));
        Assert.Same(fetchTask, completed);
        var ex = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fetchTask);
        Assert.NotNull(ex);
    }

    // ── Client disconnect does NOT cancel the shared fetch ────────────────────

    [Fact]
    public async Task GetOrFetchStreamAsync_ClientDisconnect_DoesNotCancelFetch()
    {
        // Arrange: an HTTP handler that unblocks after the client disconnects, confirming the
        // underlying fetch continued to run.
        var fetchStarted = new TaskCompletionSource();
        var allowComplete = new TaskCompletionSource<HttpResponseMessage>();
        byte[] payload = [1, 2, 3, 4];

        var handler = new SignalingHandler(fetchStarted, allowComplete);
        var lifetime = new FakeLifetime();
        var (client, store) = Build(handler, lifetime);

        // Start the single-flight fetch.
        using var requestCts1 = new CancellationTokenSource();
        var fetch1 = client.GetOrFetchStreamAsync(
            "blobs/disconnect-test", "http://upstream.invalid/blob",
            checksumSpec: null, ecosystem: "oci",
            ct: requestCts1.Token);

        // Wait until the handler has started processing the request, then cancel the client.
        await fetchStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        requestCts1.Cancel();

        // Allow the underlying HTTP call to complete with a valid response.
        allowComplete.SetResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(payload)
        });

        // The single-flight work item is not bound to the first caller's token, so the
        // underlying fetch runs to completion and caches the blob despite the disconnect.
        var completed = await Task.WhenAny(fetch1, Task.Delay(TimeSpan.FromSeconds(5)));
        Assert.Same(fetch1, completed);

        // The first caller's own awaiting path may still observe its cancelled token after
        // the shared work finishes — tolerate that, but no other failure is acceptable.
        var ex = await Record.ExceptionAsync(async () =>
        {
            var (body, _) = await fetch1;
            await body.DisposeAsync();
        });
        if (ex is not null)
        {
            Assert.IsAssignableFrom<OperationCanceledException>(ex);
        }

        // The cached blob is the proof the shared fetch survived the disconnect.
        Assert.True(await store.ExistsAsync("blobs/disconnect-test"));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static (UpstreamClient Client, InMemoryBlobStore Store) Build(
        HttpMessageHandler handler,
        FakeLifetime lifetime)
    {
        var store = new InMemoryBlobStore();
        var factory = new NamedFactory(handler);
        var audit = new AuditRepository(new ShutdownNullStore());
        var tiered = new TieredBlobStorage(store, store);
        string stagingDir = Path.Combine(Path.GetTempPath(), $"dependably-shutdown-test-{Guid.NewGuid():N}");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["PROXY_STAGING_PATH"] = stagingDir })
            .Build();
        var client = new UpstreamClient(
            factory, tiered, audit, new PermitAll(), new NotAirGapped(),
            new UnlimitedDisk(), config,
            NullLogger<UpstreamClient>.Instance,
            lifetime);
        return (client, store);
    }

    // ── Test doubles ─────────────────────────────────────────────────────────

    /// <summary>Returns the result of the provided Task, blocking until it resolves.</summary>
    private sealed class TcsHandler : HttpMessageHandler
    {
        private readonly Task<HttpResponseMessage> _pending;
        public TcsHandler(Task<HttpResponseMessage> pending) => _pending = pending;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Propagate cancellation from the linked token (host shutdown or request ct).
            using var reg = cancellationToken.Register(() => { });
            return await _pending.WaitAsync(cancellationToken);
        }
    }

    /// <summary>
    /// Signals fetchStarted when SendAsync is called, then awaits allowComplete.
    /// This lets the test cancel the client token AFTER the HTTP call is in flight.
    /// </summary>
    private sealed class SignalingHandler : HttpMessageHandler
    {
        private readonly TaskCompletionSource _fetchStarted;
        private readonly Task<HttpResponseMessage> _allowComplete;

        public SignalingHandler(TaskCompletionSource fetchStarted, TaskCompletionSource<HttpResponseMessage> allowComplete)
        {
            _fetchStarted = fetchStarted;
            _allowComplete = allowComplete.Task;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            _fetchStarted.TrySetResult();
            // The fetch token is CancellationToken.None (single-flight convention),
            // so this await returns normally when allowComplete is set.
            return await _allowComplete;
        }
    }

    private sealed class NamedFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public NamedFactory(HttpMessageHandler h) => _client = new HttpClient(h);
        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class PermitAll : IUpstreamUrlValidator
    {
        public Task<bool> IsAllowedAsync(string url, string? orgId = null, CancellationToken ct = default)
            => Task.FromResult(true);
    }

    private sealed class NotAirGapped : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new System.Collections.Generic.HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    /// <summary>
    /// IHostApplicationLifetime stub that exposes a cancellation token the test can trigger.
    /// </summary>
    private sealed class FakeLifetime : IHostApplicationLifetime
    {
        private readonly CancellationTokenSource _stopping = new();
        private readonly CancellationTokenSource _stopped = new();
        private readonly CancellationTokenSource _started = new();

        public CancellationToken ApplicationStarted => _started.Token;
        public CancellationToken ApplicationStopping => _stopping.Token;
        public CancellationToken ApplicationStopped => _stopped.Token;

        public void TriggerStopping() => _stopping.Cancel();

        public void StopApplication() => _stopping.Cancel();
    }

    private sealed class ShutdownNullStore : IMetadataStore
    {
        public DbProvider Provider => DbProvider.Sqlite;

        public Task<System.Data.Common.DbConnection> OpenAsync(CancellationToken ct = default)
        {
            var conn = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=:memory:");
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id TEXT PRIMARY KEY, scope TEXT, org_id TEXT, actor_id TEXT, action TEXT,
                    ecosystem TEXT, purl TEXT, detail TEXT, source_ip TEXT, created_at TEXT
                );
                CREATE TABLE IF NOT EXISTS activity (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL, ecosystem TEXT NOT NULL, purl TEXT NOT NULL,
                    event_type TEXT NOT NULL, actor_id TEXT, actor_kind TEXT,
                    detail TEXT, source_ip TEXT,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
                );
                """;
            cmd.ExecuteNonQuery();
            return Task.FromResult<System.Data.Common.DbConnection>(conn);
        }
    }

    private sealed class UnlimitedDisk : IStagingDiskInfo
    {
        public long GetAvailableBytes() => long.MaxValue;
        public long GetTotalBytes() => long.MaxValue;
        public long GetStagingDirectoryUsedBytes() => 0;
    }
}
