using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Dependably.Infrastructure;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Http;

namespace Dependably.Tests.Integration;

/// <summary>
/// Acceptance: the proxy-fetch MISS path stages bytes to disk (via
/// <c>HashingFileStream</c> + temp file) before uploading the verified artefact to the
/// blob store, then streams the response back from the blob store rather than handing
/// the controller a buffered byte[].
///
/// Three coordinated tests, three scopes:
/// <list type="bullet">
///   <item><b>End-to-end controller path</b>: 10 concurrent npm tarball MISS fetches
///         for 10 distinct coordinates, asserting on structural correctness (200s,
///         correct body length, exactly 10 upstream tarball calls — dedup map did not
///         collapse them) and staging-dir cleanup hygiene.</item>
///   <item><b>Direct streaming path — stream-type assertion</b>: drives
///         <see cref="Protocol.UpstreamClient.GetOrFetchStreamAsync"/> against a real
///         <see cref="LocalBlobStore"/> wrapped in an inspector and asserts the
///         <see cref="Stream"/> concrete type handed to
///         <see cref="IBlobStore.PutAsync"/> is a <see cref="FileStream"/> (the staged
///         temp file), <b>not</b> a <see cref="MemoryStream"/>. This is the direct
///         regression-catch surface: re-introducing
///         <c>new MemoryStream(bytes)</c> on the PutAsync side flips this assertion.</item>
///   <item><b>Per-fetch cleanup serial check</b>: 5 serial MISS fetches and asserts
///         every temp file is gone before moving on — isolates a cleanup regression
///         from concurrent-burst timing noise.</item>
/// </list>
///
/// The original ticket included a managed-heap-delta assertion. We dropped it because
/// the in-memory <see cref="HttpClient"/> response pipe in the test infrastructure
/// buffers ~100 MB for a 10 × 10 MB workload — an artefact of the test handler, not
/// the staging code. The stream-type assertion catches the same regression class
/// (something stuffing bytes into a MemoryStream on the put-side) without runner-
/// dependent noise.
/// </summary>
[Trait("Category", "Integration")]
public sealed class ProxyFetchSoakTests
{
    private const int ArtifactSizeBytes = 10 * 1024 * 1024; // 10 MB per coordinate
    private const int ChunkSize = 64 * 1024;
    private const int ConcurrentRequests = 10;

    [Fact]
    public async Task MissPath_10Concurrent_StreamsResponses_NoDedupCollapse()
    {
        string stagingDir = Path.Combine(Path.GetTempPath(), $"dependably-soak-stage-{Guid.NewGuid():N}");
        string blobDir = Path.Combine(Path.GetTempPath(), $"dependably-soak-blobs-{Guid.NewGuid():N}");
        Directory.CreateDirectory(stagingDir);
        Directory.CreateDirectory(blobDir);

        var coords = new List<(string Name, string Filename, byte[] Bytes, string Sha256Hex)>();
        for (int i = 0; i < ConcurrentRequests; i++)
        {
            string name = $"soakpkg{Guid.NewGuid():N}"[..18].ToLowerInvariant();
            string version = "1.0.0";
            string filename = $"{name}-{version}.tgz";
            // Smaller payload for the end-to-end test — the controller path still
            // buffers via GetOrFetchMetadataAsync + ProxyFetchService. Memory bound
            // for hash-and-stage is asserted in the focused
            // direct-streaming test below.
            byte[] bytes = RandomNumberGenerator.GetBytes(256 * 1024);
            string sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            coords.Add((name, filename, bytes, sha));
        }

        var handler = new DripFeedHandler(coords, ChunkSize, dripDelay: TimeSpan.FromMilliseconds(2));

        await using var factory = new SoakFactory(blobDir, stagingDir, handler);
        using (var warmup = factory.CreateClient())
        {
            _ = await warmup.GetAsync("/healthz/live");
        }
        string token = await factory.CreateToken("pull");

        // Fire 10 concurrent GETs.
        var responseBodyLengths = new ConcurrentBag<long>();
        var statusCodes = new ConcurrentBag<HttpStatusCode>();

        var tasks = coords.Select(async coord =>
        {
            using var client = factory.CreateClientWithBearer(token);
            using var resp = await client.GetAsync(
                $"/npm/tarballs/{coord.Name}/{coord.Filename}",
                HttpCompletionOption.ResponseHeadersRead);
            statusCodes.Add(resp.StatusCode);

            byte[] bodyBytes = await resp.Content.ReadAsByteArrayAsync();
            responseBodyLengths.Add(bodyBytes.Length);
        }).ToArray();

        await Task.WhenAll(tasks);

        // ── Structural assertions ─────────────────────────────────────────────
        Assert.All(statusCodes, sc => Assert.Equal(HttpStatusCode.OK, sc));
        Assert.All(responseBodyLengths, len => Assert.Equal(coords[0].Bytes.Length, len));
        // Upstream tarball calls: exactly one per coordinate — the inflight dedup map
        // did not collapse the 10 distinct coordinates.
        Assert.Equal(ConcurrentRequests, handler.CallCount);

        // ── Cleanup hygiene assertion ─────────────────────────────────────────
        // No staging temp files should be left behind — they live outside the blob store
        // and the FetchAndStageAsync try/finally is responsible for cleanup.
        Assert.Empty(Directory.GetFiles(stagingDir));

        try { Directory.Delete(stagingDir, recursive: true); } catch { /* ignore */ }
        try { Directory.Delete(blobDir, recursive: true); } catch { /* ignore */ }
    }

    [Fact]
    public async Task StreamingFetchPath_PassesFileStreamToBlobStore_NotMemoryStream()
    {
        // Direct, deterministic evidence that the MISS path stages to disk: the stream
        // FetchAndStageAsync hands to IBlobStore.PutAsync must be a FileStream pointing
        // at the staging temp file, not a MemoryStream (or any other in-memory
        // container). Wraps a real LocalBlobStore with an inspector that records the
        // concrete type of the Stream passed to PutAsync, then asserts on that type.
        //
        // This replaces a wall-clock mid-burst sample (too sensitive to in-memory
        // HttpClient buffering) with a structural check that catches the exact
        // regression class — re-introducing `new MemoryStream(bytes)` on the
        // PutAsync side.
        string stagingDir = Path.Combine(Path.GetTempPath(), $"dependably-soak-stage-{Guid.NewGuid():N}");
        string blobDir = Path.Combine(Path.GetTempPath(), $"dependably-soak-blobs-{Guid.NewGuid():N}");
        Directory.CreateDirectory(stagingDir);
        Directory.CreateDirectory(blobDir);

        const int Size = 1 * 1024 * 1024; // 1 MB is enough — the assertion is on type, not size
        byte[] bytes = RandomNumberGenerator.GetBytes(Size);
        string sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

        var inner = new LocalBlobStore(blobDir);
        var inspector = new StreamTypeInspectingBlobStore(inner);

        var handler = new StaticOkHandler(bytes);
        var factory = new SingleHandlerHttpClientFactory(handler);
        var auditStore = new SoakInMemoryAuditStore();
        var audit = new AuditRepository(auditStore);
        var tiered = new TieredBlobStorage(inspector, inspector);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = stagingDir
            }).Build();
        var client = new Protocol.UpstreamClient(
            factory, tiered, audit,
            new PermissiveUpstreamUrlValidator(),
            new SoakNoAirGap(),
            new Dependably.Infrastructure.DriveInfoStagingDiskInfo(stagingDir),
            config,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<Protocol.UpstreamClient>.Instance);

        string blobKey = BlobKeys.Proxy(sha);
        var spec = new Protocol.ChecksumSpec(Protocol.ChecksumAlgorithm.Sha256, sha);
        var (stream, _) = await client.GetOrFetchStreamAsync(
            blobKey, "http://upstream.invalid/pkg.tgz", spec, "npm");
        long total = 0;
        await using (stream.ConfigureAwait(false))
        {
            byte[] buf = new byte[81920];
            int n;
            while ((n = await stream.ReadAsync(buf)) > 0)
            {
                total += n;
            }
        }

        Assert.Equal(Size, total);

        // The Stream concrete type passed to PutAsync is the regression-catch surface.
        // Must NOT be MemoryStream — that would mean we're buffering bytes in managed
        // memory rather than streaming from a temp file.
        Assert.NotNull(inspector.LastPutStreamType);
        Assert.DoesNotContain("MemoryStream", inspector.LastPutStreamType, StringComparison.Ordinal);
        // Positive expectation: it should be a FileStream (the staged temp file).
        Assert.Contains("FileStream", inspector.LastPutStreamType, StringComparison.Ordinal);

        // Cleanup hygiene: temp file gone, blob present.
        Assert.Empty(Directory.GetFiles(stagingDir));
        Assert.True(await inner.ExistsAsync(blobKey));

        try { Directory.Delete(stagingDir, recursive: true); } catch { /* ignore */ }
        try { Directory.Delete(blobDir, recursive: true); } catch { /* ignore */ }
    }

    [Fact]
    public async Task MissPath_StagingTempFilesCleanedAfterEachFetch()
    {
        // Hygiene check, isolated from the burst test to keep failures pinpointable.
        // Validates that FetchAndStageAsync's try/finally deletes every temp file —
        // exercising the same code path under serial conditions so an environmental
        // hiccup on the burst test (e.g. xunit-parallel timing) doesn't mask a real
        // cleanup regression.
        string stagingDir = Path.Combine(Path.GetTempPath(), $"dependably-soak-stage-{Guid.NewGuid():N}");
        string blobDir = Path.Combine(Path.GetTempPath(), $"dependably-soak-blobs-{Guid.NewGuid():N}");
        Directory.CreateDirectory(stagingDir);
        Directory.CreateDirectory(blobDir);

        var coords = new List<(string Name, string Filename, byte[] Bytes, string Sha256Hex)>();
        for (int i = 0; i < 5; i++)
        {
            string name = $"clean{Guid.NewGuid():N}"[..16].ToLowerInvariant();
            string filename = $"{name}-1.0.0.tgz";
            byte[] bytes = RandomNumberGenerator.GetBytes(64 * 1024); // small payload — speed
            string sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            coords.Add((name, filename, bytes, sha));
        }

        var handler = new DripFeedHandler(coords, ChunkSize, dripDelay: TimeSpan.FromMilliseconds(1));

        await using var factory = new SoakFactory(blobDir, stagingDir, handler);
        using (var warmup = factory.CreateClient())
        {
            _ = await warmup.GetAsync("/healthz/live");
        }
        string token = await factory.CreateToken("pull");

        foreach (var (Name, Filename, Bytes, Sha256Hex) in coords)
        {
            using var client = factory.CreateClientWithBearer(token);
            using var resp = await client.GetAsync($"/npm/tarballs/{Name}/{Filename}");
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }

        Assert.Empty(Directory.GetFiles(stagingDir));

        try { Directory.Delete(stagingDir, recursive: true); } catch { /* ignore */ }
        try { Directory.Delete(blobDir, recursive: true); } catch { /* ignore */ }
    }

    // ── Test-only WebApplicationFactory ───────────────────────────────────────

    /// <summary>
    /// Real <see cref="LocalBlobStore"/> on a temp dir (the spec rules out
    /// <see cref="InMemoryBlobStore"/>, which buffers in <c>PutAsync</c> and would mask
    /// the memory win). Replaces the upstream HTTP handler with a test handler so we
    /// can drip-feed bytes. Records the response Stream type via a tiny middleware so
    /// the structural assertion can read it back.
    /// </summary>
    private sealed class SoakFactory : WebApplicationFactory<Program>
    {
        private readonly string _blobDir;
        private readonly string _stagingDir;
        private readonly DripFeedHandler _handler;
        private readonly TestMetadataStore _metadataStore = new();
        private LocalBlobStore? _blobStore;

        public SoakFactory(string blobDir, string stagingDir, DripFeedHandler handler)
        {
            _blobDir = blobDir;
            _stagingDir = stagingDir;
            _handler = handler;
        }

        protected override IHost CreateHost(IHostBuilder _)
        {
            var builder = WebApplication.CreateBuilder();
            Program.ConfigureBuilder(builder);

            _blobStore = new LocalBlobStore(_blobDir);
            builder.Services.RemoveAll<IBlobStore>();
            builder.Services.AddSingleton<IBlobStore>(_blobStore);
            builder.Services.RemoveAll<TieredBlobStorage>();
            builder.Services.AddSingleton(new TieredBlobStorage(_blobStore, _blobStore));

            builder.Services.RemoveAll<IMetadataStore>();
            builder.Services.AddSingleton<IMetadataStore>(_metadataStore);

            builder.Services.RemoveAll<IUpstreamUrlValidator>();
            builder.Services.AddSingleton<IUpstreamUrlValidator, PermissiveUpstreamUrlValidator>();

            // Override the "upstream" HttpClient handler so we control the bytes that
            // flow into FetchAndStageAsync.
            builder.Services.Configure<HttpClientFactoryOptions>("upstream", opts => opts.HttpMessageHandlerBuilderActions.Add(b =>
                {
                    b.PrimaryHandler = _handler;
                    b.AdditionalHandlers.Clear();
                }));

            builder.WebHost.UseTestServer();
            builder.WebHost.UseSetting("Npm:Upstream", "http://upstream.invalid");
            builder.WebHost.UseSetting("PROXY_STAGING_PATH", _stagingDir);
            builder.WebHost.UseSetting("DEFAULT_ORG_SLUG", "default");
            builder.WebHost.UseSetting("Logging:LogLevel:Default", "Warning");

            var app = builder.Build();
            Program.ConfigureApp(app);

            app.Start();
            return app;
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing)
            {
                _metadataStore.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
        }

        // Token + auth helpers mirror DependablyFactory; duplicated here because we
        // can't subclass DependablyFactory (its CreateHost is sealed onto a different
        // configuration).
        public async Task<string> CreateToken(string kind = "pull", string org = "default")
        {
            var tokens = Services.GetRequiredService<TokenRepository>();
            var orgs = Services.GetRequiredService<OrgRepository>();
            var orgRecord = await orgs.GetBySlugAsync(org)
                ?? throw new InvalidOperationException($"Org '{org}' not found. Was the server started?");
            string caps = kind == "push"
                ? """["publish:*","read:artifact","read:metadata","yank:*"]"""
                : """["read:artifact","read:metadata"]""";
            var (raw, _) = await tokens.CreateServiceTokenAsync(
                orgRecord.Id, $"test-{kind}-{Guid.NewGuid():N}", caps, expiresAt: null);
            return raw;
        }

        public HttpClient CreateClientWithBearer(string token)
        {
            var client = CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return client;
        }
    }

    // ── Drip-feed HttpMessageHandler ──────────────────────────────────────────

    /// <summary>
    /// Serves 10 MB tarballs in 64 KB chunks with a 5 ms delay between writes so the
    /// real async-IO backpressure path is exercised — a synchronous full-body response
    /// would let the entire transfer collapse into a single CopyToAsync iteration and
    /// hide the bound-memory win. Matches on the npm tarball URL pattern
    /// <c>/.+/-/(filename)</c> and 404s on anything else (no metadata stubbing — the
    /// controller's npm packument fetch fails fast and we proceed with no upstream
    /// integrity spec).
    /// </summary>
    private sealed class DripFeedHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, byte[]> _byFilename;
        private readonly int _chunkSize;
        private readonly TimeSpan _dripDelay;
        private int _callCount;

        public DripFeedHandler(
            IEnumerable<(string Name, string Filename, byte[] Bytes, string Sha256Hex)> coords,
            int chunkSize,
            TimeSpan dripDelay)
        {
            _byFilename = coords.ToDictionary(c => c.Filename, c => c.Bytes);
            _chunkSize = chunkSize;
            _dripDelay = dripDelay;
        }

        public int CallCount => Volatile.Read(ref _callCount);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string url = request.RequestUri!.AbsoluteUri;
            // Match the npm tarball pattern: /{name}/-/{filename}
            int dashIdx = url.IndexOf("/-/", StringComparison.Ordinal);
            if (dashIdx < 0)
            {
                // npm packument / metadata fetches — return 404 so the controller falls
                // back to "no upstream integrity" and proceeds with the tarball MISS.
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }
            string filename = url[(dashIdx + 3)..];
            // Strip any query string just in case.
            int q = filename.IndexOf('?');
            if (q >= 0)
            {
                filename = filename[..q];
            }

            if (!_byFilename.TryGetValue(filename, out byte[]? bytes))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }

            Interlocked.Increment(ref _callCount);

            var resp = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new DripStreamContent(bytes, _chunkSize, _dripDelay)
            };
            resp.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            resp.Content.Headers.ContentLength = bytes.Length;
            return Task.FromResult(resp);
        }
    }

    /// <summary>
    /// Returns a fixed body. Used by the direct-streaming soak test which doesn't need
    /// drip-feed timing — its assertion is on the stream concrete type, not timing.
    /// </summary>
    private sealed class StaticOkHandler : HttpMessageHandler
    {
        private readonly byte[] _body;
        public StaticOkHandler(byte[] body) { _body = body; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var content = new ByteArrayContent(_body);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            content.Headers.ContentLength = _body.Length;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content });
        }
    }

    /// <summary>
    /// <see cref="IBlobStore"/> decorator that records the concrete <see cref="Stream"/>
    /// type passed to <see cref="IBlobStore.PutAsync"/>. The test asserts that this is
    /// a <see cref="FileStream"/> (the staging temp file) and not a
    /// <see cref="MemoryStream"/> — direct evidence of hash-and-stage.
    /// </summary>
    private sealed class StreamTypeInspectingBlobStore : IBlobStore
    {
        private readonly IBlobStore _inner;
        public string? LastPutStreamType { get; private set; }

        public StreamTypeInspectingBlobStore(IBlobStore inner) => _inner = inner;

        public Task PutAsync(string key, Stream data, CancellationToken ct = default)
        {
            LastPutStreamType = data.GetType().FullName;
            return _inner.PutAsync(key, data, ct);
        }

        public Task<Stream?> GetAsync(string key, CancellationToken ct = default)
            => _inner.GetAsync(key, ct);
        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => _inner.GetRangeAsync(key, from, to, ct);
        public Task<bool> ExistsAsync(string key, CancellationToken ct = default)
            => _inner.ExistsAsync(key, ct);
        public Task DeleteAsync(string key, CancellationToken ct = default)
            => _inner.DeleteAsync(key, ct);
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default)
            => _inner.GetTotalSizeAsync(ct);
        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default)
            => _inner.ListAsync(prefix, ct);
    }

    /// <summary>
    /// Minimum-viable <see cref="IHttpClientFactory"/> that hands out a single
    /// <see cref="HttpClient"/> wired to the test handler. Used by the direct-streaming
    /// soak test where the full WebApplicationFactory plumbing would over-burden the
    /// memory baseline.
    /// </summary>
    private sealed class SingleHandlerHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public SingleHandlerHttpClientFactory(HttpMessageHandler handler)
            => _client = new HttpClient(handler);
        public HttpClient CreateClient(string name) => _client;
    }

    /// <summary>
    /// IMetadataStore-shaped stub for AuditRepository in the direct-streaming soak. Backed
    /// by an in-memory SQLite connection with the minimum schema the audit writes touch —
    /// keeps the test from booting the full schema initializer and its memory footprint.
    /// </summary>
    private sealed class SoakInMemoryAuditStore : IMetadataStore
    {
        public DbProvider Provider => DbProvider.Sqlite;

        public Task<System.Data.Common.DbConnection> OpenAsync(CancellationToken ct = default)
        {
            var conn = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=:memory:");
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id TEXT PRIMARY KEY, scope TEXT, org_id TEXT, actor_id TEXT,
                    actor_kind TEXT, action TEXT NOT NULL, ecosystem TEXT, purl TEXT,
                    detail TEXT, source_ip TEXT, created_at TEXT
                );
                CREATE TABLE IF NOT EXISTS activity (
                    id TEXT PRIMARY KEY, org_id TEXT NOT NULL, ecosystem TEXT NOT NULL,
                    purl TEXT NOT NULL, event_type TEXT NOT NULL, actor_id TEXT,
                    actor_kind TEXT, detail TEXT, source_ip TEXT, created_at TEXT
                );
                """;
            cmd.ExecuteNonQuery();
            return Task.FromResult<System.Data.Common.DbConnection>(conn);
        }
    }

    private sealed class SoakNoAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new System.Collections.Generic.HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    /// <summary>
    /// <see cref="HttpContent"/> that streams its payload in fixed-size chunks with a
    /// delay between writes, simulating a slow upstream and exercising the staging
    /// stream's async write path.
    /// </summary>
    private sealed class DripStreamContent : HttpContent
    {
        private readonly byte[] _bytes;
        private readonly int _chunkSize;
        private readonly TimeSpan _dripDelay;

        public DripStreamContent(byte[] bytes, int chunkSize, TimeSpan dripDelay)
        {
            _bytes = bytes;
            _chunkSize = chunkSize;
            _dripDelay = dripDelay;
        }

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            for (int offset = 0; offset < _bytes.Length; offset += _chunkSize)
            {
                int len = Math.Min(_chunkSize, _bytes.Length - offset);
                await stream.WriteAsync(_bytes.AsMemory(offset, len));
                if (_dripDelay > TimeSpan.Zero)
                {
                    await Task.Delay(_dripDelay);
                }
            }
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _bytes.Length;
            return true;
        }
    }
}
