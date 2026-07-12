using System.Net;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// <see cref="NpmPackumentFetcher"/> acceptance: the full packument is fetched with no Accept
/// header; when the full document overflows the metadata byte cap the fetch retries once with
/// the abbreviated (install-v1) Accept header; and the two variants of the same URL occupy
/// separate TTL-cache entries, so a cached abbreviated body can never satisfy a full-document
/// request (or vice versa).
/// </summary>
[Trait("Category", "Unit")]
public sealed class NpmPackumentFetcherTests
{
    private const string Url = "http://upstream.invalid/vite";
    private const string FullBody = """{"name":"vite","versions":{},"time":{}}""";
    private const string CorgiBody = """{"name":"vite","versions":{"8.0.16":{"dependencies":{"rolldown":"1.0.3"}}}}""";

    [Fact]
    public async Task FullPackumentUnderCap_SingleFetch_NoAcceptHeader()
    {
        var handler = new AcceptRoutingHandler();
        var client = BuildClient(handler);

        var resp = await NpmPackumentFetcher.FetchAsync(client, Url, authorizationHeader: null, logger: null, CancellationToken.None);

        Assert.True(resp.IsSuccessStatusCode);
        Assert.Equal(FullBody, resp.BodyAsString());
        Assert.Equal(1, handler.CallCount);
        Assert.Null(handler.SeenAcceptHeaders[0]);
    }

    [Fact]
    public async Task OversizedFullPackument_RetriesWithAbbreviatedAccept()
    {
        var handler = new AcceptRoutingHandler { OversizedFull = true };
        var client = BuildClient(handler);

        var resp = await NpmPackumentFetcher.FetchAsync(client, Url, authorizationHeader: null, logger: null, CancellationToken.None);

        Assert.True(resp.IsSuccessStatusCode);
        Assert.Equal(CorgiBody, resp.BodyAsString());
        Assert.Equal(2, handler.CallCount);
        Assert.Null(handler.SeenAcceptHeaders[0]);
        Assert.Equal(NpmPackumentFetcher.AbbreviatedAccept, handler.SeenAcceptHeaders[1]);
    }

    [Fact]
    public async Task OversizedAbbreviatedDocument_PropagatesTooLarge()
    {
        // When even the abbreviated document overflows the cap, the exception must surface to
        // the caller (whose existing catch degrades to local-only metadata) — not loop.
        var handler = new AcceptRoutingHandler { OversizedFull = true, OversizedAbbreviated = true };
        var client = BuildClient(handler);

        await Assert.ThrowsAsync<UpstreamResponseTooLargeException>(() =>
            NpmPackumentFetcher.FetchAsync(client, Url, authorizationHeader: null, logger: null, CancellationToken.None));
        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public async Task FullAndAbbreviatedVariants_OccupySeparateCacheEntries()
    {
        var handler = new AcceptRoutingHandler();
        var client = BuildClient(handler, withCache: true);

        // Warm both variants of the same URL.
        var full = await client.GetOrFetchMetadataAsync(Url);
        var corgi = await client.GetOrFetchMetadataAsync(
            Url, UpstreamClient.MaxMetadataResponseBytes, authorizationHeader: null,
            NpmPackumentFetcher.AbbreviatedAccept, CancellationToken.None);
        Assert.Equal(FullBody, full.BodyAsString());
        Assert.Equal(CorgiBody, corgi.BodyAsString());
        Assert.Equal(2, handler.CallCount);

        // Within TTL both variants are cache hits — and each serves ITS OWN body: a cached
        // abbreviated document must never answer a full-packument request, or npm view / any
        // full-metadata consumer would silently lose fields.
        var fullAgain = await client.GetOrFetchMetadataAsync(Url);
        var corgiAgain = await client.GetOrFetchMetadataAsync(
            Url, UpstreamClient.MaxMetadataResponseBytes, authorizationHeader: null,
            NpmPackumentFetcher.AbbreviatedAccept, CancellationToken.None);
        Assert.Equal(2, handler.CallCount);
        Assert.Equal(FullBody, fullAgain.BodyAsString());
        Assert.Equal(CorgiBody, corgiAgain.BodyAsString());
    }

    private static UpstreamClient BuildClient(AcceptRoutingHandler handler, bool withCache = false)
    {
        string stagingDir = Path.Combine(Path.GetTempPath(), $"dependably-test-{Guid.NewGuid():N}");
        var settings = new Dictionary<string, string?>
        {
            ["PROXY_STAGING_PATH"] = stagingDir,
            ["Proxy:MetadataCacheTtlSeconds"] = withCache ? "120" : "0",
        };
        var config = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        var cache = withCache
            ? new MetadataResponseCache(
                MetadataCacheOptions.Resolve(config, new EdgeMode(config)), new FakeTimeProvider())
            : null;

        var blobs = new InMemoryBlobStore();
        return new UpstreamClient(
            new FactoryFor(handler),
            new TieredBlobStorage(blobs, blobs),
            new AuditRepository(new DiscardMetadataStore()),
            new AllowEverythingValidator(),
            new NotAirGapped(),
            new DriveInfoStagingDiskInfo(stagingDir),
            StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance,
            lifetime: null,
            metadataCache: cache);
    }

    // Routes on the request's Accept header: install-v1 requests get the abbreviated body,
    // everything else the full body. "Oversized" replies declare a Content-Length past the
    // metadata cap so the capped read fails fast without materialising a 32 MB test body.
    private sealed class AcceptRoutingHandler : HttpMessageHandler
    {
        private readonly Lock _lock = new();
        public bool OversizedFull { get; init; }
        public bool OversizedAbbreviated { get; init; }
        public int CallCount;
        public List<string?> SeenAcceptHeaders { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string? accept = request.Headers.TryGetValues("Accept", out var values)
                ? string.Join(",", values)
                : null;
            lock (_lock)
            {
                CallCount++;
                SeenAcceptHeaders.Add(accept);
            }

            bool abbreviated = accept?.Contains("install-v1", StringComparison.Ordinal) == true;
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    abbreviated ? CorgiBody : FullBody, System.Text.Encoding.UTF8, "application/json"),
            };
            if (abbreviated ? OversizedAbbreviated : OversizedFull)
            {
                response.Content.Headers.ContentLength = UpstreamClient.MaxMetadataResponseBytes + 1;
            }

            return Task.FromResult(response);
        }
    }

    private sealed class FactoryFor : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public FactoryFor(HttpMessageHandler handler) => _client = new HttpClient(handler);
        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class NotAirGapped : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    private sealed class AllowEverythingValidator : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId = null, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.None);
    }

    private sealed class DiscardMetadataStore : IMetadataStore
    {
        public DbProvider Provider => DbProvider.Sqlite;

        public Task<System.Data.Common.DbConnection> OpenAsync(CancellationToken ct = default)
        {
            var conn = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=:memory:");
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id TEXT PRIMARY KEY, org_id TEXT, user_id TEXT, action TEXT, target TEXT,
                    detail TEXT, actor_email TEXT, created_at TEXT, source_ip TEXT);
                CREATE TABLE IF NOT EXISTS activity (
                    id TEXT PRIMARY KEY, org_id TEXT, package_version_id TEXT, action TEXT,
                    user_id TEXT, purl TEXT, detail TEXT, source_ip TEXT, created_at TEXT);
                """;
            cmd.ExecuteNonQuery();
            return Task.FromResult<System.Data.Common.DbConnection>(conn);
        }
    }
}
