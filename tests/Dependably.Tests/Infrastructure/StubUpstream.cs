using System.Net;
using System.Text;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// A real <see cref="UpstreamClient"/> whose HTTP layer is a per-request function, over an
/// in-memory blob store and an in-memory SQLite audit store. Upstream failures are injected by
/// returning a status or throwing from the responder, never by sleeping.
/// </summary>
public sealed class StubUpstream : IAsyncDisposable
{
    private StubUpstream(
        TestMetadataStore db, InMemoryBlobStore blobs, UpstreamClient client, RequestLog requests)
    {
        Db = db;
        Blobs = blobs;
        Client = client;
        Requests = requests;
    }

    public TestMetadataStore Db { get; }

    public InMemoryBlobStore Blobs { get; }

    public UpstreamClient Client { get; }

    /// <summary>Every request the upstream saw, in order.</summary>
    public RequestLog Requests { get; }

    public static async Task<StubUpstream> CreateAsync(
        Func<HttpRequestMessage, HttpResponseMessage> responder,
        bool airGapped = false,
        IUpstreamUrlValidator? validator = null,
        MetadataResponseCache? metadataCache = null,
        IStagingDiskInfo? stagingDisk = null,
        string? stagingPath = null,
        Func<IBlobStore, IBlobStore>? wrapBlobs = null)
    {
        var db = new TestMetadataStore();
        await new SchemaInitializer(db).InitializeAsync();
        var blobs = new InMemoryBlobStore();
        var log = new RequestLog();
        string staging = stagingPath ?? Path.Combine(Path.GetTempPath(), $"dependably-stub-{Guid.NewGuid():N}");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["PROXY_STAGING_PATH"] = staging })
            .Build();
        var client = new UpstreamClient(
            new Factory(new Handler(responder, log)),
            new TieredBlobStorage(wrapBlobs?.Invoke(blobs) ?? blobs, wrapBlobs?.Invoke(blobs) ?? blobs),
            new AuditRepository(db),
            validator ?? new Allow(),
            new AirGap(airGapped),
            stagingDisk ?? new DriveInfoStagingDiskInfo(staging),
            StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance,
            metadataCache: metadataCache);
        return new StubUpstream(db, blobs, client, log);
    }

    public static HttpResponseMessage Text(string body, HttpStatusCode status = HttpStatusCode.OK, string mediaType = "application/json")
        => new(status) { Content = new StringContent(body, Encoding.UTF8, mediaType) };

    public static HttpResponseMessage Status(HttpStatusCode status) => new(status);

    public ValueTask DisposeAsync() => Db.DisposeAsync();

    public sealed class RequestLog
    {
        private readonly List<string> _urls = new();

        public IReadOnlyList<string> Urls => _urls;

        internal void Add(string url) => _urls.Add(url);
    }

    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> responder, RequestLog log) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            log.Add(request.RequestUri!.ToString());
            return Task.FromResult(responder(request));
        }
    }

    private sealed class Factory(HttpMessageHandler handler) : IHttpClientFactory
    {
        private readonly HttpClient _client = new(handler);

        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class Allow : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.None);
    }

    private sealed class AirGap(bool enabled) : IAirGapMode
    {
        public bool IsEnabled => enabled;

        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();

        public bool IsJobDisabled(string jobName) => enabled;
    }
}
