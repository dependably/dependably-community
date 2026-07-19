using System.Linq;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Regression coverage for the Cargo crate-download host-pin: <see cref="CargoController"/>
/// rewrites the download base to a different hardcoded host (<c>static.crates.io</c>) when the
/// configured upstream is <c>index.crates.io</c>. The configured upstream's stored Authorization
/// header must never ride along to that switched host — only when the resolved download URL
/// stays on the configured upstream's own host.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CargoDownloadUpstreamAuthHostPinningTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public Task InitializeAsync() => new SchemaInitializer(_db).InitializeAsync();
    public Task DisposeAsync() => _db.DisposeAsync().AsTask();

    private UpstreamClient BuildUpstreamClient(IBlobStore blobs, CapturingHttpHandler handler)
    {
        var httpFactory = new StaticHttpClientFactory(new HttpClient(handler));
        var tiered = new TieredBlobStorage(blobs, blobs);
        var audit = new AuditRepository(_db);
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = Path.Combine(Path.GetTempPath(),
                    $"dependably-cargo-authpin-{Guid.NewGuid():N}"),
            })
            .Build();
        return new UpstreamClient(
            httpFactory, tiered, audit, new AllowAllValidator(), new StubAirGapMode(),
            new DriveInfoStagingDiskInfo(Path.GetTempPath()),
            StagingOptions.Resolve(config), NullLogger<UpstreamClient>.Instance);
    }

    [Fact]
    public async Task DownloadFetch_IndexCratesIoUpstreamWithCredential_DoesNotAttachAuthHeaderToStaticCratesIo()
    {
        const string name = "widget";
        const string version = "1.0.0";
        const string credential = "Bearer index-crates-io-secret";
        const string upstreamBase = "https://index.crates.io";

        // BuildCrateDownloadUrl rewrites index.crates.io to the static.crates.io CDN — a
        // different host than the configured upstream.
        string downloadUrl = CargoController.BuildCrateDownloadUrl(upstreamBase, name, version);
        Assert.StartsWith("https://static.crates.io/crates/", downloadUrl);

        // The host-pinned decision the real ProxyCrateFromUpstreamAsync call site makes.
        string? downloadAuthorizationHeader =
            CargoController.ResolveDownloadAuthorizationHeader(upstreamBase, downloadUrl, credential);
        Assert.Null(downloadAuthorizationHeader);

        var handler = new CapturingHttpHandler("crate-bytes"u8.ToArray());
        var client = BuildUpstreamClient(new InMemoryBlobStore(), handler);
        string blobKey = BlobKeys.Cargo("org-x", name, version);

        await client.GetOrFetchToBlobKeyAsync(
            blobKey, downloadUrl, checksumSpec: null, "cargo", "org-x",
            authorizationHeader: downloadAuthorizationHeader);

        Assert.Equal(1, handler.CallCount);
        Assert.Equal(downloadUrl, handler.LastRequestUri?.ToString());
        Assert.Null(handler.LastAuthorizationHeader);
    }

    [Fact]
    public async Task DownloadFetch_SameHostSparseRegistryWithCredential_AttachesAuthHeader()
    {
        const string name = "widget";
        const string version = "1.0.0";
        const string credential = "Bearer own-host-secret";
        const string upstreamBase = "https://private-sparse-registry.test";

        string downloadUrl = CargoController.BuildCrateDownloadUrl(upstreamBase, name, version);
        Assert.StartsWith("https://private-sparse-registry.test/api/v1/crates/", downloadUrl);

        string? downloadAuthorizationHeader =
            CargoController.ResolveDownloadAuthorizationHeader(upstreamBase, downloadUrl, credential);
        Assert.Equal(credential, downloadAuthorizationHeader);

        var handler = new CapturingHttpHandler("crate-bytes"u8.ToArray());
        var client = BuildUpstreamClient(new InMemoryBlobStore(), handler);
        string blobKey = BlobKeys.Cargo("org-x", name, version);

        await client.GetOrFetchToBlobKeyAsync(
            blobKey, downloadUrl, checksumSpec: null, "cargo", "org-x",
            authorizationHeader: downloadAuthorizationHeader);

        Assert.Equal(1, handler.CallCount);
        Assert.Equal(downloadUrl, handler.LastRequestUri?.ToString());
        Assert.Equal(credential, handler.LastAuthorizationHeader);
    }

    private sealed class StubAirGapMode : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    private sealed class AllowAllValidator : IUpstreamUrlValidator
    {
        public Task<UpstreamUrlBlock> CheckAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(UpstreamUrlBlock.None);
    }

    private sealed class StaticHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public StaticHttpClientFactory(HttpClient client) => _client = client;
        public HttpClient CreateClient(string name) => _client;
    }

    /// <summary>Records the last outgoing request's URI and Authorization header, and answers
    /// a fixed byte body — used to observe exactly what <see cref="UpstreamClient"/> sent
    /// without any real network egress.</summary>
    private sealed class CapturingHttpHandler(byte[] body) : HttpMessageHandler
    {
        public int CallCount { get; private set; }
        public Uri? LastRequestUri { get; private set; }
        public string? LastAuthorizationHeader { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            CallCount++;
            LastRequestUri = request.RequestUri;
            LastAuthorizationHeader = request.Headers.TryGetValues("Authorization", out var values)
                ? values.FirstOrDefault()
                : null;
            var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(body),
            };
            return Task.FromResult(response);
        }
    }
}
