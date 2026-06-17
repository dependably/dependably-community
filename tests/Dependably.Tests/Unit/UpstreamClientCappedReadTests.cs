using System.Net;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Buffered upstream reads are capped: <see cref="UpstreamClient.ReadBodyCappedAsync"/> is the
/// single helper every buffered consumer routes through, failing fast on a declared
/// Content-Length above the cap and counting the copied bytes so chunked / auto-decompressed
/// transfers cannot inflate past the cap into managed memory.
/// </summary>
[Trait("Category", "Unit")]
public class UpstreamClientCappedReadTests
{
    private static HttpResponseMessage OkResponse(byte[] body)
        => new(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };

    // ── ReadBodyCappedAsync ───────────────────────────────────────────────────

    [Fact]
    public async Task ReadBodyCappedAsync_BodyUnderCap_ReturnsBytesIntact()
    {
        byte[] body = new byte[1024];
        Random.Shared.NextBytes(body);
        using var response = OkResponse(body);

        byte[] read = await UpstreamClient.ReadBodyCappedAsync(
            response, maxBytes: 2048, "http://upstream.test/doc", CancellationToken.None);

        Assert.Equal(body, read);
    }

    [Fact]
    public async Task ReadBodyCappedAsync_BodyOverCap_ThrowsTooLarge()
    {
        // Strip the Content-Length header so the counted copy loop — not the fail-fast
        // header check — has to enforce the cap (the chunked / decompressed-transfer case).
        byte[] body = new byte[4096];
        using var response = OkResponse(body);
        response.Content.Headers.ContentLength = null;

        await Assert.ThrowsAsync<UpstreamResponseTooLargeException>(() =>
            UpstreamClient.ReadBodyCappedAsync(
                response, maxBytes: 1024, "http://upstream.test/bomb", CancellationToken.None));
    }

    [Fact]
    public async Task ReadBodyCappedAsync_ContentLengthOverCap_FailsBeforeReadingBody()
    {
        var content = new PoisonContent(declaredLength: 10_000);
        using var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = content };

        await Assert.ThrowsAsync<UpstreamResponseTooLargeException>(() =>
            UpstreamClient.ReadBodyCappedAsync(
                response, maxBytes: 1024, "http://upstream.test/declared-huge", CancellationToken.None));

        // The declared Content-Length alone must trigger the failure — the body stream
        // is never opened.
        Assert.False(content.StreamOpened);
    }

    [Fact]
    public async Task ReadBodyCappedAsync_ExactlyAtCap_ReturnsBytesIntact()
    {
        byte[] body = new byte[1024];
        Random.Shared.NextBytes(body);
        using var response = OkResponse(body);

        byte[] read = await UpstreamClient.ReadBodyCappedAsync(
            response, maxBytes: 1024, "http://upstream.test/exact", CancellationToken.None);

        Assert.Equal(body, read);
    }

    // ── GetOrFetchMetadataAsync caps ──────────────────────────────────────────

    [Fact]
    public async Task GetOrFetchMetadataAsync_MixedFetches_OverCapThrowsAndUnderCapSucceeds()
    {
        // Mixed scenario through one client: the over-cap fetch fails, and a subsequent
        // under-cap fetch on the same client passes through intact — a single hostile
        // upstream response must not poison the fetch path for everything else.
        byte[] small = new byte[64];
        Random.Shared.NextBytes(small);
        byte[] huge = new byte[8192];

        var hugeResponse = OkResponse(huge);
        hugeResponse.Content.Headers.ContentLength = null; // force the counted-copy path

        var handler = new RoutedFakeHandler();
        handler.Responses["http://upstream.test/huge.tgz"] = hugeResponse;
        handler.Responses["http://upstream.test/small.json"] = OkResponse(small);
        var client = BuildClient(handler);

        await Assert.ThrowsAsync<UpstreamResponseTooLargeException>(() =>
            client.GetOrFetchMetadataAsync("http://upstream.test/huge.tgz", maxBytes: 1024));

        var ok = await client.GetOrFetchMetadataAsync("http://upstream.test/small.json", maxBytes: 1024);
        Assert.True(ok.IsSuccessStatusCode);
        Assert.Equal(small, ok.Body);
    }

    [Fact]
    public async Task GetOrFetchMetadataAsync_DefaultCap_RejectsDeclaredOversizeBody()
    {
        // The default overload applies the metadata cap; a Content-Length above it fails
        // fast without buffering anything.
        var content = new PoisonContent(declaredLength: UpstreamClient.MaxMetadataResponseBytes + 1);
        var handler = new RoutedFakeHandler();
        handler.Responses["http://upstream.test/huge-metadata"] =
            new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
        var client = BuildClient(handler);

        await Assert.ThrowsAsync<UpstreamResponseTooLargeException>(() =>
            client.GetOrFetchMetadataAsync("http://upstream.test/huge-metadata"));
        Assert.False(content.StreamOpened);
    }

    [Fact]
    public async Task GetOrFetchMetadataAsync_ExplicitArtifactCap_AllowsBodyAboveMetadataCap()
    {
        // Artifact consumers (npm tarballs, NuGet flatcontainer, Maven fetch-then-hash)
        // pass the artifact cap explicitly; a declared length the metadata cap would
        // reject passes under the artifact cap.
        byte[] body = new byte[256];
        Random.Shared.NextBytes(body);

        var handler = new RoutedFakeHandler();
        var response = OkResponse(body);
        response.Content.Headers.ContentLength = UpstreamClient.MaxMetadataResponseBytes + 1;
        handler.Responses["http://upstream.test/artifact.nupkg"] = response;
        var client = BuildClient(handler);

        var ok = await client.GetOrFetchMetadataAsync(
            "http://upstream.test/artifact.nupkg", UpstreamClient.MaxUpstreamResponseBytes);
        Assert.Equal(body, ok.Body);
    }

    // ── Helpers / doubles ─────────────────────────────────────────────────────

    private static UpstreamClient BuildClient(HttpMessageHandler handler)
    {
        var store = new InMemoryBlobStore();
        string stagingDir = Path.Combine(Path.GetTempPath(), $"dependably-test-{Guid.NewGuid():N}");
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["PROXY_STAGING_PATH"] = stagingDir })
            .Build();
        return new UpstreamClient(
            new SingleClientFactory(handler),
            new TieredBlobStorage(store, store),
            new AuditRepository(new TestMetadataStore()),
            new PermissiveValidator(),
            new DisabledAirGap(),
            new Dependably.Infrastructure.DriveInfoStagingDiskInfo(stagingDir),
            Dependably.Infrastructure.StagingOptions.Resolve(config),
            NullLogger<UpstreamClient>.Instance);
    }

    /// <summary>HttpContent that declares a Content-Length but throws if its body is ever read.</summary>
    private sealed class PoisonContent : HttpContent
    {
        private readonly long _declaredLength;

        public PoisonContent(long declaredLength) => _declaredLength = declaredLength;

        public bool StreamOpened { get; private set; }

        protected override Task SerializeToStreamAsync(Stream stream, System.Net.TransportContext? context)
        {
            StreamOpened = true;
            throw new InvalidOperationException("Body must not be read when Content-Length exceeds the cap.");
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _declaredLength;
            return true;
        }
    }

    private sealed class RoutedFakeHandler : HttpMessageHandler
    {
        public Dictionary<string, HttpResponseMessage> Responses { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(Responses[request.RequestUri!.ToString()]);
    }

    private sealed class SingleClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public SingleClientFactory(HttpMessageHandler handler) => _client = new HttpClient(handler);
        public HttpClient CreateClient(string name) => _client;
    }

    private sealed class PermissiveValidator : IUpstreamUrlValidator
    {
        public Task<bool> IsAllowedAsync(string url, string? orgId, CancellationToken ct = default)
            => Task.FromResult(true);
    }

    private sealed class DisabledAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }
}
