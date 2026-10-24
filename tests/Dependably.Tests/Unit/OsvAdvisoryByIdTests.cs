using System.Net;
using System.Text;
using Dependably.Protocol;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// <see cref="IOsvSource.TryGetAdvisoryAsync"/> must keep "the source does not know this id" apart
/// from "the source could not answer": the first lets a caller drop a scanner's fabricated id, the
/// second must refuse the result for a retry rather than trust anything else. Covered for the
/// remote client, the sideloaded dumps, and the interface default.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OsvAdvisoryByIdTests : IDisposable
{
    private const string Record = """
        {
          "id": "DSA-5990-1",
          "aliases": ["CVE-2026-40404"],
          "summary": "openssl buffer over-read",
          "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" }],
          "affected": [{ "package": { "ecosystem": "Debian:12", "name": "openssl" }, "versions": ["3.0.11-1~deb12u1"] }]
        }
        """;

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "osvbyid_" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    [Fact]
    public async Task Remote_AKnownId_IsReachedWithTheRecord()
    {
        var (osv, handler) = Remote(HttpStatusCode.OK, Record);

        var result = await osv.TryGetAdvisoryAsync("DSA-5990-1");

        Assert.True(result.Reached);
        Assert.Equal("DSA-5990-1", result.Advisory!.Id);
        Assert.Equal(7.5, result.Advisory.CvssScore);
        Assert.True(result.Advisory.IsHydrated);
        Assert.Equal("/v1/vulns/DSA-5990-1", handler.LastPath);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.BadRequest)]
    public async Task Remote_AnIdOsvDoesNotHold_IsReachedWithNothing(HttpStatusCode status)
    {
        var (osv, _) = Remote(status, """{"code":5,"message":"Bug not found."}""");

        var result = await osv.TryGetAdvisoryAsync("GHSA-zz99-fake-0001");

        Assert.True(result.Reached);
        Assert.Null(result.Advisory);
    }

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.BadGateway)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task Remote_AnOutage_IsUnreached(HttpStatusCode status)
    {
        var (osv, _) = Remote(status, "");

        var result = await osv.TryGetAdvisoryAsync("DSA-5990-1");

        Assert.False(result.Reached);
        Assert.Null(result.Advisory);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("")]
    [InlineData("null")]
    [InlineData("{}")]
    public async Task Remote_A200ThatIsNotARecord_IsUnreached_NeverUnknown(string body)
    {
        var (osv, _) = Remote(HttpStatusCode.OK, body);

        var result = await osv.TryGetAdvisoryAsync("DSA-5990-1");

        Assert.False(result.Reached);
        Assert.Null(result.Advisory);
    }

    [Fact]
    public async Task Remote_ARateLimitThatOutlastsTheRetries_IsUnreached()
    {
        int calls = 0;
        var handler = new StubHandler(_ =>
        {
            Interlocked.Increment(ref calls);
            var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
            response.Headers.Add("Retry-After", "0");
            return response;
        });
        var osv = new OsvClient(new SingleHandlerFactory(handler), NullLogger<OsvClient>.Instance);

        var result = await osv.TryGetAdvisoryAsync("DSA-5990-1");

        Assert.False(result.Reached);
        Assert.Equal(3, calls);
    }

    [Fact]
    public async Task Local_AnIdIsMatchedWithoutRegardToCase()
    {
        Directory.CreateDirectory(_dir);
        await File.WriteAllTextAsync(Path.Combine(_dir, "DSA-5990-1.json"), Record);
        var local = new LocalOsvSource(_dir, NullLogger<LocalOsvSource>.Instance);

        var result = await local.TryGetAdvisoryAsync("dsa-5990-1");

        Assert.True(result.Reached);
        Assert.Equal("DSA-5990-1", result.Advisory!.Id);
    }

    [Fact]
    public async Task Remote_AnHttpClientTimeout_IsUnreached_NotAnException()
    {
        var osv = new OsvClient(new HangingFactory(), NullLogger<OsvClient>.Instance);

        var result = await osv.TryGetAdvisoryAsync("DSA-5990-1");

        Assert.False(result.Reached);
        Assert.Null(result.Advisory);
    }

    [Fact]
    public async Task Remote_AnHttpClientTimeout_OnAPurlQuery_IsUnreached()
    {
        var osv = new OsvClient(new HangingFactory(), NullLogger<OsvClient>.Instance);

        var result = await osv.TryQueryAsync("pkg:npm/left-pad@1.3.0");

        Assert.False(result.Reached);
    }

    [Fact]
    public async Task Remote_ACallerCancellation_StillPropagates()
    {
        var osv = new OsvClient(new HangingFactory(TimeSpan.FromMinutes(5)), NullLogger<OsvClient>.Instance);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => osv.TryGetAdvisoryAsync("DSA-5990-1", cts.Token));
    }

    [Fact]
    public async Task Remote_ATransportFailure_IsUnreached()
    {
        var handler = new StubHandler(_ => throw new HttpRequestException("connection refused"));
        var osv = new OsvClient(new SingleHandlerFactory(handler), NullLogger<OsvClient>.Instance);

        var result = await osv.TryGetAdvisoryAsync("DSA-5990-1");

        Assert.False(result.Reached);
    }

    [Fact]
    public async Task Remote_AnIdIsEscapedIntoOnePathSegment()
    {
        var (osv, handler) = Remote(HttpStatusCode.NotFound, "");

        await osv.TryGetAdvisoryAsync("../querybatch?x=1");

        Assert.Equal("/v1/vulns/..%2Fquerybatch%3Fx%3D1", handler.LastPath);
    }

    [Fact]
    public async Task Local_AKnownId_IsReached_AndAnUnknownOneIsReachedWithNothing()
    {
        Directory.CreateDirectory(_dir);
        await File.WriteAllTextAsync(Path.Combine(_dir, "DSA-5990-1.json"), Record);
        var local = new LocalOsvSource(_dir, NullLogger<LocalOsvSource>.Instance);

        var known = await local.TryGetAdvisoryAsync("DSA-5990-1");
        var unknown = await local.TryGetAdvisoryAsync("GHSA-zz99-fake-0001");

        Assert.True(known.Reached);
        Assert.Equal(7.5, known.Advisory!.CvssScore);
        Assert.True(unknown.Reached);
        Assert.Null(unknown.Advisory);
    }

    [Fact]
    public async Task Local_AMissingDumpDirectory_IsUnreached()
    {
        var local = new LocalOsvSource(_dir, NullLogger<LocalOsvSource>.Instance);

        var result = await local.TryGetAdvisoryAsync("DSA-5990-1");

        Assert.False(result.Reached);
    }

    [Fact]
    public async Task TheInterfaceDefault_IsUnreached_NeverUnknown()
    {
        IOsvSource source = new QueryOnlySource();

        var result = await source.TryGetAdvisoryAsync("DSA-5990-1");

        Assert.False(result.Reached);
    }

    private static (OsvClient Client, StubHandler Handler) Remote(HttpStatusCode status, string body)
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(status)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        });
        return (new OsvClient(new SingleHandlerFactory(handler), NullLogger<OsvClient>.Instance), handler);
    }

    private sealed class QueryOnlySource : IOsvSource
    {
        public Task<List<OsvAdvisory>> QueryAsync(string purl, CancellationToken ct = default) => Task.FromResult(new List<OsvAdvisory>());

        public Task<List<List<OsvAdvisory>>> QueryBatchAsync(IReadOnlyList<string> purls, CancellationToken ct = default) =>
            Task.FromResult(purls.Select(_ => new List<OsvAdvisory>()).ToList());
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public string? LastPath { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastPath = request.RequestUri!.AbsolutePath;
            return Task.FromResult(respond(request));
        }
    }

    private sealed class SingleHandlerFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(handler, disposeHandler: false) { BaseAddress = new Uri("https://api.osv.dev/v1/") };
    }

    private sealed class HangingHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // now-ok: waits only for the HttpClient timeout or the caller's cancellation to fire.
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    private sealed class HangingFactory(TimeSpan? timeout = null) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(new HangingHandler(), disposeHandler: true)
            {
                BaseAddress = new Uri("https://api.osv.dev/v1/"),
                Timeout = timeout ?? TimeSpan.FromMilliseconds(100),
            };
    }
}
