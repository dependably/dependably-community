using System.Net;
using Dependably.Infrastructure.Siem;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class WebhookSiemForwarderTests
{
    private static IConfiguration Cfg(params (string Key, string? Value)[] entries) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(e => new KeyValuePair<string, string?>(e.Key, e.Value)))
            .Build();

    private static SiemEvent SampleEvent() =>
        new(
            Id: "ev-1",
            Action: "login.success",
            Scope: "tenant",
            OrgId: "tenant-1",
            ActorId: "user-7",
            Ecosystem: null,
            Purl: null,
            Detail: null,
            CreatedAt: TestTime.KnownNow);

    [Fact]
    public void Constructor_MissingUrl_Throws()
    {
        var handler = new RecordingHandler(HttpStatusCode.OK);
        using var http = new HttpClient(handler);
        Assert.Throws<InvalidOperationException>(() => new WebhookSiemForwarder(http, Cfg()));
    }

    [Fact]
    public async Task SendAsync_PostsNdjson_ToConfiguredUrl()
    {
        var handler = new RecordingHandler(HttpStatusCode.NoContent);
        using var http = new HttpClient(handler);
        var sut = new WebhookSiemForwarder(http, Cfg(("SIEM_WEBHOOK_URL", "https://siem.test/ingest")));

        await sut.SendAsync(SampleEvent());

        Assert.NotNull(handler.LastRequest);
        Assert.Equal(HttpMethod.Post, handler.LastRequest!.Method);
        Assert.Equal(new Uri("https://siem.test/ingest"), handler.LastRequest.RequestUri);
        Assert.Equal("application/x-ndjson", handler.LastRequest.Content?.Headers.ContentType?.MediaType);
        Assert.NotNull(handler.LastBody);
        Assert.EndsWith("\n", handler.LastBody);
    }

    [Fact]
    public async Task SendAsync_BearerToken_SetWhenConfigured()
    {
        var handler = new RecordingHandler(HttpStatusCode.NoContent);
        using var http = new HttpClient(handler);
        var sut = new WebhookSiemForwarder(http, Cfg(
            ("SIEM_WEBHOOK_URL", "https://siem.test/ingest"),
            ("SIEM_WEBHOOK_BEARER", "tok-abc")));

        await sut.SendAsync(SampleEvent());

        var authz = handler.LastRequest?.Headers.Authorization;
        Assert.NotNull(authz);
        Assert.Equal("Bearer", authz!.Scheme);
        Assert.Equal("tok-abc", authz.Parameter);
    }

    [Fact]
    public async Task SendAsync_NoBearer_OmitsAuthorizationHeader()
    {
        var handler = new RecordingHandler(HttpStatusCode.NoContent);
        using var http = new HttpClient(handler);
        var sut = new WebhookSiemForwarder(http, Cfg(("SIEM_WEBHOOK_URL", "https://siem.test/ingest")));

        await sut.SendAsync(SampleEvent());

        Assert.Null(handler.LastRequest?.Headers.Authorization);
    }

    [Fact]
    public async Task SendAsync_NonSuccessStatus_Throws()
    {
        var handler = new RecordingHandler(HttpStatusCode.InternalServerError);
        using var http = new HttpClient(handler);
        var sut = new WebhookSiemForwarder(http, Cfg(("SIEM_WEBHOOK_URL", "https://siem.test/ingest")));

        await Assert.ThrowsAsync<HttpRequestException>(() => sut.SendAsync(SampleEvent()));
    }

    [Fact]
    public async Task SendAsync_EmptyBearer_OmitsAuthorizationHeader()
    {
        // Empty string must hit the IsNullOrEmpty short-circuit and skip Authorization,
        // distinct from the null-key path covered above.
        var handler = new RecordingHandler(HttpStatusCode.NoContent);
        using var http = new HttpClient(handler);
        var sut = new WebhookSiemForwarder(http, Cfg(
            ("SIEM_WEBHOOK_URL", "https://siem.test/ingest"),
            ("SIEM_WEBHOOK_BEARER", "")));

        await sut.SendAsync(SampleEvent());

        Assert.Null(handler.LastRequest?.Headers.Authorization);
    }

    [Fact]
    public void Name_Returns_Webhook()
    {
        var handler = new RecordingHandler(HttpStatusCode.NoContent);
        using var http = new HttpClient(handler);
        var sut = new WebhookSiemForwarder(http, Cfg(("SIEM_WEBHOOK_URL", "https://siem.test/ingest")));

        Assert.Equal("webhook", sut.Name);
    }

    [Fact]
    public async Task SendAsync_SerializesEventAsSnakeCaseJson()
    {
        var handler = new RecordingHandler(HttpStatusCode.NoContent);
        using var http = new HttpClient(handler);
        var sut = new WebhookSiemForwarder(http, Cfg(("SIEM_WEBHOOK_URL", "https://siem.test/ingest")));

        await sut.SendAsync(SampleEvent());

        Assert.NotNull(handler.LastBody);
        Assert.Contains("\"action\":\"login.success\"", handler.LastBody);
        Assert.Contains("\"org_id\":\"tenant-1\"", handler.LastBody);
        Assert.Contains("\"actor_id\":\"user-7\"", handler.LastBody);
        Assert.Contains("\"created_at\":", handler.LastBody);
    }

    [Fact]
    public async Task SendAsync_PropagatesCancellation()
    {
        var handler = new RecordingHandler(HttpStatusCode.NoContent);
        using var http = new HttpClient(handler);
        var sut = new WebhookSiemForwarder(http, Cfg(("SIEM_WEBHOOK_URL", "https://siem.test/ingest")));

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => sut.SendAsync(SampleEvent(), cts.Token));
    }

    // ── Response body never buffered ────────────────────────────────────────

    [Fact]
    public async Task SendAsync_DoesNotBufferResponseBody()
    {
        // The collector's response body is served from a stream that never completes a read —
        // it hangs forever. SendAsync only needs the status code (EnsureSuccessStatusCode), so
        // it must return well within the bound below regardless: HttpCompletionOption
        // .ResponseHeadersRead makes HttpClient hand back the response as soon as headers
        // arrive, without ever awaiting the body. The default option (ResponseContentRead)
        // buffers the whole body first and would hang on this stream indefinitely — a hostile
        // or malfunctioning collector could use exactly this shape to drive the process OOM by
        // returning a huge or slow-drip body instead.
        var handler = new RecordingHandler(HttpStatusCode.NoContent, respondWithHangingBody: true);
        using var http = new HttpClient(handler);
        var sut = new WebhookSiemForwarder(http, Cfg(("SIEM_WEBHOOK_URL", "https://siem.test/ingest")));

        var sendTask = sut.SendAsync(SampleEvent());
        var completed = await Task.WhenAny(sendTask, Task.Delay(TimeSpan.FromSeconds(5)));

        Assert.Same(sendTask, completed);
        await sendTask;
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly bool _respondWithHangingBody;
        public HttpRequestMessage? LastRequest { get; private set; }
        public string? LastBody { get; private set; }

        public RecordingHandler(HttpStatusCode status, bool respondWithHangingBody = false)
        {
            _status = status;
            _respondWithHangingBody = respondWithHangingBody;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // A real handler (SocketsHttpHandler) checks the token before opening the
            // connection; this in-memory double completes every step synchronously and would
            // otherwise never observe an already-cancelled token, which — combined with
            // HttpCompletionOption.ResponseHeadersRead skipping the body-buffering step where
            // .NET's ResponseContentRead path checks it — would make the cancellation test below
            // pass for the wrong reason (the call racing ahead of a check that never runs) rather
            // than for the real one (the call genuinely honouring the token).
            cancellationToken.ThrowIfCancellationRequested();
            LastRequest = request;
            LastBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            var response = new HttpResponseMessage(_status);
            if (_respondWithHangingBody)
            {
                response.Content = new StreamContent(new NeverCompletingStream());
            }
            return response;
        }
    }

    /// <summary>A response-body stand-in whose reads never complete — proves a caller that
    /// awaits the body would hang forever, and that <see cref="WebhookSiemForwarder"/> does not.</summary>
    private sealed class NeverCompletingStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => 0; set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException("Async-only stand-in.");

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            new TaskCompletionSource<int>().Task;

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
