using System.Net;
using Dependably.Infrastructure.Siem;
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
            CreatedAt: DateTimeOffset.UtcNow);

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

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        public HttpRequestMessage? LastRequest { get; private set; }
        public string? LastBody { get; private set; }

        public RecordingHandler(HttpStatusCode status) => _status = status;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            LastBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(_status);
        }
    }
}
