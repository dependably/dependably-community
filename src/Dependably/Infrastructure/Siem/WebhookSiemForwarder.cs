using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Dependably.Infrastructure.Siem;

/// <summary>
/// POSTs each event as one NDJSON line to the configured collector URL. Optional bearer
/// token via <c>SIEM_WEBHOOK_BEARER</c>. Failure throws so the queue's retry path can record
/// it; the queue, not the forwarder, owns drop-with-metric on overflow.
/// </summary>
public sealed class WebhookSiemForwarder : ISiemForwarder
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };

    private readonly HttpClient _http;
    private readonly Uri _url;
    private readonly string? _bearer;

    public WebhookSiemForwarder(HttpClient http, IConfiguration config)
    {
        _http = http;
        string url = config["SIEM_WEBHOOK_URL"]
            ?? throw new InvalidOperationException("SIEM_WEBHOOK_URL is required for WebhookSiemForwarder.");
        _url = new Uri(url, UriKind.Absolute);
        _bearer = config["SIEM_WEBHOOK_BEARER"];
    }

    public string Name => "webhook";

    public async Task SendAsync(SiemEvent ev, CancellationToken ct = default)
    {
        string json = JsonSerializer.Serialize(ev, JsonOpts);
        using var req = new HttpRequestMessage(HttpMethod.Post, _url)
        {
            Content = new StringContent(json + "\n", Encoding.UTF8, "application/x-ndjson")
        };
        if (!string.IsNullOrEmpty(_bearer))
        {
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _bearer);
        }

        using var resp = await _http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
    }
}
