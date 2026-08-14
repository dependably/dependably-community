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

        // Refuse a cleartext collector at construction — before a single event is posted. The
        // payload carries actor ids and the typed detail, and SIEM_WEBHOOK_BEARER rides the same
        // request, so an http:// collector leaks both the personal data and the credential that
        // authenticates to it. Startup is the only point at which refusing costs nothing; by
        // SendAsync the events are already flowing.
        //
        // Failing at construction rather than warning is the difference from the syslog path: a
        // syslog operator picked a transport explicitly, whereas a URL's scheme is easy to paste
        // wrong, and there is a correct value one character away.
        if (!_url.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && !AllowsInsecure(config))
        {
            throw new InvalidOperationException(
                $"SIEM_WEBHOOK_URL must use https (got '{_url.Scheme}'). Audit events carry actor ids, " +
                "event payloads, and the SIEM_WEBHOOK_BEARER credential. Set SIEM_WEBHOOK_ALLOW_INSECURE=true " +
                "to send them in cleartext anyway (e.g. a collector on a trusted loopback interface).");
        }
    }

    // Accepts the spellings an operator plausibly writes in a compose file.
    private static bool AllowsInsecure(IConfiguration config)
    {
        string? raw = config["SIEM_WEBHOOK_ALLOW_INSECURE"]?.Trim();
        return raw is not null
            && (raw.Equals("true", StringComparison.OrdinalIgnoreCase)
                || raw == "1"
                || raw.Equals("yes", StringComparison.OrdinalIgnoreCase));
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

        // ResponseHeadersRead: the forwarder only needs the status code, so the response body —
        // fully attacker-controlled by whatever answers at SIEM_WEBHOOK_URL — is never buffered
        // into managed memory. Mirrors WebhookDeliveryClient/SlackWebhookClient, which read from
        // the same class of caller/operator-supplied endpoint.
        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        resp.EnsureSuccessStatusCode();
    }
}
