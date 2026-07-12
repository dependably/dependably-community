using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// Posts a Slack incoming-webhook message: a bare <c>{"text": ...}</c> body, not the HMAC-signed
/// generic-webhook envelope <see cref="Webhooks.WebhookDeliveryClient"/> builds. Mirrors that
/// client's SSRF posture (dedicated typed <see cref="HttpClient"/>, <c>SocketsHttpHandler</c> with
/// <c>AllowAutoRedirect=false</c>, and a per-client SSRF connect-time guard wired at
/// registration) — the URL validator is shared verbatim via
/// <see cref="Webhooks.WebhookDeliveryClient.ValidateWebhookUrl"/> since a Slack webhook URL is
/// just as SSRF-sensitive as a generic one.
/// </summary>
public sealed class SlackWebhookClient
{
    private readonly HttpClient _http;

    public SlackWebhookClient(HttpClient http)
    {
        _http = http;
    }

    /// <summary>
    /// POSTs <paramref name="text"/> as a Slack incoming-webhook message to
    /// <paramref name="webhookUrl"/>. Throws on non-2xx or network failure so the caller's retry
    /// path can record it.
    /// </summary>
    public async Task SendAsync(string webhookUrl, string text, CancellationToken ct)
    {
        string body = JsonSerializer.Serialize(new SlackMessage(text));
        using var req = new HttpRequestMessage(HttpMethod.Post, webhookUrl)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };
        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        resp.EnsureSuccessStatusCode();
    }

    // Slack's incoming-webhook contract requires the lowercase key "text"; the record property
    // is capitalized for C# convention, so the JSON name is pinned explicitly.
    private sealed record SlackMessage([property: JsonPropertyName("text")] string Text);
}
