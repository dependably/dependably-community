using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dependably.Security;

namespace Dependably.Infrastructure.Webhooks;

/// <summary>
/// Delivers a signed webhook POST to a single subscriber URL. Mirrors the pattern used
/// by <see cref="Dependably.Infrastructure.Siem.WebhookSiemForwarder"/>:
/// snake_case body, <see cref="SocketsHttpHandler"/> with <c>AllowAutoRedirect=false</c>,
/// and a per-client <see cref="SsrfConnectCallback"/> wired at construction.
///
/// HMAC headers follow the GitHub-style convention:
///   X-Dependably-Signature: sha256={hex(HMAC-SHA256(secret, rawBodyBytes))}
///   X-Dependably-Event: {event_type}
///   X-Dependably-Delivery: {uuid}
///   X-Dependably-Timestamp: {iso8601}
///
/// When no secret is configured the Signature header is omitted; receivers must not
/// reject unsigned payloads unless they opt in by configuring a secret.
/// </summary>
public sealed class WebhookDeliveryClient
{
    private readonly HttpClient _http;

    public WebhookDeliveryClient(HttpClient http)
    {
        _http = http;
    }

    /// <summary>
    /// POSTs the envelope as a signed JSON webhook body to <paramref name="url"/>.
    /// Throws on non-2xx or network failure so the queue's retry path can record it.
    /// </summary>
    public async Task SendAsync(
        string url,
        string? secret,
        PackageEventEnvelope envelope,
        string deliveryId,
        CancellationToken ct)
    {
        byte[] bodyBytes = BuildPayloadBytes(envelope, deliveryId);

        using var req = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new ByteArrayContent(bodyBytes)
        };
        req.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json")
        {
            CharSet = "utf-8"
        };

        req.Headers.Add("X-Dependably-Event", envelope.EventType);
        req.Headers.Add("X-Dependably-Delivery", deliveryId);
        req.Headers.Add("X-Dependably-Timestamp", envelope.OccurredAt.ToUtcIso());

        if (!string.IsNullOrEmpty(secret))
        {
            string sig = ComputeHmacSha256Hex(secret, bodyBytes);
            req.Headers.Add("X-Dependably-Signature", $"sha256={sig}");
        }

        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        resp.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Validates a webhook URL string at save time. Applies the scheme allowlist and
    /// IP-literal check from <see cref="UpstreamUrlValidator"/>, then re-runs the
    /// IP-literal check with the always-blocked-only predicate when
    /// <paramref name="allowPrivate"/> is true.
    /// Returns a problem string on failure, null on success.
    /// </summary>
    internal static string? ValidateWebhookUrl(string url, bool allowPrivate)
    {
        string? baseError = UpstreamUrlValidator.ValidateUrl(url);
        if (baseError is null || !allowPrivate)
        {
            return baseError;
        }

        // Private allowed: re-validate with only the always-blocked ranges (loopback /
        // link-local / cloud-metadata), passing 10/8, 172.16/12, and 192.168/16 through
        // for self-hosted receivers on private networks.
        return !Uri.TryCreate(url, UriKind.Absolute, out var uri) ? "Invalid URL format."
            : uri.Scheme is not "http" and not "https" ? "Only http:// and https:// schemes are accepted."
            : System.Net.IPAddress.TryParse(uri.Host, out var ip) && SsrfGuard.IsBlockedIpExcludingPrivate(ip)
                ? $"Webhook URL resolves to a blocked IP range: {ip}"
                : null;
    }

    /// <summary>
    /// Builds the canonical JSON payload bytes. The <c>data</c> field embeds the
    /// pre-serialized event-specific JSON fragment verbatim as a nested object,
    /// not as a string. HMAC is computed over these exact bytes.
    /// </summary>
    internal static byte[] BuildPayloadBytes(PackageEventEnvelope envelope, string deliveryId)
    {
        // Build the top-level fields manually so we can embed DataJson as a raw JSON
        // fragment rather than a double-encoded string.
        using var ms = new System.IO.MemoryStream();
        using (var writer = new Utf8JsonWriter(ms))
        {
            writer.WriteStartObject();
            writer.WriteString("event", envelope.EventType);
            writer.WriteString("delivery_id", deliveryId);
            writer.WriteString("occurred_at", envelope.OccurredAt.ToUtcIso());
            writer.WriteString("org", envelope.OrgSlug);
            writer.WriteString("ecosystem", envelope.Ecosystem);
            writer.WriteString("name", envelope.Name);
            writer.WriteString("version", envelope.Version);
            writer.WriteString("purl", envelope.Purl);
            if (envelope.ArtifactHash is not null)
            {
                writer.WriteString("artifact_hash", envelope.ArtifactHash);
            }
            else
            {
                writer.WriteNull("artifact_hash");
            }

            if (envelope.Actor is not null)
            {
                writer.WriteString("actor", envelope.Actor);
            }
            else
            {
                writer.WriteNull("actor");
            }

            // Embed the pre-serialized event-specific JSON as a raw object fragment.
            writer.WritePropertyName("data");
            using var dataDoc = JsonDocument.Parse(envelope.DataJson);
            dataDoc.RootElement.WriteTo(writer);

            writer.WriteEndObject();
        }
        return ms.ToArray();
    }

    internal static string ComputeHmacSha256Hex(string secret, byte[] body)
    {
        byte[] key = Encoding.UTF8.GetBytes(secret);
        byte[] hash = HMACSHA256.HashData(key, body);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
