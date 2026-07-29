using System.Text.Json;
using System.Text.Json.Serialization;

namespace Dependably.Infrastructure.Caching;

/// <summary>
/// Wire codec for a <see cref="MetadataInvalidation"/> crossing the replica-to-replica fan-out
/// channel. Lives in Core (rather than beside the Redis transport) so the message format is
/// testable without a broker and so any future transport encodes the identical bytes.
///
/// The payload is snake_case JSON — an external wire format, matching the convention the OSV,
/// SIEM, and audit payloads follow, not the camelCase the browser consumes. It carries a schema
/// version so a rolling deploy in which two builds share one channel degrades to "ignore what you
/// do not understand" instead of mis-parsing: <see cref="TryDecode"/> returns
/// <see langword="false"/> for an unknown version, an unknown ecosystem, or malformed JSON, and
/// the receiver falls back to TTL expiry for that message.
///
/// <c>origin</c> is the sending replica's process id. A replica evicts locally before publishing,
/// so its own message coming back round is redundant work; the subscriber drops it by comparing
/// origins, which also keeps the received counter measuring genuine cross-replica fan-out.
/// </summary>
public static class MetadataInvalidationCodec
{
    /// <summary>Current wire schema version. Bump only on a breaking field change.</summary>
    public const int SchemaVersion = 1;

    private static readonly JsonSerializerOptions WireOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Encodes <paramref name="invalidation"/> for transmission, stamped with <paramref name="origin"/>.</summary>
    public static string Encode(MetadataInvalidation invalidation, string origin) =>
        JsonSerializer.Serialize(
            new Envelope
            {
                V = SchemaVersion,
                Origin = origin,
                Ecosystem = invalidation.Ecosystem,
                OrgId = invalidation.OrgId,
                Name = invalidation.Name,
                GroupId = invalidation.GroupId,
                ArtifactId = invalidation.ArtifactId,
                Version = invalidation.Version,
            },
            WireOptions);

    /// <summary>
    /// Decodes a received payload. Returns <see langword="false"/> — never throws — for malformed
    /// JSON, an unknown schema version, an unknown ecosystem, or a missing org, so a bad or
    /// future-shaped message degrades to TTL expiry instead of faulting the subscriber loop.
    /// </summary>
    public static bool TryDecode(string? payload, out MetadataInvalidation invalidation, out string origin)
    {
        invalidation = null!;
        origin = string.Empty;

        if (string.IsNullOrWhiteSpace(payload))
        {
            return false;
        }

        Envelope? envelope;
        try
        {
            envelope = JsonSerializer.Deserialize<Envelope>(payload, WireOptions);
        }
        catch (JsonException)
        {
            return false;
        }

        if (envelope is null
            || envelope.V != SchemaVersion
            || string.IsNullOrEmpty(envelope.OrgId)
            || !MetadataInvalidationEcosystems.IsKnown(envelope.Ecosystem))
        {
            return false;
        }

        origin = envelope.Origin ?? string.Empty;
        invalidation = new MetadataInvalidation
        {
            OrgId = envelope.OrgId,
            Ecosystem = envelope.Ecosystem!,
            Name = envelope.Name,
            GroupId = envelope.GroupId,
            ArtifactId = envelope.ArtifactId,
            Version = envelope.Version,
        };
        return true;
    }

    // Transport shape. Separate from MetadataInvalidation so the domain record carries no
    // transport fields (schema version, origin replica).
    private sealed class Envelope
    {
        public int V { get; set; }
        public string? Origin { get; set; }
        public string? Ecosystem { get; set; }
        public string? OrgId { get; set; }
        public string? Name { get; set; }
        public string? GroupId { get; set; }
        public string? ArtifactId { get; set; }
        public string? Version { get; set; }
    }
}
