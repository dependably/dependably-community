namespace Dependably.Infrastructure.Webhooks;

/// <summary>
/// Envelope that wraps a package event for delivery to webhook subscribers.
/// Carries the event type, the org that owns the package, the package coordinates,
/// and a pre-serialized JSON body (snake_case, for outbound webhook delivery).
///
/// The delivery id is assigned at enqueue time (not here) so the queue worker
/// stamps it per delivery rather than once per event.
/// </summary>
public sealed record PackageEventEnvelope(
    string EventType,
    string OrgId,
    string OrgSlug,
    string Ecosystem,
    string Name,
    string Version,
    string Purl,
    string? ArtifactHash,
    string? Actor,
    DateTimeOffset OccurredAt,
    /// <summary>
    /// Event-specific additional data. Already serialized to JSON (snake_case).
    /// Embedded verbatim in the outbound payload's "data" field.
    /// </summary>
    string DataJson);
