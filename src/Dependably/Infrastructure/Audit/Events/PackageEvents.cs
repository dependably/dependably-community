using System.Text.Json;

namespace Dependably.Infrastructure.Audit.Events;

internal static class EventJsonOptions
{
    /// <summary>
    /// snake_case for payload property names — keeps audit_event.payload greppable across
    /// event types and matches the wire-format convention used by the rest of the codebase.
    /// </summary>
    internal static readonly JsonSerializerOptions Snake = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };
}

/// <summary>
/// Typed payload shapes for package-level audit events. Each record's
/// <c>ToJson()</c> produces the JSON body the audit_event row's <c>payload</c> column
/// expects. Required-init properties enforce that mandatory fields land in every event;
/// missing data fails at construction rather than on read.
///
/// Adding a new event type does not require a schema migration — <c>audit_event.payload</c>
/// is freeform JSON. Bump <c>schema_version</c> when changing an existing event's shape.
/// </summary>
public static class PackageEvents
{
    public const string TypePublish = "package.publish";
    public const string TypeReplace = "package.replace";
    public const string TypeImport = "package.import";

    public sealed record Publish(
        string Ecosystem,
        string Name,
        string Version,
        string Filename,
        string ArtifactHash,
        long SizeBytes,
        string Origin,
        string ClaimState)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }

    public sealed record Replace(
        string Ecosystem,
        string Name,
        string Version,
        string Filename,
        string ArtifactHash,
        string PriorArtifactHash,
        long SizeBytes,
        string Origin,
        string ClaimState)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }

    public sealed record Import(
        string Ecosystem,
        string Name,
        string Version,
        string Filename,
        string ArtifactHash,
        long SizeBytes,
        string Origin,
        string BatchId,
        string ImportMode,
        string ClaimState)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }
}
