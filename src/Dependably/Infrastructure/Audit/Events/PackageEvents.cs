using System.Text.Encodings.Web;
using System.Text.Json;

namespace Dependably.Infrastructure.Audit.Events;

internal static class EventJsonOptions
{
    /// <summary>
    /// snake_case for payload property names — keeps audit_event.payload greppable across
    /// event types and matches the wire-format convention used by the rest of the codebase.
    /// Uses the relaxed encoder so characters like <c>+</c>, <c>&amp;</c>, <c>&lt;</c>, <c>&gt;</c>
    /// round-trip as themselves instead of the default encoder's HTML-safe <c>\uXXXX</c> escapes —
    /// the audit UI renders payloads as plain text, not into HTML/JS, so that escaping only
    /// produces confusing literal escape sequences on screen.
    /// </summary>
    internal static readonly JsonSerializerOptions Snake = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>
    /// Options for inline anonymous-object audit/activity detail payloads that already
    /// hand-write their snake_case keys (no naming policy needed). Same relaxed encoder as
    /// <see cref="Snake"/> so detail JSON never HTML-escapes ordinary characters.
    /// </summary>
    internal static readonly JsonSerializerOptions Detail = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
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
    public const string TypeUnlist = "package.unlist";
    public const string TypeYank = "package.yank";
    public const string TypeVuln = "package.vuln";

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

    public sealed record Unlist(
        string Ecosystem,
        string Name,
        string Version,
        string Purl)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }

    public sealed record Yank(
        string Ecosystem,
        string Name,
        string Version,
        string Purl,
        string? Reason)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }

    /// <summary>
    /// Vuln payload carries IDs and severity only — bounded body size for the dispatch channel.
    /// </summary>
    public sealed record Vuln(
        string Ecosystem,
        string Name,
        string Version,
        string Purl,
        IReadOnlyList<VulnAdvisory> Advisories)
    {
        public string ToJson() => JsonSerializer.Serialize(this, EventJsonOptions.Snake);
    }

    /// <summary>Advisory summary: id + severity only.</summary>
    public sealed record VulnAdvisory(string Id, string? Severity);
}
