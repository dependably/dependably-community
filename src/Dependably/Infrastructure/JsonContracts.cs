using System.Text.Json;

namespace Dependably.Infrastructure;

/// <summary>
/// Shared serializer-options singletons for the frontend/backend JSON contract. Anything the
/// browser/Svelte frontend consumes serializes camelCase via <see cref="Web"/> — the C# default
/// <c>JsonSerializer.Serialize(obj)</c> with no options emits PascalCase, which the frontend does
/// not read and which surfaces as a runtime crash, not a compile error. External wire formats
/// (OSV, SIEM, audit events) deliberately use their own snake_case options
/// (<c>Dependably.Infrastructure.Audit.Events.EventJsonOptions</c>) and stay separate from this one.
/// </summary>
internal static class JsonContracts
{
    /// <summary>camelCase options for frontend-facing management API payloads.</summary>
    internal static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);
}
