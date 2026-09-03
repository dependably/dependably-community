using System.Text.Json;

namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// Null-tolerant readers over a <see cref="JsonElement"/>, shared by the three document parsers.
///
/// <para>Every accessor answers "absent" for a property that is missing, JSON null, or present
/// with the wrong value kind. That single rule is what makes the parsers defensive by
/// construction: an ingest path reading third-party documents must treat a producer's unexpected
/// shape as a missing fact rather than as an exception, because the alternative is refusing a
/// whole document over a field nothing downstream needs.</para>
/// </summary>
internal static class JsonRead
{
    /// <summary>The named property, or null when the element is not an object or has no such property.</summary>
    private static JsonElement? Property(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value)
            ? value
            : null;

    /// <summary>The property as a non-empty string, or null.</summary>
    public static string? String(JsonElement element, string name)
    {
        var value = Property(element, name);
        string? text = value?.ValueKind == JsonValueKind.String ? value.Value.GetString() : null;
        return string.IsNullOrWhiteSpace(text) ? null : text;
    }

    /// <summary>
    /// The property as a string, accepting a JSON number too. SARIF's <c>security-severity</c>
    /// is specified as a string but is emitted as a bare number by some producers.
    /// </summary>
    public static string? StringOrNumber(JsonElement element, string name) =>
        Property(element, name) switch
        {
            { ValueKind: JsonValueKind.String } => String(element, name),
            { ValueKind: JsonValueKind.Number } value => value.GetRawText(),
            _ => null,
        };

    /// <summary>
    /// The property as a bool, or null when it is absent or not a JSON boolean. Null is a third
    /// state the callers keep rather than collapse: a component that never declared the flag and
    /// one that declared it false are different claims, and every document below CycloneDX 1.7
    /// is in the first group.
    /// </summary>
    public static bool? Bool(JsonElement element, string name) =>
        Property(element, name) switch
        {
            { ValueKind: JsonValueKind.True } => true,
            { ValueKind: JsonValueKind.False } => false,
            _ => null,
        };

    /// <summary>The property as an object, or null.</summary>
    public static JsonElement? Object(JsonElement element, string name)
    {
        var value = Property(element, name);
        return value?.ValueKind == JsonValueKind.Object ? value : null;
    }

    /// <summary>The property's elements, or an empty sequence when it is not an array.</summary>
    public static IEnumerable<JsonElement> Array(JsonElement element, string name)
    {
        var value = Property(element, name);
        return value?.ValueKind == JsonValueKind.Array ? value.Value.EnumerateArray() : [];
    }

    /// <summary>
    /// The first string in an array-valued property, or the property itself when the producer
    /// wrote a bare string where the specification says array. CycloneDX
    /// <c>analysis.response</c> is the case: the column holds one response and the document may
    /// hold several, so the first is recorded and the stored document keeps the rest.
    /// </summary>
    public static string? FirstStringOfArray(JsonElement element, string name)
    {
        string? bare = String(element, name);
        if (bare is not null)
        {
            return bare;
        }

        foreach (var entry in Array(element, name))
        {
            if (entry.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(entry.GetString()))
            {
                return entry.GetString();
            }
        }

        return null;
    }

    /// <summary>Every string in an array-valued property, in document order.</summary>
    public static List<string> StringArray(JsonElement element, string name)
    {
        var values = new List<string>();
        foreach (var entry in Array(element, name))
        {
            if (entry.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(entry.GetString()))
            {
                values.Add(entry.GetString()!);
            }
        }

        return values;
    }
}
