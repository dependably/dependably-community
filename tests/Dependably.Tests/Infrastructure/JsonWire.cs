using System.Text.Json;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Reads a JSON property by its exact wire name and fails naming that name when it is absent.
///
/// <para><see cref="JsonElement.GetProperty(string)"/> throws a bare "The given key was not
/// present in the dictionary" — across a wire-shape block of thirty-odd assertions that says a
/// response field moved without saying which one, which is the single fact the reader needs.
/// <see cref="Field"/> names the missing field and lists the siblings that are present, so a
/// renamed property reads as a rename rather than as a puzzle.</para>
/// </summary>
internal static class JsonWire
{
    /// <summary>
    /// Returns the value of <paramref name="name"/> on <paramref name="element"/>, failing the
    /// test with the field name and the object's actual keys when it is missing.
    /// </summary>
    internal static JsonElement Field(this JsonElement element, string name)
    {
        if (element.TryGetProperty(name, out var value))
        {
            return value;
        }

        string present = element.ValueKind == JsonValueKind.Object
            ? string.Join(", ", element.EnumerateObject().Select(p => p.Name))
            : $"<not an object: {element.ValueKind}>";

        Assert.Fail($"Missing wire field '{name}'. Fields present: {present}");
        return default;
    }
}
