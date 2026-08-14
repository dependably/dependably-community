using System.Text.Json;
using System.Text.Json.Serialization;

namespace Dependably.Api;

/// <summary>
/// Tri-state request-body field: absent from the payload, present-and-explicitly-null, or
/// present with a value. A plain nullable property can only distinguish two of those three
/// states — <c>null</c> means both "the client didn't mention this field" and "the client
/// explicitly cleared it" — which is wrong wherever a field's own legitimate value space
/// includes null (e.g. <c>min_release_age_hours</c>/<c>max_epss_tolerance</c>, whose "gate
/// disabled" domain state <em>is</em> SQL NULL). System.Text.Json never invokes a property's
/// converter when that property is absent from the JSON payload, so a default-constructed
/// <see cref="Optional{T}"/> (<see cref="IsPresent"/> = false) is exactly what a missing key
/// deserializes to; an explicit JSON <c>null</c> DOES invoke <see cref="OptionalJsonConverter{T}"/>,
/// producing <c>IsPresent = true, Value = default</c>.
/// </summary>
[JsonConverter(typeof(OptionalJsonConverterFactory))]
public readonly struct Optional<T>
{
    public bool IsPresent { get; private init; }
    public T? Value { get; private init; }

    public static Optional<T> Absent => default;

    public static Optional<T> Of(T? value) => new() { IsPresent = true, Value = value };
}

/// <summary>
/// Resolves the per-<c>T</c> converter for <see cref="Optional{T}"/> — required because
/// <c>JsonConverter&lt;Optional&lt;T&gt;&gt;</c> can't be applied directly to an open generic
/// type via the attribute above.
/// </summary>
public sealed class OptionalJsonConverterFactory : JsonConverterFactory
{
    public override bool CanConvert(Type typeToConvert) =>
        typeToConvert.IsGenericType && typeToConvert.GetGenericTypeDefinition() == typeof(Optional<>);

    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options)
    {
        var innerType = typeToConvert.GetGenericArguments()[0];
        var converterType = typeof(OptionalJsonConverter<>).MakeGenericType(innerType);
        return (JsonConverter)Activator.CreateInstance(converterType)!;
    }
}

internal sealed class OptionalJsonConverter<T> : JsonConverter<Optional<T>>
{
    public override Optional<T> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = JsonSerializer.Deserialize<T>(ref reader, options);
        return Optional<T>.Of(value);
    }

    public override void Write(Utf8JsonWriter writer, Optional<T> value, JsonSerializerOptions options)
    {
        // Only reached when a caller explicitly serializes an Optional<T> (e.g. an audit-log
        // projection); request DTOs are write-only from the wire's perspective.
        if (value.IsPresent)
        {
            JsonSerializer.Serialize(writer, value.Value, options);
        }
        else
        {
            writer.WriteNullValue();
        }
    }
}
