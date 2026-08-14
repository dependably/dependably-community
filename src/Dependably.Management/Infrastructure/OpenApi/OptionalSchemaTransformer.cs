using Dependably.Api;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;

namespace Dependably.Infrastructure.OpenApi;

/// <summary>
/// Rewrites the generated schema for <see cref="Optional{T}"/> from its structural shape
/// (the exporter can't reflect through <see cref="OptionalJsonConverterFactory"/>, so it falls
/// back to an empty/unconstrained schema) into the plain nullable scalar the type actually reads
/// and writes on the wire: absent-vs-present-vs-value is a server-side binding concern, not
/// something an API consumer needs to see — from outside, <c>Optional&lt;int?&gt;</c> is just
/// "an integer, or null, or omit the property entirely" like any other optional nullable field.
/// Only <c>int</c>/<c>double</c> underlying types are handled because those are the only
/// <see cref="Optional{T}"/> instantiations that currently exist on a request DTO; a future
/// instantiation with an unhandled underlying type keeps the exporter's default (empty) schema
/// rather than silently mis-describing it.
/// </summary>
internal sealed class OptionalSchemaTransformer : IOpenApiSchemaTransformer
{
    public Task TransformAsync(
        OpenApiSchema schema,
        OpenApiSchemaTransformerContext context,
        CancellationToken cancellationToken)
    {
        var clrType = context.JsonTypeInfo.Type;
        if (!clrType.IsGenericType || clrType.GetGenericTypeDefinition() != typeof(Optional<>))
        {
            return Task.CompletedTask;
        }

        var declared = clrType.GetGenericArguments()[0];
        var underlying = Nullable.GetUnderlyingType(declared) ?? declared;

        if (underlying == typeof(int))
        {
            schema.Type = JsonSchemaType.Integer | JsonSchemaType.Null;
            schema.Format = "int32";
        }
        else if (underlying == typeof(double))
        {
            schema.Type = JsonSchemaType.Number | JsonSchemaType.Null;
            schema.Format = "double";
        }
        else
        {
            return Task.CompletedTask;
        }

        schema.Properties?.Clear();
        schema.Required?.Clear();
        return Task.CompletedTask;
    }
}
