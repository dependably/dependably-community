using System.Text.Json.Serialization;

namespace Dependably.Protocol;

/// <summary>
/// OCI Distribution Spec error codes. Returned in <see cref="OciErrorResponse"/>
/// bodies so docker clients can disambiguate "blob unknown" from "manifest unknown"
/// without parsing the message text. Wire form is SCREAMING_SNAKE_CASE per the spec.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum OciErrorCode
{
    BLOB_UNKNOWN,
    BLOB_UPLOAD_INVALID,
    BLOB_UPLOAD_UNKNOWN,
    DIGEST_INVALID,
    MANIFEST_BLOB_UNKNOWN,
    MANIFEST_INVALID,
    MANIFEST_UNKNOWN,
    NAME_INVALID,
    NAME_UNKNOWN,
    SIZE_INVALID,
    UNAUTHORIZED,
    DENIED,
    UNSUPPORTED,
}

/// <summary>RFC-compliant OCI error response body.</summary>
public sealed record OciErrorResponse(
    [property: JsonPropertyName("errors")] IReadOnlyList<OciError> Errors);

public sealed record OciError(
    [property: JsonPropertyName("code")] OciErrorCode Code,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("detail")] object? Detail = null);
