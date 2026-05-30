using System.Text.Json;
using Dependably.Protocol;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit coverage for the OCI Distribution Spec error payload (#98). The wire form is
/// canonical SCREAMING_SNAKE_CASE per the spec — docker clients disambiguate on
/// <c>code</c> string equality, so any drift here breaks <c>docker pull</c>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciErrorCodeTests
{
    [Theory]
    [InlineData(OciErrorCode.BLOB_UNKNOWN, "BLOB_UNKNOWN")]
    [InlineData(OciErrorCode.BLOB_UPLOAD_INVALID, "BLOB_UPLOAD_INVALID")]
    [InlineData(OciErrorCode.BLOB_UPLOAD_UNKNOWN, "BLOB_UPLOAD_UNKNOWN")]
    [InlineData(OciErrorCode.DIGEST_INVALID, "DIGEST_INVALID")]
    [InlineData(OciErrorCode.MANIFEST_BLOB_UNKNOWN, "MANIFEST_BLOB_UNKNOWN")]
    [InlineData(OciErrorCode.MANIFEST_INVALID, "MANIFEST_INVALID")]
    [InlineData(OciErrorCode.MANIFEST_UNKNOWN, "MANIFEST_UNKNOWN")]
    [InlineData(OciErrorCode.NAME_INVALID, "NAME_INVALID")]
    [InlineData(OciErrorCode.NAME_UNKNOWN, "NAME_UNKNOWN")]
    [InlineData(OciErrorCode.SIZE_INVALID, "SIZE_INVALID")]
    [InlineData(OciErrorCode.UNAUTHORIZED, "UNAUTHORIZED")]
    [InlineData(OciErrorCode.DENIED, "DENIED")]
    [InlineData(OciErrorCode.UNSUPPORTED, "UNSUPPORTED")]
    public void OciErrorCode_SerializesAsScreamingSnakeCase(OciErrorCode code, string expectedWire)
    {
        // The [JsonStringEnumConverter] on the enum forces the wire form to match the
        // member name exactly — that's the contract docker daemons depend on. A
        // rename / cammelCase shift here would break pull.
        var json = JsonSerializer.Serialize(code);
        Assert.Equal($"\"{expectedWire}\"", json);
    }

    [Fact]
    public void OciErrorCode_RoundTripsThroughJson()
    {
        // Sanity-check the converter handles both directions — needed because we both
        // emit OCI errors (server → docker) and may parse remote upstream errors back.
        foreach (OciErrorCode value in Enum.GetValues<OciErrorCode>())
        {
            var json = JsonSerializer.Serialize(value);
            var back = JsonSerializer.Deserialize<OciErrorCode>(json);
            Assert.Equal(value, back);
        }
    }

    [Fact]
    public void OciError_SerializesShapeRequiredBySpec()
    {
        // OCI Distribution Spec § Errors: { "code": "...", "message": "...", "detail": ... }.
        var err = new OciError(OciErrorCode.MANIFEST_UNKNOWN, "Manifest unknown: latest");
        var json = JsonSerializer.Serialize(err);

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.Equal("MANIFEST_UNKNOWN", root.GetProperty("code").GetString());
        Assert.Equal("Manifest unknown: latest", root.GetProperty("message").GetString());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("detail").ValueKind);
    }

    [Fact]
    public void OciError_PreservesDetailWhenProvided()
    {
        // The optional `detail` slot carries diagnostic context — needs to survive the
        // round-trip so clients can show it.
        var detail = new { hint = "use sha256: prefix" };
        var err = new OciError(OciErrorCode.DIGEST_INVALID, "Bad digest", detail);
        var json = JsonSerializer.Serialize(err);

        using var doc = JsonDocument.Parse(json);
        var d = doc.RootElement.GetProperty("detail");
        Assert.Equal(JsonValueKind.Object, d.ValueKind);
        Assert.Equal("use sha256: prefix", d.GetProperty("hint").GetString());
    }

    [Fact]
    public void OciErrorResponse_WrapsErrorsArrayWithSpecKey()
    {
        // The top-level body shape is `{ "errors": [...] }` — singular `error` is wrong
        // and would break docker clients that key on "errors".
        var body = new OciErrorResponse(new[]
        {
            new OciError(OciErrorCode.BLOB_UNKNOWN, "Blob unknown: sha256:deadbeef"),
            new OciError(OciErrorCode.MANIFEST_BLOB_UNKNOWN, "Manifest blob unknown."),
        });

        var json = JsonSerializer.Serialize(body);
        using var doc = JsonDocument.Parse(json);
        var arr = doc.RootElement.GetProperty("errors");
        Assert.Equal(JsonValueKind.Array, arr.ValueKind);
        Assert.Equal(2, arr.GetArrayLength());
        Assert.Equal("BLOB_UNKNOWN", arr[0].GetProperty("code").GetString());
        Assert.Equal("MANIFEST_BLOB_UNKNOWN", arr[1].GetProperty("code").GetString());
    }
}
