using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using Dependably.Api.NpmProtocol;

namespace Dependably.Tests.Unit;

/// <summary>
/// The npm publish body is stream-parsed: the base64 tarball under
/// <c>_attachments.{key}.data</c> is decoded incrementally to a staging file, and only a small
/// redacted envelope DOM is materialised. These tests pin the round-trip integrity (the decoded
/// tarball must be byte-identical to what was published, across the 48 KB decode-window boundary),
/// the cap-before-decode ordering (oversize body → 413 with no tarball staged), and the shape
/// validations the pre-streaming handler produced (bad base64, missing data, multi-entry
/// _attachments, length mismatch, and the deprecate shape).
/// </summary>
[Trait("Category", "Unit")]
public class NpmPublishBodyParserTests : IDisposable
{
    private readonly string _staging = Path.Combine(Path.GetTempPath(), $"dependably-npmparse-{Guid.NewGuid():N}");

    public NpmPublishBodyParserTests() => Directory.CreateDirectory(_staging);

    public void Dispose()
    {
        try { Directory.Delete(_staging, recursive: true); } catch { /* best effort */ }
        GC.SuppressFinalize(this);
    }

    private static byte[] BuildTarball(byte[] extraPayload)
    {
        using var raw = new MemoryStream();
        using (var gz = new GZipStream(raw, CompressionLevel.Fastest, leaveOpen: true))
        using (var tw = new TarWriter(gz, leaveOpen: true))
        {
            byte[] pj = Encoding.UTF8.GetBytes("{\"name\":\"my-pkg\",\"version\":\"1.0.0\"}");
            var manifest = new PaxTarEntry(TarEntryType.RegularFile, "package/package.json")
            { DataStream = new MemoryStream(pj) };
            tw.WriteEntry(manifest);

            if (extraPayload.Length > 0)
            {
                var blob = new PaxTarEntry(TarEntryType.RegularFile, "package/payload.bin")
                { DataStream = new MemoryStream(extraPayload) };
                tw.WriteEntry(blob);
            }
        }
        return raw.ToArray();
    }

    private static byte[] BuildPublishBody(byte[] tarball, string attachmentKey = "my-pkg-1.0.0.tgz",
        bool dataLast = true, long? declaredLength = null, bool includeDistTags = true)
    {
        string b64 = Convert.ToBase64String(tarball);
        long len = declaredLength ?? tarball.LongLength;
        // Deliberately order the attachment object fields so the base64 `data` value is NOT last
        // when dataLast is false — the parser must resolve the value regardless of field order.
        string attachmentObj = dataLast
            ? $"{{\"content_type\":\"application/octet-stream\",\"length\":{len},\"data\":\"{b64}\"}}"
            : $"{{\"data\":\"{b64}\",\"content_type\":\"application/octet-stream\",\"length\":{len}}}";
        string distTags = includeDistTags ? ",\"dist-tags\":{\"latest\":\"1.0.0\"}" : "";
        string body =
            "{\"_id\":\"my-pkg\",\"name\":\"my-pkg\"," +
            "\"versions\":{\"1.0.0\":{\"name\":\"my-pkg\",\"version\":\"1.0.0\",\"license\":\"MIT\"}}" +
            distTags +
            $",\"_attachments\":{{\"{attachmentKey}\":{attachmentObj}}}}}";
        return Encoding.UTF8.GetBytes(body);
    }

    private Task<NpmPublishBodyParser.NpmParseResult> ParseAsync(byte[] body, long cap = 500L * 1024 * 1024)
        => NpmPublishBodyParser.ParseAsync(new MemoryStream(body), cap, _staging, CancellationToken.None);

    [Theory]
    [InlineData(0)]        // tiny: base64 fits one decode window
    [InlineData(200_000)]  // spans several 48 KB decode windows
    [InlineData(1_000_000)]
    public async Task Parse_RoundTrips_TarballBytesAndEnvelope(int payloadSize)
    {
        byte[] payload = new byte[payloadSize];
        Random.Shared.NextBytes(payload);
        byte[] tarball = BuildTarball(payload);
        byte[] body = BuildPublishBody(tarball);

        var result = await ParseAsync(body);

        Assert.Equal(NpmPublishBodyParser.NpmParseErrorKind.None, result.ErrorKind);
        Assert.Equal("my-pkg-1.0.0.tgz", result.AttachmentKey);
        Assert.NotNull(result.TarballPath);
        Assert.Equal(tarball.LongLength, result.TarballSize);

        byte[] staged = await File.ReadAllBytesAsync(result.TarballPath!);
        Assert.Equal(tarball, staged);

        Assert.Equal("my-pkg", (string?)result.Envelope?["name"]);
        Assert.NotNull(result.Envelope?["versions"]?["1.0.0"]);
        Assert.Equal("1.0.0", (string?)result.Envelope?["dist-tags"]?["latest"]);
        // The base64 must never survive in the envelope DOM — it was redacted to "".
        Assert.Equal("", (string?)result.Envelope?["_attachments"]?["my-pkg-1.0.0.tgz"]?["data"]);
    }

    [Fact]
    public async Task Parse_DataFieldNotLast_StillResolvesValue()
    {
        byte[] tarball = BuildTarball(new byte[50_000]);
        byte[] body = BuildPublishBody(tarball, dataLast: false);

        var result = await ParseAsync(body);

        Assert.Equal(NpmPublishBodyParser.NpmParseErrorKind.None, result.ErrorKind);
        byte[] staged = await File.ReadAllBytesAsync(result.TarballPath!);
        Assert.Equal(tarball, staged);
    }

    [Fact]
    public async Task Parse_ScopedAttachmentKey_Resolves()
    {
        byte[] tarball = BuildTarball(new byte[1000]);
        byte[] body = BuildPublishBody(tarball, attachmentKey: "@scope/my-pkg-1.0.0.tgz");

        var result = await ParseAsync(body);

        Assert.Equal(NpmPublishBodyParser.NpmParseErrorKind.None, result.ErrorKind);
        Assert.Equal("@scope/my-pkg-1.0.0.tgz", result.AttachmentKey);
    }

    [Fact]
    public async Task Parse_BodyOverCap_Returns413_AndStagesNoTarball()
    {
        byte[] tarball = BuildTarball(new byte[300_000]);
        byte[] body = BuildPublishBody(tarball);

        // Cap well below the body size — the LimitedReadStream aborts the spool before any
        // decode, so no tarball is ever written.
        var result = await ParseAsync(body, cap: 1024);

        Assert.Equal(NpmPublishBodyParser.NpmParseErrorKind.TooLarge, result.ErrorKind);
        Assert.Null(result.TarballPath);
        // No leftover .tmp tarball staged (only the transient .json spool, deleted in finally).
        Assert.Empty(Directory.GetFiles(_staging, "*.tmp"));
    }

    [Fact]
    public async Task Parse_DeclaredLengthMismatch_Returns422()
    {
        byte[] tarball = BuildTarball(new byte[2000]);
        byte[] body = BuildPublishBody(tarball, declaredLength: tarball.LongLength + 99);

        var result = await ParseAsync(body);

        Assert.Equal(NpmPublishBodyParser.NpmParseErrorKind.AttachmentShape, result.ErrorKind);
        Assert.Contains("length mismatch", result.ErrorDetail);
    }

    [Fact]
    public async Task Parse_InvalidBase64_Returns422()
    {
        string body =
            "{\"name\":\"my-pkg\",\"versions\":{\"1.0.0\":{}}," +
            "\"_attachments\":{\"my-pkg-1.0.0.tgz\":{\"data\":\"not valid base64!!!\",\"length\":10}}}";

        var result = await ParseAsync(Encoding.UTF8.GetBytes(body));

        Assert.Equal(NpmPublishBodyParser.NpmParseErrorKind.AttachmentShape, result.ErrorKind);
        Assert.Contains("base64", result.ErrorDetail);
    }

    [Fact]
    public async Task Parse_MissingData_Returns422()
    {
        string body =
            "{\"name\":\"my-pkg\",\"versions\":{\"1.0.0\":{}}," +
            "\"_attachments\":{\"my-pkg-1.0.0.tgz\":{\"content_type\":\"application/octet-stream\"}}}";

        var result = await ParseAsync(Encoding.UTF8.GetBytes(body));

        Assert.Equal(NpmPublishBodyParser.NpmParseErrorKind.AttachmentShape, result.ErrorKind);
        Assert.Contains("data is required", result.ErrorDetail);
    }

    [Fact]
    public async Task Parse_MultipleAttachments_Returns422()
    {
        byte[] tarball = BuildTarball(new byte[100]);
        string b64 = Convert.ToBase64String(tarball);
        string body =
            "{\"name\":\"my-pkg\",\"versions\":{\"1.0.0\":{}},\"_attachments\":{" +
            $"\"a-1.0.0.tgz\":{{\"data\":\"{b64}\",\"length\":{tarball.Length}}}," +
            $"\"b-1.0.0.tgz\":{{\"data\":\"{b64}\",\"length\":{tarball.Length}}}}}}}";

        var result = await ParseAsync(Encoding.UTF8.GetBytes(body));

        Assert.Equal(NpmPublishBodyParser.NpmParseErrorKind.AttachmentShape, result.ErrorKind);
        Assert.Contains("exactly one entry", result.ErrorDetail);
    }

    [Fact]
    public async Task Parse_DeprecateShape_NoAttachments_ReturnsEnvelopeWithNoTarball()
    {
        // npm deprecate sends a packument PUT with no _attachments key.
        string body =
            "{\"name\":\"my-pkg\",\"versions\":{\"1.0.0\":{\"deprecated\":\"do not use\"}}}";

        var result = await ParseAsync(Encoding.UTF8.GetBytes(body));

        Assert.Equal(NpmPublishBodyParser.NpmParseErrorKind.None, result.ErrorKind);
        Assert.Null(result.TarballPath);
        Assert.Null(result.AttachmentKey);
        Assert.Null(result.Envelope?["_attachments"]);
        Assert.Equal("do not use", (string?)result.Envelope?["versions"]?["1.0.0"]?["deprecated"]);
    }

    [Fact]
    public async Task Parse_NonAttachmentDataKey_IsNotTreatedAsTarball()
    {
        // A "data" field inside a version object must NOT be mistaken for the attachment data.
        byte[] tarball = BuildTarball(new byte[500]);
        string b64 = Convert.ToBase64String(tarball);
        string body =
            "{\"name\":\"my-pkg\"," +
            "\"versions\":{\"1.0.0\":{\"data\":\"decoy-not-base64-value\"}}," +
            $"\"_attachments\":{{\"my-pkg-1.0.0.tgz\":{{\"length\":{tarball.Length},\"data\":\"{b64}\"}}}}}}";

        var result = await ParseAsync(Encoding.UTF8.GetBytes(body));

        Assert.Equal(NpmPublishBodyParser.NpmParseErrorKind.None, result.ErrorKind);
        byte[] staged = await File.ReadAllBytesAsync(result.TarballPath!);
        Assert.Equal(tarball, staged);
    }

    [Fact]
    public async Task Parse_InvalidJson_Returns422()
    {
        var result = await ParseAsync(Encoding.UTF8.GetBytes("{ this is not json "));
        Assert.Equal(NpmPublishBodyParser.NpmParseErrorKind.InvalidJson, result.ErrorKind);
    }

    [Fact]
    public async Task Parse_RealFactoryFixtureBody_Succeeds()
    {
        string body = Dependably.Tests.Infrastructure.NpmFixtures.BuildPublishBody("left-pad", "1.0.0");
        var result = await ParseAsync(Encoding.UTF8.GetBytes(body));
        Assert.True(result.ErrorKind == NpmPublishBodyParser.NpmParseErrorKind.None,
            $"kind={result.ErrorKind} detail={result.ErrorDetail}");
        Assert.Equal("left-pad-1.0.0.tgz", result.AttachmentKey);
    }

    [Fact]
    public async Task Parse_JsonEscapeStraddlingDecodeWindowBoundary_RoundTrips()
    {
        // System.Text.Json escapes base64 '+' as +. Such a 6-char escape can straddle the
        // 48 KiB decode-window boundary; it must be carried across the boundary, not rejected as a
        // truncated escape. Force a '+' at base64 offset 49150 so its + escape spans the
        // boundary at 49152, then assert the tarball still round-trips byte-for-byte.
        const int Window = 48 * 1024; // matches NpmPublishBodyParser's decode window
        byte[] seed = new byte[40_000];
        Random.Shared.NextBytes(seed);
        char[] b64 = Convert.ToBase64String(seed).ToCharArray();
        Assert.True(b64.Length > Window + 8, "base64 value must span more than one decode window");
        b64[Window - 2] = '+'; // offset 49150 — its + escape will straddle the 49152 boundary
        byte[] tarball = Convert.FromBase64String(new string(b64));

        var value = new StringBuilder(b64.Length + 8);
        for (int i = 0; i < b64.Length; i++)
        {
            value.Append(i == Window - 2 ? "\\u002B" : b64[i].ToString());
        }
        string body =
            "{\"name\":\"my-pkg\",\"versions\":{\"1.0.0\":{}}," +
            $"\"_attachments\":{{\"my-pkg-1.0.0.tgz\":{{\"length\":{tarball.LongLength},\"data\":\"{value}\"}}}}}}";

        var result = await ParseAsync(Encoding.UTF8.GetBytes(body));

        Assert.Equal(NpmPublishBodyParser.NpmParseErrorKind.None, result.ErrorKind);
        Assert.NotNull(result.TarballPath);
        byte[] staged = await File.ReadAllBytesAsync(result.TarballPath!);
        Assert.Equal(tarball, staged);
    }
}
