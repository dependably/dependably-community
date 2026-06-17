using System.Buffers.Binary;
using System.Text;
using Dependably.Protocol;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit coverage for the Cargo publish-frame parser: the binary envelope of a
/// <c>PUT /api/v1/crates/new</c> body (LE u32 metadata length, JSON metadata, LE u32 crate
/// length, crate bytes). Malformed frames must be rejected with a typed error before any
/// crate bytes are sliced.
/// </summary>
public class CargoPublishFrameTests
{
    private static byte[] BuildFrame(string metadataJson, byte[] crateBytes)
    {
        byte[] meta = Encoding.UTF8.GetBytes(metadataJson);
        byte[] buf = new byte[4 + meta.Length + 4 + crateBytes.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(buf, (uint)meta.Length);
        meta.CopyTo(buf, 4);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(4 + meta.Length), (uint)crateBytes.Length);
        crateBytes.CopyTo(buf, 4 + meta.Length + 4);
        return buf;
    }

    [Fact]
    public void ReadHeader_WellFormedFrame_ParsesMetadataAndCrateRange()
    {
        byte[] crate = "crate-bytes-here"u8.ToArray();
        string json = """{"name":"serde","vers":"1.0.0","deps":[],"features":{}}""";
        byte[] frame = BuildFrame(json, crate);

        var (err, header) = CargoPublishFrame.ReadHeader(frame);

        Assert.Equal(CargoPublishFrame.FrameError.None, err);
        Assert.NotNull(header);
        Assert.Equal("serde", header!.Metadata.Name);
        Assert.Equal("1.0.0", header.Metadata.Vers);
        Assert.Equal(crate.Length, header.CrateLength);
        Assert.Equal(crate, CargoPublishFrame.SliceCrate(frame, header));
    }

    [Fact]
    public void ReadHeader_EmptyBuffer_ReportsTruncated()
    {
        var (err, header) = CargoPublishFrame.ReadHeader(Array.Empty<byte>());
        Assert.Equal(CargoPublishFrame.FrameError.Truncated, err);
        Assert.Null(header);
    }

    [Fact]
    public void ReadHeader_MetadataLengthBeyondBuffer_ReportsLengthOverflow()
    {
        byte[] buf = new byte[8];
        // Declare a metadata length far larger than the 8-byte buffer.
        BinaryPrimitives.WriteUInt32LittleEndian(buf, 1_000_000u);

        var (err, header) = CargoPublishFrame.ReadHeader(buf);

        Assert.Equal(CargoPublishFrame.FrameError.LengthOverflow, err);
        Assert.Null(header);
    }

    [Fact]
    public void ReadHeader_CrateLengthBeyondBuffer_ReportsLengthOverflow()
    {
        byte[] meta = "{\"name\":\"a\",\"vers\":\"1.0.0\"}"u8.ToArray();
        byte[] buf = new byte[4 + meta.Length + 4];
        BinaryPrimitives.WriteUInt32LittleEndian(buf, (uint)meta.Length);
        meta.CopyTo(buf, 4);
        // Declare a crate length that overruns the buffer (no crate bytes actually present).
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(4 + meta.Length), 5000u);

        var (err, header) = CargoPublishFrame.ReadHeader(buf);

        Assert.Equal(CargoPublishFrame.FrameError.LengthOverflow, err);
        Assert.Null(header);
    }

    [Fact]
    public void ReadHeader_TruncatedBeforeCrateLengthPrefix_ReportsTruncated()
    {
        byte[] meta = "{\"name\":\"a\",\"vers\":\"1.0.0\"}"u8.ToArray();
        // Buffer holds the metadata length prefix + metadata but is missing the crate prefix.
        byte[] buf = new byte[4 + meta.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(buf, (uint)meta.Length);
        meta.CopyTo(buf, 4);

        var (err, header) = CargoPublishFrame.ReadHeader(buf);

        Assert.Equal(CargoPublishFrame.FrameError.Truncated, err);
        Assert.Null(header);
    }

    [Fact]
    public void ReadHeader_InvalidMetadataJson_ReportsInvalidMetadata()
    {
        byte[] frame = BuildFrame("not-json", "crate"u8.ToArray());
        var (err, header) = CargoPublishFrame.ReadHeader(frame);
        Assert.Equal(CargoPublishFrame.FrameError.InvalidMetadata, err);
        Assert.Null(header);
    }

    [Fact]
    public void ReadHeader_MetadataMissingNameOrVers_ReportsInvalidMetadata()
    {
        byte[] frame = BuildFrame("""{"vers":"1.0.0"}""", "crate"u8.ToArray());
        var (err, _) = CargoPublishFrame.ReadHeader(frame);
        Assert.Equal(CargoPublishFrame.FrameError.InvalidMetadata, err);
    }

    [Fact]
    public void ToIndexLine_MapsVersionReqToReqAndPreservesDepFields()
    {
        string json = """
        {
          "name":"mycrate","vers":"2.1.0",
          "deps":[{"name":"serde","version_req":"^1.0","features":["derive"],"optional":true,"default_features":false,"target":"cfg(unix)","kind":"normal","registry":"https://other"}],
          "features":{"std":["serde/std"]},
          "links":"mylib"
        }
        """;
        byte[] frame = BuildFrame(json, "x"u8.ToArray());
        var (_, header) = CargoPublishFrame.ReadHeader(frame);

        string line = header!.Metadata.ToIndexLine("abc123", yanked: false);

        Assert.Contains("\"cksum\":\"abc123\"", line);
        Assert.Contains("\"yanked\":false", line);
        Assert.Contains("\"req\":\"^1.0\"", line);   // version_req → req
        Assert.DoesNotContain("version_req", line);
        Assert.Contains("\"optional\":true", line);
        Assert.Contains("\"default_features\":false", line);
        Assert.Contains("\"target\":\"cfg(unix)\"", line);
        Assert.Contains("\"registry\":\"https://other\"", line);
        Assert.Contains("\"links\":\"mylib\"", line);
        Assert.Contains("\"std\":[\"serde/std\"]", line);
    }

    [Fact]
    public void ToIndexLine_SameRegistryDep_EmitsNullRegistry()
    {
        string json = """
        {"name":"a","vers":"1.0.0","deps":[{"name":"b","version_req":"^1"}],"features":{}}
        """;
        byte[] frame = BuildFrame(json, "x"u8.ToArray());
        var (_, header) = CargoPublishFrame.ReadHeader(frame);

        string line = header!.Metadata.ToIndexLine("d", yanked: false);

        Assert.Contains("\"registry\":null", line);
        Assert.Contains("\"kind\":\"normal\"", line);
    }
}
