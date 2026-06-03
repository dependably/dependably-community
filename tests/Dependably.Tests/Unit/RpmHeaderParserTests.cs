using System.Buffers.Binary;
using System.Text;
using Dependably.Protocol;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit tests for the RPM binary header parser. Each test constructs a synthetic
/// .rpm byte-stream (lead + signature + main header) so we can assert against precise
/// inputs without shipping real RPM fixtures.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmHeaderParserTests
{
    [Fact]
    public void Parse_RejectsBadLeadMagic()
    {
        var bytes = new byte[200];
        bytes[0] = 0x00; // wrong
        Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
    }

    [Fact]
    public void Parse_RejectsUnsupportedMajor()
    {
        var bytes = BuildBareRpm(majorVersion: 99);
        Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
    }

    [Fact]
    public void Parse_RejectsMissingMandatoryTags()
    {
        // Build an RPM with empty signature + empty main header — no NAME tag.
        var bytes = BuildRpmWithMainHeader(new List<RpmTagWrite>());
        Assert.Throws<RpmParseException>(() => RpmHeaderParser.Parse(bytes));
    }

    [Fact]
    public void Parse_HappyPath_PullsNevra()
    {
        var bytes = BuildRpmWithMainHeader(new List<RpmTagWrite>
        {
            RpmTagWrite.String(1000, "zlib"),     // NAME
            RpmTagWrite.String(1001, "1.2.11"),   // VERSION
            RpmTagWrite.String(1002, "39.el9"),   // RELEASE
            RpmTagWrite.String(1022, "x86_64"),   // ARCH
            RpmTagWrite.String(1004, "Compression utility"),
            RpmTagWrite.Int32(1003, 0),           // EPOCH
            RpmTagWrite.Int32(1009, 102400),      // INSTALLED_SIZE
        });

        var info = RpmHeaderParser.Parse(bytes);
        Assert.Equal("zlib", info.Name);
        Assert.Equal("1.2.11", info.Version);
        Assert.Equal("39.el9", info.Release);
        Assert.Equal("x86_64", info.Arch);
        Assert.Equal("Compression utility", info.Summary);
        Assert.Equal(0, info.Epoch);
        Assert.Equal(102400, info.InstalledSize);
    }

    [Fact]
    public void Parse_HeaderRange_PointsAtMainHeader()
    {
        var bytes = BuildRpmWithMainHeader(new List<RpmTagWrite>
        {
            RpmTagWrite.String(1000, "demo"),
            RpmTagWrite.String(1001, "1.0"),
            RpmTagWrite.String(1002, "1"),
            RpmTagWrite.String(1022, "noarch"),
        });

        var info = RpmHeaderParser.Parse(bytes);
        // Main header sits after the 96-byte lead + 16-byte sig intro (no signature
        // index entries) padded to 8 bytes.
        Assert.True(info.HeaderStart >= 96 + 16);
        Assert.True(info.HeaderEnd > info.HeaderStart);
    }

    // ── Synthetic RPM byte builder ─────────────────────────────────────────────

    private static byte[] BuildBareRpm(byte majorVersion = 3)
    {
        // Lead with valid magic, configurable major, plus an empty signature header.
        var lead = new byte[96];
        lead[0] = 0xED; lead[1] = 0xAB; lead[2] = 0xEE; lead[3] = 0xDB;
        lead[4] = majorVersion;
        lead[5] = 0;
        // type, archnum, name, osnum, signature_type, reserved — left as zeros.

        // Empty signature header: 0 index entries, 0 hsize.
        var sig = BuildEmptyHeaderIntro();
        return [..lead, ..sig];
    }

    private static byte[] BuildRpmWithMainHeader(List<RpmTagWrite> tags)
    {
        // Lead + empty signature + aligned main header carrying the supplied tags.
        var lead = new byte[96];
        lead[0] = 0xED; lead[1] = 0xAB; lead[2] = 0xEE; lead[3] = 0xDB;
        lead[4] = 3; // major 3

        var sig = BuildEmptyHeaderIntro();
        var sigEnd = 96 + sig.Length;
        var padLen = (8 - (sigEnd % 8)) % 8;
        var pad = new byte[padLen];

        var (index, store) = BuildHeader(tags);
        var intro = BuildHeaderIntro(tags.Count, store.Length);

        return [..lead, ..sig, ..pad, ..intro, ..index, ..store];
    }

    private static byte[] BuildEmptyHeaderIntro() => BuildHeaderIntro(0, 0);

    private static byte[] BuildHeaderIntro(int nindex, int hsize)
    {
        var b = new byte[16];
        b[0] = 0x8E; b[1] = 0xAD; b[2] = 0xE8; b[3] = 0x01;
        // bytes 4..7 reserved
        BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(8, 4), nindex);
        BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(12, 4), hsize);
        return b;
    }

    private static (byte[] Index, byte[] Store) BuildHeader(List<RpmTagWrite> tags)
    {
        var indexBytes = new List<byte>();
        var storeBytes = new List<byte>();

        foreach (var t in tags)
        {
            var offset = storeBytes.Count;
            indexBytes.AddRange(WriteIndexEntry(t.Tag, t.Type, offset, t.Count));
            storeBytes.AddRange(t.Bytes);
        }
        return (indexBytes.ToArray(), storeBytes.ToArray());
    }

    private static byte[] WriteIndexEntry(int tag, int type, int offset, int count)
    {
        var b = new byte[16];
        BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(0, 4), tag);
        BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(4, 4), type);
        BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(8, 4), offset);
        BinaryPrimitives.WriteInt32BigEndian(b.AsSpan(12, 4), count);
        return b;
    }

    private sealed record RpmTagWrite(int Tag, int Type, int Count, byte[] Bytes)
    {
        public static RpmTagWrite String(int tag, string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            var withNul = new byte[bytes.Length + 1];
            Array.Copy(bytes, withNul, bytes.Length);
            return new RpmTagWrite(tag, Type: 6, Count: 1, withNul);
        }

        public static RpmTagWrite Int32(int tag, int value)
        {
            var bytes = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(bytes, value);
            return new RpmTagWrite(tag, Type: 4, Count: 1, bytes);
        }
    }
}
