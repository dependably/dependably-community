using System.Buffers.Binary;
using System.Text;
using Dependably.Protocol;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit coverage for the RPM upload gate. The validator is the cheap first-pass
/// reject between raw upload bytes and the heavy <see cref="RpmHeaderParser"/>. Every
/// rejection branch (size, parser failure, illegal NEVRA characters) needs a test so a
/// regression to "accept everything" can't slip through.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmArtifactValidatorTests
{
    [Fact]
    public void Validate_HappyPath_ReturnsHeader()
    {
        var bytes = BuildRpmWithMainHeader(new List<RpmTagWrite>
        {
            RpmTagWrite.String(1000, "zlib"),
            RpmTagWrite.String(1001, "1.2.11"),
            RpmTagWrite.String(1002, "39.el9"),
            RpmTagWrite.String(1022, "x86_64"),
            RpmTagWrite.Int32(1003, 0),
        });

        var info = RpmArtifactValidator.Validate(bytes);

        Assert.Equal("zlib", info.Name);
        Assert.Equal("1.2.11", info.Version);
        Assert.Equal("39.el9", info.Release);
        Assert.Equal("x86_64", info.Arch);
    }

    [Fact]
    public void Validate_NullBytes_Throws()
    {
        // ArgumentNullException.ThrowIfNull guards the entry point.
        Assert.Throws<ArgumentNullException>(() => RpmArtifactValidator.Validate(null!));
    }

    [Fact]
    public void Validate_BytesBelowMinimum_ThrowsRpmParse()
    {
        // Anything shorter than lead(96) + header intro(16) is dropped before parsing
        // so we never hand garbage to RpmHeaderParser.
        var tiny = new byte[RpmArtifactValidator.MinimumValidSize - 1];
        var ex = Assert.Throws<RpmParseException>(() => RpmArtifactValidator.Validate(tiny));
        Assert.Contains("too short", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Validate_AtMinimumSize_StillRejected_ByParser_NotBySizeGate()
    {
        // Exactly MinimumValidSize bytes of zeros — passes the length check but fails
        // the parser's magic-bytes check. Proves the size gate is a strict `<`, not `<=`.
        var atMin = new byte[RpmArtifactValidator.MinimumValidSize];
        Assert.Throws<RpmParseException>(() => RpmArtifactValidator.Validate(atMin));
    }

    [Fact]
    public void Validate_BadLeadMagic_ThrowsRpmParse()
    {
        // Lead magic bytes wrong — the parser kicks back; the validator rethrows untouched.
        var bytes = new byte[200];
        // No magic written → first byte is 0x00 not 0xED.
        Assert.Throws<RpmParseException>(() => RpmArtifactValidator.Validate(bytes));
    }

    [Fact]
    public void MinimumValidSize_IsLeadPlusHeaderIntro()
    {
        // The constant is exposed so callers (RpmController) can short-circuit before
        // calling the validator. Lock the value so accidental changes show up here.
        Assert.Equal(96 + 16, RpmArtifactValidator.MinimumValidSize);
    }

    [Fact]
    public void NameRegex_AcceptsExpectedNevraCharset()
    {
        // The shared regex is exposed publicly because both the validator and external
        // callers (e.g. the repodata builder) want the same definition of "safe".
        Assert.Matches(RpmArtifactValidator.NameRegex, "zlib");
        Assert.Matches(RpmArtifactValidator.NameRegex, "gcc-c++");
        Assert.Matches(RpmArtifactValidator.NameRegex, "python3.11");
        Assert.Matches(RpmArtifactValidator.NameRegex, "libstdc++_devel");
        Assert.Matches(RpmArtifactValidator.NameRegex, "foo+bar");
    }

    [Theory]
    [InlineData("bad name")]      // space
    [InlineData("bad/name")]      // slash (path traversal)
    [InlineData("bad\nname")]     // newline
    [InlineData("bad;rm")]        // shell metacharacter
    [InlineData("")]              // empty
    public void NameRegex_RejectsUnsafe(string candidate)
    {
        Assert.DoesNotMatch(RpmArtifactValidator.NameRegex, candidate);
    }

    [Fact]
    public void Validate_IllegalNameCharacter_ThrowsWithNameInMessage()
    {
        // Header parses successfully (NAME = "bad name") but the regex check fires.
        var bytes = BuildRpmWithMainHeader(new List<RpmTagWrite>
        {
            RpmTagWrite.String(1000, "bad name"),
            RpmTagWrite.String(1001, "1.0.0"),
            RpmTagWrite.String(1002, "1"),
            RpmTagWrite.String(1022, "x86_64"),
        });
        var ex = Assert.Throws<RpmParseException>(() => RpmArtifactValidator.Validate(bytes));
        Assert.Contains("name", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Validate_IllegalVersionCharacter_ThrowsWithVersionInMessage()
    {
        // Version with a forbidden character — the second regex branch.
        var bytes = BuildRpmWithMainHeader(new List<RpmTagWrite>
        {
            RpmTagWrite.String(1000, "zlib"),
            RpmTagWrite.String(1001, "bad version"),
            RpmTagWrite.String(1002, "1"),
            RpmTagWrite.String(1022, "x86_64"),
        });
        var ex = Assert.Throws<RpmParseException>(() => RpmArtifactValidator.Validate(bytes));
        Assert.Contains("version", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Validate_IllegalReleaseCharacter_ThrowsWithReleaseInMessage()
    {
        // Release with a slash — third regex branch.
        var bytes = BuildRpmWithMainHeader(new List<RpmTagWrite>
        {
            RpmTagWrite.String(1000, "zlib"),
            RpmTagWrite.String(1001, "1.0.0"),
            RpmTagWrite.String(1002, "bad/release"),
            RpmTagWrite.String(1022, "x86_64"),
        });
        var ex = Assert.Throws<RpmParseException>(() => RpmArtifactValidator.Validate(bytes));
        Assert.Contains("release", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Validate_IllegalArchCharacter_ThrowsWithArchInMessage()
    {
        // Arch with a space — fourth regex branch.
        var bytes = BuildRpmWithMainHeader(new List<RpmTagWrite>
        {
            RpmTagWrite.String(1000, "zlib"),
            RpmTagWrite.String(1001, "1.0.0"),
            RpmTagWrite.String(1002, "1"),
            RpmTagWrite.String(1022, "bad arch"),
        });
        var ex = Assert.Throws<RpmParseException>(() => RpmArtifactValidator.Validate(bytes));
        Assert.Contains("arch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ── Synthetic RPM byte builder (cribbed from RpmHeaderParserTests) ─────────

    private static byte[] BuildRpmWithMainHeader(List<RpmTagWrite> tags)
    {
        var lead = new byte[96];
        lead[0] = 0xED; lead[1] = 0xAB; lead[2] = 0xEE; lead[3] = 0xDB;
        lead[4] = 3;

        var sig = BuildHeaderIntro(0, 0);
        var sigEnd = 96 + sig.Length;
        var padLen = (8 - (sigEnd % 8)) % 8;
        var pad = new byte[padLen];

        var (index, store) = BuildHeader(tags);
        var intro = BuildHeaderIntro(tags.Count, store.Length);

        return [..lead, ..sig, ..pad, ..intro, ..index, ..store];
    }

    private static byte[] BuildHeaderIntro(int nindex, int hsize)
    {
        var b = new byte[16];
        b[0] = 0x8E; b[1] = 0xAD; b[2] = 0xE8; b[3] = 0x01;
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
