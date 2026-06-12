using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

[Trait("Category", "Unit")]
public sealed class ArchiveExtractorTests
{
    [Fact]
    public void Detect_GzipMagicBytes_ReturnsGzippedTar()
    {
        byte[] bytes = new byte[] { 0x1F, 0x8B, 0x08, 0x00 };
        Assert.Equal(ArchiveExtractor.ArchiveFormat.GzippedTar, ArchiveExtractor.Detect(bytes));
    }

    [Fact]
    public void Detect_StandardZipLocalFileHeader_ReturnsZip()
    {
        // PK\x03\x04 — most common ZIP local file header
        byte[] bytes = new byte[] { (byte)'P', (byte)'K', 0x03, 0x04 };
        Assert.Equal(ArchiveExtractor.ArchiveFormat.Zip, ArchiveExtractor.Detect(bytes));
    }

    [Fact]
    public void Detect_ZipCentralDirectoryEndRecord_ReturnsZip()
    {
        // PK\x05\x06 — end-of-central-directory record (covers bytes[2]==0x05 and bytes[3]==0x06)
        byte[] bytes = new byte[] { (byte)'P', (byte)'K', 0x05, 0x06 };
        Assert.Equal(ArchiveExtractor.ArchiveFormat.Zip, ArchiveExtractor.Detect(bytes));
    }

    [Fact]
    public void Detect_ZipMixedHeaderBytes_ReturnsZip()
    {
        // PK\x03\x06 — covers bytes[2]==0x03 with bytes[3]==0x06 branch combination
        byte[] bytes = new byte[] { (byte)'P', (byte)'K', 0x03, 0x06 };
        Assert.Equal(ArchiveExtractor.ArchiveFormat.Zip, ArchiveExtractor.Detect(bytes));
    }

    [Fact]
    public void Detect_ZipMixedHeaderBytes_05_04_ReturnsZip()
    {
        // PK\x05\x04 — covers bytes[2]==0x05 with bytes[3]==0x04 branch combination
        byte[] bytes = new byte[] { (byte)'P', (byte)'K', 0x05, 0x04 };
        Assert.Equal(ArchiveExtractor.ArchiveFormat.Zip, ArchiveExtractor.Detect(bytes));
    }

    [Fact]
    public void Detect_EmptyArray_ReturnsUnknown()
    {
        Assert.Equal(ArchiveExtractor.ArchiveFormat.Unknown, ArchiveExtractor.Detect(System.Array.Empty<byte>()));
    }

    [Fact]
    public void Detect_SingleByte_ReturnsUnknown()
    {
        // Length < 2 — fails gzip length guard
        Assert.Equal(ArchiveExtractor.ArchiveFormat.Unknown, ArchiveExtractor.Detect(new byte[] { 0x1F }));
    }

    [Fact]
    public void Detect_TwoBytes_NonMagic_ReturnsUnknown()
    {
        // Length == 2, no match for gzip (fails bytes[0]==0x1F), zip needs >= 4
        Assert.Equal(ArchiveExtractor.ArchiveFormat.Unknown, ArchiveExtractor.Detect(new byte[] { 0x00, 0x00 }));
    }

    [Fact]
    public void Detect_GzipSecondByteWrong_ReturnsUnknown()
    {
        // bytes[0] == 0x1F but bytes[1] != 0x8B
        byte[] bytes = new byte[] { 0x1F, 0x00, 0x08, 0x00 };
        Assert.Equal(ArchiveExtractor.ArchiveFormat.Unknown, ArchiveExtractor.Detect(bytes));
    }

    [Fact]
    public void Detect_GzipFirstByteWrong_ReturnsUnknown()
    {
        // bytes[0] != 0x1F path
        byte[] bytes = new byte[] { 0x00, 0x8B, 0x08, 0x00 };
        Assert.Equal(ArchiveExtractor.ArchiveFormat.Unknown, ArchiveExtractor.Detect(bytes));
    }

    [Fact]
    public void Detect_ZipPButNotK_ReturnsUnknown()
    {
        // bytes[0] == 'P' but bytes[1] != 'K'
        byte[] bytes = new byte[] { (byte)'P', (byte)'X', 0x03, 0x04 };
        Assert.Equal(ArchiveExtractor.ArchiveFormat.Unknown, ArchiveExtractor.Detect(bytes));
    }

    [Fact]
    public void Detect_ZipFirstByteNotP_ReturnsUnknown()
    {
        // bytes[0] != 'P'
        byte[] bytes = new byte[] { (byte)'X', (byte)'K', 0x03, 0x04 };
        Assert.Equal(ArchiveExtractor.ArchiveFormat.Unknown, ArchiveExtractor.Detect(bytes));
    }

    [Fact]
    public void Detect_ZipThirdByteInvalid_ReturnsUnknown()
    {
        // PK header but bytes[2] is neither 0x03 nor 0x05
        byte[] bytes = new byte[] { (byte)'P', (byte)'K', 0x07, 0x04 };
        Assert.Equal(ArchiveExtractor.ArchiveFormat.Unknown, ArchiveExtractor.Detect(bytes));
    }

    [Fact]
    public void Detect_ZipFourthByteInvalid_ReturnsUnknown()
    {
        // PK header, bytes[2] valid (0x03) but bytes[3] is neither 0x04 nor 0x06
        byte[] bytes = new byte[] { (byte)'P', (byte)'K', 0x03, 0x07 };
        Assert.Equal(ArchiveExtractor.ArchiveFormat.Unknown, ArchiveExtractor.Detect(bytes));
    }

    [Fact]
    public void Detect_ThreeBytesZipPrefix_ReturnsUnknown()
    {
        // Length 3 — fails zip length guard (needs >= 4)
        byte[] bytes = new byte[] { (byte)'P', (byte)'K', 0x03 };
        Assert.Equal(ArchiveExtractor.ArchiveFormat.Unknown, ArchiveExtractor.Detect(bytes));
    }

    [Fact]
    public void Detect_LargerGzippedBuffer_StillDetects()
    {
        byte[] bytes = new byte[256];
        bytes[0] = 0x1F;
        bytes[1] = 0x8B;
        Assert.Equal(ArchiveExtractor.ArchiveFormat.GzippedTar, ArchiveExtractor.Detect(bytes));
    }
}
