namespace Dependably.Protocol;

/// <summary>
/// Magic-byte detection for the two archive formats that ship every supported package:
/// gzipped tar (npm <c>.tgz</c>, PyPI sdist <c>.tar.gz</c>) and ZIP (NuGet <c>.nupkg</c>,
/// PyPI wheel <c>.whl</c>). The unified upload path uses this first, then the
/// <see cref="EcosystemDetector"/> peeks at archive contents to identify the ecosystem.
/// </summary>
public static class ArchiveExtractor
{
    // gzip magic bytes: 0x1F 0x8B (RFC 1952).
    private const byte GzipMagic1 = 0x1F;
    private const byte GzipMagic2 = 0x8B;
    private const int GzipHeaderMinLength = 2;

    // ZIP local file header signatures (PK\x03\x04 and PK\x05\x06).
    private const byte ZipMagic1 = (byte)'P';
    private const byte ZipMagic2 = (byte)'K';
    private const byte ZipLocalHeader3 = 0x03;
    private const byte ZipEndHeader3 = 0x05;
    private const byte ZipLocalHeader4 = 0x04;
    private const byte ZipEndHeader4 = 0x06;
    private const int ZipHeaderMinLength = 4;

    // Byte-array offsets for the third and fourth bytes of a ZIP local file header.
    private const int ZipByte2Index = 2;
    private const int ZipByte3Index = 3;

    public enum ArchiveFormat { Unknown, Zip, GzippedTar }

    public static ArchiveFormat Detect(byte[] bytes)
    {
        return bytes.Length >= GzipHeaderMinLength && bytes[0] == GzipMagic1 && bytes[1] == GzipMagic2
            ? ArchiveFormat.GzippedTar
            : bytes.Length >= ZipHeaderMinLength && bytes[0] == ZipMagic1 && bytes[1] == ZipMagic2
            && (bytes[ZipByte2Index] == ZipLocalHeader3 || bytes[ZipByte2Index] == ZipEndHeader3)
            && (bytes[ZipByte3Index] == ZipLocalHeader4 || bytes[ZipByte3Index] == ZipEndHeader4)
            ? ArchiveFormat.Zip
            : ArchiveFormat.Unknown;
    }
}
