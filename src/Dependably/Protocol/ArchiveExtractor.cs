namespace Dependably.Protocol;

/// <summary>
/// Magic-byte detection for the two archive formats that ship every supported package:
/// gzipped tar (npm <c>.tgz</c>, PyPI sdist <c>.tar.gz</c>) and ZIP (NuGet <c>.nupkg</c>,
/// PyPI wheel <c>.whl</c>). The unified upload path uses this first, then the
/// <see cref="EcosystemDetector"/> peeks at archive contents to identify the ecosystem.
/// </summary>
public static class ArchiveExtractor
{
    public enum ArchiveFormat { Unknown, Zip, GzippedTar }

    public static ArchiveFormat Detect(byte[] bytes)
    {
        return bytes.Length >= 2 && bytes[0] == 0x1F && bytes[1] == 0x8B
            ? ArchiveFormat.GzippedTar
            : bytes.Length >= 4 && bytes[0] == 'P' && bytes[1] == 'K'
            && (bytes[2] == 0x03 || bytes[2] == 0x05) && (bytes[3] == 0x04 || bytes[3] == 0x06)
            ? ArchiveFormat.Zip
            : ArchiveFormat.Unknown;
    }
}
