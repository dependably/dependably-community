using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace Dependably.Tests.Infrastructure;

/// <summary>Generates synthetic PyPI packages for edge-case testing.</summary>
public static class PyPiFixtures
{
    /// <summary>
    /// Builds a minimal but valid .whl (ZIP) file in memory.
    /// Contains METADATA and WHEEL dist-info entries.
    /// </summary>
    public static (byte[] Bytes, string Sha256Hex) BuildWheel(string name, string version)
    {
        var normalized = name.ToLowerInvariant().Replace('-', '_').Replace('.', '_');
        var distInfoDir = $"{normalized}-{version}.dist-info";

        var metadata = $"""
            Metadata-Version: 2.1
            Name: {name}
            Version: {version}
            Summary: Synthetic test package
            """;

        var wheel = """
            Wheel-Version: 1.0
            Generator: dependably-test
            Root-Is-Purelib: true
            Tag: py3-none-any
            """;

        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteEntry(zip, $"{distInfoDir}/METADATA", metadata);
            WriteEntry(zip, $"{distInfoDir}/WHEEL", wheel);
        }

        var bytes = ms.ToArray();
        var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        return (bytes, hash);
    }

    /// <summary>
    /// Builds a minimal .tar.gz (sdist) in memory.
    /// Contains PKG-INFO at the top level.
    /// </summary>
    public static (byte[] Bytes, string Sha256Hex) BuildSdist(string name, string version)
    {
        var pkgInfo = $"""
            Metadata-Version: 2.1
            Name: {name}
            Version: {version}
            Summary: Synthetic test package
            """;

        var pkgInfoBytes = Encoding.UTF8.GetBytes(pkgInfo);
        var entryName = $"{name}-{version}/PKG-INFO";

        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tw = new System.Formats.Tar.TarWriter(gz, leaveOpen: true))
        {
            var entry = new System.Formats.Tar.PaxTarEntry(System.Formats.Tar.TarEntryType.RegularFile, entryName)
            {
                DataStream = new MemoryStream(pkgInfoBytes)
            };
            tw.WriteEntry(entry);
        }

        var bytes = ms.ToArray();
        var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        return (bytes, hash);
    }

    /// <summary>Loads the real mypy_extensions wheel fixture.</summary>
    public static (byte[] Bytes, string Sha256Hex) RealWheel()
        => LoadFixture("pypi", "mypy_extensions-1.0.0-py3-none-any.whl");

    /// <summary>Loads the real mypy_extensions sdist fixture.</summary>
    public static (byte[] Bytes, string Sha256Hex) RealSdist()
        => LoadFixture("pypi", "mypy_extensions-1.0.0.tar.gz");

    private static (byte[], string) LoadFixture(string ecosystem, string filename)
    {
        var path = Path.Combine(FixtureManifest.FixturesRoot, ecosystem, filename);
        var bytes = File.ReadAllBytes(path);
        var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        return (bytes, hash);
    }

    private static void WriteEntry(ZipArchive zip, string name, string content)
    {
        var entry = zip.CreateEntry(name);
        using var writer = new StreamWriter(entry.Open());
        writer.Write(content);
    }
}
