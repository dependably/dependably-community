using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace Dependably.Tests.Infrastructure;

/// <summary>Generates synthetic NuGet packages for edge-case testing.</summary>
public static class NuGetFixtures
{
    /// <summary>
    /// Builds a minimal .nupkg (ZIP) in memory.
    /// Contains a .nuspec and an empty lib/netstandard2.0 entry.
    /// </summary>
    public static (byte[] Bytes, string Sha256Hex) BuildNupkg(string id, string version)
    {
        string nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
              <metadata>
                <id>{id}</id>
                <version>{version}</version>
                <authors>dependably-test</authors>
                <description>Synthetic test package</description>
              </metadata>
            </package>
            """;

        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteEntry(zip, $"{id}.nuspec", nuspec);
            // Minimal content entry so the package has something in it
            WriteEntry(zip, $"lib/netstandard2.0/_._", "");
        }

        byte[] bytes = ms.ToArray();
        string hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        return (bytes, hash);
    }

    /// <summary>Loads the real Newtonsoft.Json nupkg fixture.</summary>
    public static (byte[] Bytes, string Sha256Hex) RealNupkg()
    {
        string path = Path.Combine(FixtureManifest.FixturesRoot, "nuget", "Newtonsoft.Json.13.0.3.nupkg");
        byte[] bytes = File.ReadAllBytes(path);
        string hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        return (bytes, hash);
    }

    private static void WriteEntry(ZipArchive zip, string name, string content)
    {
        var entry = zip.CreateEntry(name);
        using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
        writer.Write(content);
    }
}
