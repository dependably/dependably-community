using System.Collections.Immutable;
using System.IO.Compression;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Security.Cryptography;
using System.Text;

namespace Dependably.Tests.Infrastructure;

/// <summary>Generates synthetic NuGet packages for edge-case testing.</summary>
public static class NuGetFixtures
{
    // ECMA-335 defines a fixed set of 64 metadata table indexes; PortablePdbBuilder requires the
    // type-system row-count array to be exactly this length.
    private const int MetadataTableCount = 64;

    /// <summary>
    /// Builds a minimal, valid Portable PDB whose debug-metadata signature GUID is exactly
    /// <paramref name="signature"/>. Serializing with a fixed <see cref="BlobContentId"/> pins the
    /// PDB id so a test can compute the expected SSQP key and assert the served bytes round-trip.
    /// </summary>
    public static byte[] BuildPortablePdb(Guid signature)
    {
        var metadata = new MetadataBuilder();
        var rowCounts = ImmutableArray.CreateRange(Enumerable.Repeat(0, MetadataTableCount));
        var pdbBuilder = new PortablePdbBuilder(
            metadata,
            rowCounts,
            entryPoint: default,
            idProvider: _ => new BlobContentId(signature, stamp: 0x04030201u));

        var blob = new BlobBuilder();
        pdbBuilder.Serialize(blob);
        return blob.ToArray();
    }

    /// <summary>
    /// Builds a <c>.snupkg</c> (ZIP) containing a <c>.nuspec</c> plus one or more PDB entries.
    /// Each entry is placed at <c>lib/netstandard2.0/{name}</c>. Used to exercise the symbol-server
    /// index-and-serve path with real Portable PDBs (and, for mixed scenarios, unreadable ones).
    /// </summary>
    public static byte[] BuildSnupkgWithPdbs(string id, string version, params (string PdbName, byte[] PdbBytes)[] pdbs)
    {
        string nuspec = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
              <metadata>
                <id>{id}</id>
                <version>{version}</version>
                <authors>dependably-test</authors>
                <description>Synthetic symbol package</description>
              </metadata>
            </package>
            """;

        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteEntry(zip, $"{id}.nuspec", nuspec);
            foreach (var (pdbName, pdbBytes) in pdbs)
            {
                var entry = zip.CreateEntry($"lib/netstandard2.0/{pdbName}");
                using var s = entry.Open();
                s.Write(pdbBytes, 0, pdbBytes.Length);
            }
        }

        return ms.ToArray();
    }

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

    /// <summary>
    /// Corrupts a well-formed ZIP so a single named entry becomes unreadable: rewrites both the
    /// local-file-header and central-directory-record compression-method field for that entry to
    /// an unsupported value, leaving every other entry (and every size/CRC field) untouched. Models
    /// a real-world corrupt/unsupported-compression <c>.pdb</c> entry inside an otherwise
    /// well-formed <c>.snupkg</c> — the archive parses fine at the ZIP-structure level (entry names
    /// enumerate normally), but <c>ZipArchiveEntry.Open()</c> throws for that one entry.
    /// </summary>
    public static byte[] CorruptEntryCompressionMethod(byte[] zipBytes, string entryName)
    {
        byte[] bytes = (byte[])zipBytes.Clone();

        int eocd = FindSignature(bytes, 0x06054b50, fromEnd: true)
            ?? throw new InvalidOperationException("EOCD signature not found.");
        int cdOffset = BitConverter.ToInt32(bytes, eocd + 16);
        int cdCount = BitConverter.ToUInt16(bytes, eocd + 10);

        int pos = cdOffset;
        for (int i = 0; i < cdCount; i++)
        {
            if (BitConverter.ToUInt32(bytes, pos) != 0x02014b50)
            {
                throw new InvalidOperationException("Central directory record signature mismatch.");
            }

            int fnLen = BitConverter.ToUInt16(bytes, pos + 28);
            int extraLen = BitConverter.ToUInt16(bytes, pos + 30);
            int commentLen = BitConverter.ToUInt16(bytes, pos + 32);
            string name = Encoding.UTF8.GetString(bytes, pos + 46, fnLen);

            if (name == entryName)
            {
                int lfhOffset = BitConverter.ToInt32(bytes, pos + 42);
                byte[] unsupportedMethod = BitConverter.GetBytes((ushort)99);
                unsupportedMethod.CopyTo(bytes, pos + 10);       // central directory compression method
                unsupportedMethod.CopyTo(bytes, lfhOffset + 8);  // local file header compression method
                return bytes;
            }

            pos += 46 + fnLen + extraLen + commentLen;
        }

        throw new InvalidOperationException($"Entry '{entryName}' not found in central directory.");
    }

    private static int? FindSignature(byte[] bytes, uint signature, bool fromEnd)
    {
        byte[] sig = BitConverter.GetBytes(signature);
        if (fromEnd)
        {
            for (int i = bytes.Length - sig.Length; i >= 0; i--)
            {
                if (bytes[i] == sig[0] && bytes[i + 1] == sig[1] && bytes[i + 2] == sig[2] && bytes[i + 3] == sig[3])
                {
                    return i;
                }
            }
            return null;
        }

        for (int i = 0; i <= bytes.Length - sig.Length; i++)
        {
            if (bytes[i] == sig[0] && bytes[i + 1] == sig[1] && bytes[i + 2] == sig[2] && bytes[i + 3] == sig[3])
            {
                return i;
            }
        }
        return null;
    }
}
