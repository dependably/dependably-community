using System.IO.Compression;
using System.Reflection.Metadata;

namespace Dependably.Protocol;

/// <summary>
/// Derives Simple Symbol Query Protocol (SSQP) lookup keys for the PDBs shipped inside a NuGet
/// symbol package (<c>.snupkg</c>) and enumerates those PDBs from the archive.
///
/// A debugger (Visual Studio, WinDbg, <c>dotnet-symbol</c>) knows a module's PDB debug-id — the
/// Portable-PDB signature GUID plus an age — not the NuGet id/version. The SSQP key encodes that
/// debug-id so the symbol server can resolve a single PDB on demand. For Portable PDBs the age is
/// always <c>0xFFFFFFFF</c>, so the key is the 32-hex GUID (<see cref="Guid.ToString(string)"/>
/// with the <c>"N"</c> format) followed by the literal <c>ffffffff</c>, lowercased.
///
/// The 16-byte signature is read from the Portable PDB's debug-metadata header
/// (<see cref="DebugMetadataHeader.Id"/>, first 16 of its 20 bytes); constructing a
/// <see cref="Guid"/> from those bytes applies the correct mixed-endian read of the first three
/// components. This is the single source of truth for symbol-key construction.
/// </summary>
public static class NuGetSymbolKey
{
    // Portable PDBs always report an age of 0xFFFFFFFF, so the SSQP key suffix is fixed.
    private const string PortablePdbAge = "ffffffff";

    // A Guid is built from the first 16 of the debug-metadata header's 20 signature bytes.
    private const int GuidSignatureLength = 16;

    /// <summary>
    /// Builds the SSQP lookup key for a Portable PDB from its signature GUID:
    /// the 32-hex GUID (<c>"N"</c> format) followed by the fixed <c>ffffffff</c> age, lowercased.
    /// </summary>
    public static string PortableKey(Guid signature) =>
        signature.ToString("N").ToLowerInvariant() + PortablePdbAge;

    /// <summary>
    /// Builds the SSQP request path segment <c>{filename}/{key}/{filename}</c> with the filename
    /// lowercased at both positions, per the SSQP key conventions.
    /// </summary>
    public static string LookupPath(string pdbFileName, string key)
    {
        string lower = pdbFileName.ToLowerInvariant();
        return $"{lower}/{key.ToLowerInvariant()}/{lower}";
    }

    /// <summary>
    /// Reads the SSQP key of a single Portable PDB from a stream. Returns <see langword="null"/>
    /// when the stream is not a readable Portable PDB (native PDB, corrupt, or empty) — the caller
    /// treats that as "not indexable" and skips it. The stream is fully buffered internally, so a
    /// non-seekable source (e.g. a ZIP entry stream) is accepted.
    /// </summary>
    public static string? TryReadPortableKey(Stream pdbStream)
    {
        try
        {
            // MetadataReaderProvider needs a seekable stream; buffer the (small) PDB in memory.
            using var buffer = new MemoryStream();
            pdbStream.CopyTo(buffer);
            buffer.Position = 0;

            using var provider = MetadataReaderProvider.FromPortablePdbStream(buffer);
            var reader = provider.GetMetadataReader();
            var id = reader.DebugMetadataHeader?.Id ?? default;
            if (id.Length < GuidSignatureLength)
            {
                return null;
            }

            byte[] guidBytes = new byte[GuidSignatureLength];
            id.CopyTo(0, guidBytes, 0, GuidSignatureLength);
            return PortableKey(new Guid(guidBytes));
        }
        // InvalidDataException derives directly from SystemException, NOT IOException, so it must
        // be listed explicitly: LimitedReadStream (the decompression-bomb guard the caller wraps
        // this stream in) throws it when the cap is exceeded, and ZipArchiveEntry.Open()/the
        // deflate reader throws it for a corrupt entry (bad CRC, truncated deflate stream).
        catch (Exception ex) when (ex is BadImageFormatException or InvalidOperationException
            or IOException or InvalidDataException)
        {
            // Not a Portable PDB (native/Windows PDB, truncated, over the decompression cap, or
            // otherwise unreadable). Native PDB indexing is out of scope; the caller skips this entry.
            return null;
        }
    }

    /// <summary>
    /// Enumerates the indexable PDBs inside a <c>.snupkg</c> ZIP: for each <c>.pdb</c> entry that
    /// parses as a Portable PDB, yields its lowercased filename, SSQP key, and the entry's path
    /// within the archive (needed to re-extract the PDB bytes on a later symbol-server request).
    /// Non-Portable / unreadable / oversized PDBs are skipped-with-null by
    /// <see cref="TryExtractEntryKey"/>; a single bad entry never fails the whole extraction. The
    /// caller retains ownership of the stream.
    /// </summary>
    public static IReadOnlyList<PdbSymbol> ExtractPortablePdbs(Stream snupkgStream)
    {
        var results = new List<PdbSymbol>();
        using var zip = new ZipArchive(snupkgStream, ZipArchiveMode.Read, leaveOpen: true);
        foreach (var entry in zip.Entries)
        {
            if (!entry.Name.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string? key = TryExtractEntryKey(entry);
            if (key is null)
            {
                continue;
            }

            results.Add(new PdbSymbol(entry.Name.ToLowerInvariant(), key, entry.FullName));
        }

        return results;
    }

    /// <summary>
    /// Opens one ZIP entry and reads its SSQP key, guarded end-to-end: the decompressed read is
    /// capped at <see cref="ZipEntryLimits.MaxPdbEntryBytes"/> via <see cref="LimitedReadStream"/>
    /// (the same decompression-bomb guard <see cref="NuGetNupkgValidator"/> applies to the nuspec
    /// read), and <c>entry.Open()</c> itself — which throws for an unsupported compression method
    /// or a corrupt local-file header — runs inside the guard rather than unguarded in the caller's
    /// loop. A bad entry returns <see langword="null"/> (skip) instead of failing the whole archive.
    /// </summary>
    private static string? TryExtractEntryKey(ZipArchiveEntry entry)
    {
        try
        {
            using var entryStream = new LimitedReadStream(
                entry.Open(), ZipEntryLimits.MaxPdbEntryBytes, "PDB entry");
            return TryReadPortableKey(entryStream);
        }
        catch (Exception ex) when (ex is BadImageFormatException or InvalidOperationException
            or IOException or InvalidDataException or NotSupportedException)
        {
            return null;
        }
    }
}

/// <summary>
/// One indexable PDB extracted from a symbol package: its lowercased filename, its SSQP lookup
/// key, and the full path of the entry inside the <c>.snupkg</c> ZIP.
/// </summary>
public sealed record PdbSymbol(string PdbFileName, string SsqpKey, string EntryPath);
