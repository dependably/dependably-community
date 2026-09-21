using System.Diagnostics.CodeAnalysis;
using System.Formats.Tar;
using System.Security.Cryptography;
using System.Text;

namespace Dependably.Protocol.Hex;

/// <summary>
/// The four entries of a Hex package tarball, read from the raw (uncompressed) <c>.tar</c> the
/// registry stores and serves: <c>VERSION</c>, <c>CHECKSUM</c>, <c>metadata.config</c> and
/// <c>contents.tar.gz</c>. The contents archive is never unpacked here — nothing this registry
/// does needs a file out of it, and not extracting is what keeps tar-slip structurally
/// unreachable. <see cref="InnerChecksum"/> is the value the registry index must carry as
/// <c>Release.inner_checksum</c>; <see cref="OuterChecksum"/> is SHA-256 of the whole tarball,
/// the checksum clients verify a download against.
/// </summary>
public sealed record HexTarballParsed(
    string Version,
    byte[] InnerChecksum,
    byte[] OuterChecksum,
    string MetadataText,
    long ContentsBytes);

public static class HexTarball
{
    /// <summary>The only tarball format version hex_core produces or accepts.</summary>
    public const string SupportedVersion = "3";

    /// <summary>Caps mirrored from hex_core's tarball reader, so a tarball this registry accepts is one a client will too.</summary>
    public const int MaxVersionBytes = 32;
    public const int MaxChecksumBytes = 128;
    public const int MaxMetadataBytes = 1024 * 1024;

    /// <summary>Upper bound on entries walked before the four required ones are found; a real tarball has exactly four.</summary>
    public const int MaxEntries = 16;

    /// <summary>
    /// Reads and validates a package tarball. Every structural rule hex_core's own unpacker
    /// enforces is applied here — the four entries present, <c>VERSION</c> equal to
    /// <see cref="SupportedVersion"/>, and <c>CHECKSUM</c> equal to SHA-256 over
    /// <c>VERSION ‖ metadata.config ‖ contents.tar.gz</c> — so a tarball that would fail on the
    /// client is refused at publish. <paramref name="maxContentsBytes"/> caps the contents archive
    /// (already bounded by the upload cap on the publish path; the parameter exists so a caller
    /// reading a stored blob is bounded too). Throws <see cref="HexProtocolException"/> on any refusal.
    /// </summary>
    [SuppressMessage("Major Code Smell", "S3776:Cognitive Complexity of methods should not be too high",
        Justification = "One pass over the tar entries filling four required slots, then the completeness and checksum checks over "
            + "those slots. Splitting the pass from the checks would hand the checker four nullable buffers and lose the "
            + "single place that decides an entry set is admissible.")]
    public static HexTarballParsed Parse(byte[] tarball, long maxContentsBytes)
    {
        byte[]? version = null, checksum = null, metadata = null, contents = null;
        try
        {
            using var input = new MemoryStream(tarball, writable: false);
            using var tar = new TarReader(input, leaveOpen: true);
            int entries = 0;
            while (tar.GetNextEntry() is { } entry)
            {
                if (++entries > MaxEntries)
                {
                    throw new HexProtocolException("Package tarball carries more entries than the format allows.");
                }

                if (entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile) || entry.DataStream is null)
                {
                    continue;
                }

                switch (entry.Name)
                {
                    case "VERSION": version = ReadEntry(entry, MaxVersionBytes, "VERSION"); break;
                    case "CHECKSUM": checksum = ReadEntry(entry, MaxChecksumBytes, "CHECKSUM"); break;
                    case "metadata.config": metadata = ReadEntry(entry, MaxMetadataBytes, "metadata.config"); break;
                    case "contents.tar.gz": contents = ReadEntry(entry, maxContentsBytes, "contents.tar.gz"); break;
                    default: break;
                }
            }
        }
        catch (Exception ex) when (ex is InvalidDataException or EndOfStreamException or IOException or FormatException)
        {
            throw new HexProtocolException("Package tarball is not a readable tar archive.", ex);
        }

        if (version is null || checksum is null || metadata is null || contents is null)
        {
            var missing = new List<string>(4);
            if (version is null) { missing.Add("VERSION"); }
            if (checksum is null) { missing.Add("CHECKSUM"); }
            if (metadata is null) { missing.Add("metadata.config"); }
            if (contents is null) { missing.Add("contents.tar.gz"); }
            throw new HexProtocolException($"Package tarball is missing {string.Join(", ", missing)}.");
        }

        string versionText = Encoding.ASCII.GetString(version).Trim();
        if (versionText != SupportedVersion)
        {
            throw new HexProtocolException($"Package tarball format version '{versionText}' is not supported (expected {SupportedVersion}).");
        }

        byte[] declaredInner;
        try
        {
            declaredInner = Convert.FromHexString(Encoding.ASCII.GetString(checksum).Trim());
        }
        catch (FormatException ex)
        {
            throw new HexProtocolException("Package tarball CHECKSUM is not hex-encoded.", ex);
        }

        byte[] actualInner = ComputeInnerChecksum(version, metadata, contents);
        if (declaredInner.Length != 32 || !CryptographicOperations.FixedTimeEquals(declaredInner, actualInner))
        {
            throw new HexProtocolException("Package tarball CHECKSUM does not match its contents.");
        }

        string metadataText;
        try
        {
            metadataText = HexProtocolText.Utf8Strict.GetString(metadata);
        }
        catch (DecoderFallbackException)
        {
            // hex_core falls back to latin1 for a pre-UTF-8 metadata file; so does this reader.
            metadataText = Encoding.Latin1.GetString(metadata);
        }

        return new HexTarballParsed(versionText, actualInner, SHA256.HashData(tarball), metadataText, contents.LongLength);
    }

    /// <summary>SHA-256 over <c>VERSION ‖ metadata.config ‖ contents.tar.gz</c>, the value the <c>CHECKSUM</c> entry hex-encodes in upper case.</summary>
    public static byte[] ComputeInnerChecksum(byte[] version, byte[] metadata, byte[] contents)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        sha.AppendData(version);
        sha.AppendData(metadata);
        sha.AppendData(contents);
        return sha.GetHashAndReset();
    }

    /// <summary>
    /// Assembles a tarball from its parts in the entry order hex_core writes
    /// (<c>VERSION</c>, <c>CHECKSUM</c>, <c>metadata.config</c>, <c>contents.tar.gz</c>), with the
    /// fixed epoch mtime that makes the output reproducible. Used by tests and fixtures; the
    /// registry itself never rewrites a tarball a client uploaded.
    /// </summary>
    public static byte[] Build(string metadataText, byte[] contentsTarGz)
    {
        byte[] version = Encoding.ASCII.GetBytes(SupportedVersion);
        byte[] metadata = Encoding.UTF8.GetBytes(metadataText);
        byte[] checksum = Encoding.ASCII.GetBytes(Convert.ToHexString(ComputeInnerChecksum(version, metadata, contentsTarGz)));

        using var ms = new MemoryStream();
        using (var writer = new TarWriter(ms, TarEntryFormat.Ustar, leaveOpen: true))
        {
            WriteEntry(writer, "VERSION", version);
            WriteEntry(writer, "CHECKSUM", checksum);
            WriteEntry(writer, "metadata.config", metadata);
            WriteEntry(writer, "contents.tar.gz", contentsTarGz);
        }

        return ms.ToArray();
    }

    private static void WriteEntry(TarWriter writer, string name, byte[] data)
    {
        var entry = new UstarTarEntry(TarEntryType.RegularFile, name)
        {
            DataStream = new MemoryStream(data),
            ModificationTime = DateTimeOffset.UnixEpoch,
            Mode = (UnixFileMode)0b110_100_100,
        };
        writer.WriteEntry(entry);
    }

    private static byte[] ReadEntry(TarEntry entry, long maxBytes, string name)
    {
        if (entry.Length > maxBytes)
        {
            throw new HexProtocolException($"Package tarball entry {name} exceeds its {maxBytes}-byte limit.");
        }

        using var limited = new LimitedReadStream(entry.DataStream!, maxBytes, name);
        using var ms = new MemoryStream();
        limited.CopyTo(ms);
        return ms.ToArray();
    }
}
