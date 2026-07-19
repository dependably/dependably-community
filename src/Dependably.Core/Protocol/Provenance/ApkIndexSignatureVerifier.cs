using System.Buffers.Binary;
using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using Dependably.Protocol;

namespace Dependably.Protocol.Provenance;

/// <summary>Digest algorithm encoded in an apk <c>.SIGN.*</c> tar entry's filename prefix.</summary>
public enum ApkSignatureAlgorithm
{
    /// <summary><c>.SIGN.RSA.&lt;keyname&gt;</c> — SHA-1 (the variant Alpine currently ships).</summary>
    Sha1,

    /// <summary><c>.SIGN.RSA256.&lt;keyname&gt;</c> — SHA-256.</summary>
    Sha256,

    /// <summary><c>.SIGN.RSA512.&lt;keyname&gt;</c> — SHA-512.</summary>
    Sha512,
}

/// <summary>One <c>.SIGN.*</c> entry extracted from an <c>APKINDEX.tar.gz</c> signature member.</summary>
public sealed record ApkIndexSignature(string KeyName, ApkSignatureAlgorithm Algorithm, byte[] SignatureBytes);

/// <summary>
/// Result of successfully splitting an <c>APKINDEX.tar.gz</c> into its embedded signatures and
/// the raw compressed bytes those signatures were computed over.
/// </summary>
public sealed record ParsedApkIndex(IReadOnlyList<ApkIndexSignature> Signatures, byte[] SignedPayload);

/// <summary>Caps applied when parsing the embedded apk index signature member.</summary>
public static class ApkIndexSignatureLimits
{
    /// <summary>
    /// Maximum decompressed size of the first gzip member (the signature tar). It holds a
    /// handful of small <c>.SIGN.*</c> entries, never a package-scale payload.
    /// </summary>
    public const long MaxSignatureMemberDecompressedBytes = 4L * 1024 * 1024;

    /// <summary>
    /// Maximum size of a single signature blob. RSA-4096/PKCS#1v1.5 signatures are 512 bytes;
    /// this leaves generous headroom without allowing an unbounded read.
    /// </summary>
    public const int MaxSignatureBytes = 4096;

    /// <summary>Maximum number of entries scanned inside the signature tar member.</summary>
    public const int MaxSignatureEntries = 64;
}

/// <summary>
/// Parses and verifies the RSA signature(s) embedded in an Alpine <c>APKINDEX.tar.gz</c>.
///
/// <para><c>APKINDEX.tar.gz</c> is not a single gzip stream: it is two (or more) concatenated
/// gzip members. The first member decompresses to a tiny tar archive containing one or more
/// <c>.SIGN.RSA[256|512].&lt;keyname&gt;</c> entries — each entry's content is a raw RSA
/// PKCS#1v1.5 signature. The signed payload is <b>not</b> the decompressed index; it is the
/// raw compressed bytes of every gzip member after the first, taken byte-for-byte.</para>
///
/// <para>Locating the exact boundary between the first member and the rest is the crux of
/// parsing this format correctly. <see cref="System.IO.Compression.GZipStream"/> transparently
/// decodes concatenated members when read to completion, and even a raw
/// <see cref="System.IO.Compression.DeflateStream"/> reads ahead into its own internal buffer
/// rather than stopping the underlying stream's position exactly at the compressed data's
/// logical end — so the position of the source stream after decompression cannot be trusted as
/// the boundary. Instead this parser recomputes the gzip trailer (CRC-32 + ISIZE, the standard
/// 8-byte trailer every gzip member ends with) from the member's decompressed bytes and
/// locates that exact byte sequence in the raw input; the boundary is confirmed by checking
/// that what follows is either end-of-input or another gzip member's magic bytes.</para>
/// </summary>
public static class ApkIndexSignatureVerifier
{
    private const string Rsa1Prefix = ".SIGN.RSA.";
    private const string Rsa256Prefix = ".SIGN.RSA256.";
    private const string Rsa512Prefix = ".SIGN.RSA512.";

    /// <summary>
    /// Verifies <paramref name="apkindex"/> against the given trust anchors. Returns true iff
    /// the index parses cleanly, carries at least one <c>.SIGN.*</c> entry, and at least one
    /// entry verifies against at least one anchor. Never throws — malformed gzip/tar, a missing
    /// signature member, zero anchors, or a truncated input all resolve to false.
    /// </summary>
    public static bool Verify(byte[] apkindex, IReadOnlyList<RSA> anchors, ILogger? logger = null)
        => VerifyWithReason(apkindex, anchors, logger).Verified;

    /// <summary>
    /// Same as <see cref="Verify"/> but also returns a machine-readable failure reason
    /// (<c>malformed_index</c> | <c>missing_signature</c> | <c>no_trusted_key</c> |
    /// <c>bad_signature</c>) suitable for metrics tagging and logging. Reason is empty on success.
    /// </summary>
    public static (bool Verified, string Reason) VerifyWithReason(
        byte[] apkindex, IReadOnlyList<RSA> anchors, ILogger? logger = null)
    {
        var parsed = TryParse(apkindex, logger);
        if (parsed is null)
        {
            return (false, "malformed_index");
        }

        if (parsed.Signatures.Count == 0)
        {
            return (false, "missing_signature");
        }

        if (anchors.Count == 0)
        {
            return (false, "no_trusted_key");
        }

        foreach (var sig in parsed.Signatures)
        {
            if (VerifiesAgainstAnyAnchor(parsed.SignedPayload, sig, anchors))
            {
                return (true, "");
            }
        }

        return (false, "bad_signature");
    }

    // Tries every trust anchor against one signature entry, returning true on the first that
    // verifies. An unsupported algorithm (never assigned by ParseSignatureEntries today, but
    // defensive) fails this signature entry without consuming any anchor.
    private static bool VerifiesAgainstAnyAnchor(
        byte[] signedPayload, ApkIndexSignature sig, IReadOnlyList<RSA> anchors)
    {
        HashAlgorithmName? hashAlgorithm = sig.Algorithm switch
        {
            ApkSignatureAlgorithm.Sha1 => HashAlgorithmName.SHA1,
            ApkSignatureAlgorithm.Sha256 => HashAlgorithmName.SHA256,
            ApkSignatureAlgorithm.Sha512 => HashAlgorithmName.SHA512,
            _ => null,
        };
        if (hashAlgorithm is null)
        {
            return false;
        }

        foreach (var key in anchors)
        {
            if (VerifiesWithKey(signedPayload, sig.SignatureBytes, hashAlgorithm.Value, key))
            {
                return true;
            }
        }

        return false;
    }

    // Signature bytes that are not a valid PKCS#1v1.5 encoding for this key fail closed (false)
    // rather than throwing, so the caller tries the next anchor/signature pair.
    private static bool VerifiesWithKey(
        byte[] signedPayload, byte[] signatureBytes, HashAlgorithmName hashAlgorithm, RSA key)
    {
        try
        {
            return key.VerifyData(signedPayload, signatureBytes, hashAlgorithm, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// Splits <paramref name="apkindex"/> into its embedded <c>.SIGN.*</c> signatures and the
    /// raw signed payload bytes. Returns null on any parse failure (never throws).
    /// </summary>
    internal static ParsedApkIndex? TryParse(byte[] apkindex, ILogger? logger)
    {
        try
        {
            if (!TryParseGzipHeader(apkindex, out int deflateStart))
            {
                return null;
            }

            if (!TryInflateFirstMember(apkindex, deflateStart, out byte[]? decompressed) || decompressed is null)
            {
                return null;
            }

            int memberEnd = FindFirstMemberEnd(apkindex, deflateStart, decompressed);
            if (memberEnd <= 0 || memberEnd >= apkindex.Length)
            {
                logger?.LogWarning(
                    "apk index signature member boundary could not be located; treating APKINDEX.tar.gz as malformed.");
                return null;
            }

            byte[] signedPayload = apkindex[memberEnd..];
            var signatures = ParseSignatureEntries(decompressed, logger);
            return new ParsedApkIndex(signatures, signedPayload);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or ObjectDisposedException
                                       or FormatException or OverflowException or ArgumentException)
        {
            logger?.LogWarning(
                ex, "apk index signature parse failed ({ExceptionType}); treating APKINDEX.tar.gz as malformed.",
                ex.GetType().Name);
            return null;
        }
    }

    // Parses the fixed 10-byte gzip header plus any optional FEXTRA/FNAME/FCOMMENT/FHCRC
    // fields, returning the offset where the raw deflate body begins. False on a truncated
    // or non-gzip input.
    private static bool TryParseGzipHeader(byte[] data, out int deflateStart)
    {
        deflateStart = 0;
        if (data.Length < 10 || data[0] != 0x1f || data[1] != 0x8b || data[2] != 0x08)
        {
            return false;
        }

        byte flg = data[3];
        int pos = 10;

        if ((flg & 0x04) != 0)  // FEXTRA
        {
            if (pos + 2 > data.Length)
            {
                return false;
            }
            int xlen = data[pos] | (data[pos + 1] << 8);
            pos += 2 + xlen;
            if (pos > data.Length)
            {
                return false;
            }
        }

        if ((flg & 0x08) != 0 && !SkipNulTerminated(data, ref pos))  // FNAME
        {
            return false;
        }

        if ((flg & 0x10) != 0 && !SkipNulTerminated(data, ref pos))  // FCOMMENT
        {
            return false;
        }

        if ((flg & 0x02) != 0)  // FHCRC
        {
            pos += 2;
            if (pos > data.Length)
            {
                return false;
            }
        }

        if (pos >= data.Length)
        {
            return false;
        }

        deflateStart = pos;
        return true;
    }

    private static bool SkipNulTerminated(byte[] data, ref int pos)
    {
        while (pos < data.Length && data[pos] != 0)
        {
            pos++;
        }
        if (pos >= data.Length)
        {
            return false;
        }
        pos++;
        return true;
    }

    // Decompresses the raw deflate body starting at deflateStart. A plain DeflateStream reads
    // ahead into its internal buffer past the logical end of this member's compressed data
    // (it will happily keep consuming bytes belonging to the next gzip member), but the
    // *decompressed output* it produces is still exactly this member's content — the deflate
    // BFINAL bit correctly terminates the logical bitstream at the right point regardless of
    // how much extra input the stream implementation buffered. Capped to guard against a
    // decompression-bomb crafted first member.
    private static bool TryInflateFirstMember(byte[] data, int deflateStart, out byte[]? decompressed)
    {
        decompressed = null;
        try
        {
            using var source = new MemoryStream(data, deflateStart, data.Length - deflateStart, writable: false);
            using var inflate = new DeflateStream(source, CompressionMode.Decompress, leaveOpen: true);
            using var limited = new LimitedReadStream(
                inflate, ApkIndexSignatureLimits.MaxSignatureMemberDecompressedBytes, "apk index signature member");
            using var outMs = new MemoryStream();
            limited.CopyTo(outMs);
            decompressed = outMs.ToArray();
            return true;
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or ObjectDisposedException)
        {
            return false;
        }
    }

    // Locates the exact end of the first gzip member (header + compressed body + 8-byte
    // trailer) by recomputing the trailer (CRC-32 of the decompressed bytes, little-endian,
    // followed by the decompressed length mod 2^32, little-endian) and searching for that exact
    // 8-byte sequence in the raw input. A candidate match is accepted only when it is followed
    // by end-of-input or another gzip member's magic bytes, so an accidental 8-byte collision
    // inside the compressed body cannot be mistaken for the real trailer.
    private static int FindFirstMemberEnd(byte[] data, int deflateStart, byte[] decompressed)
    {
        uint crc = Crc32.Compute(decompressed);
        uint isize = unchecked((uint)decompressed.Length);
        Span<byte> trailer = stackalloc byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(trailer, crc);
        BinaryPrimitives.WriteUInt32LittleEndian(trailer[4..], isize);

        for (int i = deflateStart; i <= data.Length - 8; i++)
        {
            if (!data.AsSpan(i, 8).SequenceEqual(trailer))
            {
                continue;
            }

            int after = i + 8;
            bool plausible = after == data.Length
                || (after + 2 <= data.Length && data[after] == 0x1f && data[after + 1] == 0x8b);
            if (plausible)
            {
                return after;
            }
        }

        return -1;
    }

    // Scans the decompressed signature-member tar for .SIGN.RSA[256|512].<keyname> entries.
    // Entries with an unrecognized name prefix are skipped (not every possible .SIGN.* variant
    // is supported); an oversized entry is skipped rather than failing the whole parse.
    private static List<ApkIndexSignature> ParseSignatureEntries(byte[] tarBytes, ILogger? logger)
    {
        var result = new List<ApkIndexSignature>();
        using var ms = new MemoryStream(tarBytes, writable: false);
        using var tar = new TarReader(ms, leaveOpen: false);

        int entryCount = 0;
        while (tar.GetNextEntry() is { } entry)
        {
            if (++entryCount > ApkIndexSignatureLimits.MaxSignatureEntries)
            {
                break;
            }

            if (entry.DataStream is null)
            {
                continue;
            }

            string name = entry.Name;
            if (name.StartsWith("./", StringComparison.Ordinal))
            {
                name = name[2..];
            }

            var classified = ClassifySignatureEntryName(name);
            if (classified is not { } c || string.IsNullOrEmpty(c.KeyName))
            {
                continue;
            }

            byte[] sigBytes;
            try
            {
                using var limited = new LimitedReadStream(
                    entry.DataStream, ApkIndexSignatureLimits.MaxSignatureBytes, "apk index signature entry");
                using var sigMs = new MemoryStream();
                limited.CopyTo(sigMs);
                sigBytes = sigMs.ToArray();
            }
            catch (InvalidDataException)
            {
                logger?.LogWarning(
                    "apk index signature entry {Entry} exceeds the {MaxBytes}-byte cap; skipping.",
                    c.KeyName, ApkIndexSignatureLimits.MaxSignatureBytes);
                continue;
            }

            if (sigBytes.Length == 0)
            {
                continue;
            }

            result.Add(new ApkIndexSignature(c.KeyName, c.Algorithm, sigBytes));
        }

        return result;
    }

    private static (ApkSignatureAlgorithm Algorithm, string KeyName)? ClassifySignatureEntryName(string name) =>
        name.StartsWith(Rsa256Prefix, StringComparison.Ordinal) ? (ApkSignatureAlgorithm.Sha256, name[Rsa256Prefix.Length..])
        : name.StartsWith(Rsa512Prefix, StringComparison.Ordinal) ? (ApkSignatureAlgorithm.Sha512, name[Rsa512Prefix.Length..])
        : name.StartsWith(Rsa1Prefix, StringComparison.Ordinal) ? (ApkSignatureAlgorithm.Sha1, name[Rsa1Prefix.Length..])
        : null;

    // Minimal table-driven CRC-32 (IEEE 802.3 polynomial), used only to recompute a gzip
    // member's trailer for boundary detection — not a cryptographic primitive.
    private static class Crc32
    {
        private static readonly uint[] Table = BuildTable();

        private static uint[] BuildTable()
        {
            uint[] table = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint c = i;
                for (int k = 0; k < 8; k++)
                {
                    c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
                }
                table[i] = c;
            }
            return table;
        }

        public static uint Compute(byte[] data)
        {
            uint crc = 0xFFFFFFFF;
            foreach (byte b in data)
            {
                crc = Table[(crc ^ b) & 0xFF] ^ (crc >> 8);
            }
            return crc ^ 0xFFFFFFFF;
        }
    }
}
