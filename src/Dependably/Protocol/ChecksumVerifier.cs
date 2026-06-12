using System.Security.Cryptography;

namespace Dependably.Protocol;

public enum ChecksumAlgorithm { Sha256, Sha512, Sha1 }

public sealed record ChecksumSpec(ChecksumAlgorithm Algorithm, string ExpectedValue);

/// <summary>
/// Verifies checksums per ecosystem:
///   PyPI    — SHA-256 hex from #sha256= fragment
///   npm     — SRI sha512-{base64} (primary) or shasum hex SHA-1 (fallback)
///   NuGet   — base64-encoded SHA-512 as packageHash
/// </summary>
public static class ChecksumVerifier
{
    /// <summary>Parses the #sha256= fragment from a PyPI download URL.</summary>
    public static ChecksumSpec? ParsePyPiUrl(string url)
    {
        int idx = url.IndexOf("#sha256=", StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
        {
            return null;
        }

        string hash = url[(idx + 8)..];
        return new ChecksumSpec(ChecksumAlgorithm.Sha256, hash);
    }

    /// <summary>Parses npm integrity (SRI sha512-{base64}) or shasum (hex SHA-1).</summary>
    public static ChecksumSpec? ParseNpmIntegrity(string? integrity, string? shasum)
    {
        if (integrity is not null && integrity.StartsWith("sha512-", StringComparison.OrdinalIgnoreCase))
        {
            string b64 = integrity[7..];
            return new ChecksumSpec(ChecksumAlgorithm.Sha512, b64); // base64-encoded
        }
        if (shasum is not null)
        {
            return new ChecksumSpec(ChecksumAlgorithm.Sha1, shasum); // hex SHA-1
        }

        return null;
    }

    /// <summary>Parses NuGet packageHash (base64 SHA-512) + packageHashAlgorithm.</summary>
    public static ChecksumSpec? ParseNuGetHash(string? packageHash, string? algorithm)
    {
        if (string.IsNullOrEmpty(packageHash) || string.IsNullOrEmpty(algorithm))
        {
            return null;
        }

        if (!algorithm.Equals("SHA512", StringComparison.OrdinalIgnoreCase))
        {
            return null; // Only SHA512 accepted; caller emits checksum_algorithm_unsupported
        }

        return new ChecksumSpec(ChecksumAlgorithm.Sha512, packageHash); // base64-encoded
    }

    /// <summary>
    /// Verifies bytes against a ChecksumSpec.
    /// Returns true if valid (or spec is null — no verification possible).
    /// </summary>
    public static bool Verify(byte[] data, ChecksumSpec? spec)
    {
        if (spec is null)
        {
            return true; // caller must decide whether to cache without checksum
        }

        return spec.Algorithm switch
        {
            ChecksumAlgorithm.Sha256 => VerifyHex(data, spec.ExpectedValue, SHA256.HashData),
            ChecksumAlgorithm.Sha1 => VerifyHex(data, spec.ExpectedValue, SHA1.HashData),
            ChecksumAlgorithm.Sha512 => VerifyBase64OrHex(data, spec.ExpectedValue, SHA512.HashData),
            _ => false
        };
    }

    public static string ComputeSha256Hex(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    /// <summary>
    /// Streaming SHA-256 of an unread stream. Reads through to EOF using a single 81920-byte
    /// buffer + <see cref="IncrementalHash"/>; does not buffer the whole stream. Used by the
    /// hash-and-stage proxy-fetch path where the bytes have already been written to a
    /// temp file and we re-read them for blob upload.
    /// </summary>
    public static async ValueTask<string> ComputeSha256HexAsync(Stream data, CancellationToken ct = default)
    {
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[81920];
        int read;
        while ((read = await data.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
        {
            hasher.AppendData(buffer, 0, read);
        }

        return Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
    }

    /// <summary>
    /// Streaming checksum verification. Mirrors <see cref="Verify(byte[], ChecksumSpec?)"/>
    /// semantics — returns true when <paramref name="spec"/> is null (no verification
    /// possible). Spec.Algorithm controls the hash; SHA-512 accepts either base64 or hex
    /// expected encodings (mirrors <see cref="VerifyBase64OrHex"/>).
    /// </summary>
    public static async ValueTask<bool> VerifyAsync(
        Stream data, ChecksumSpec? spec, CancellationToken ct = default)
    {
        if (spec is null)
        {
            return true;
        }

        var algo = spec.Algorithm switch
        {
            ChecksumAlgorithm.Sha256 => HashAlgorithmName.SHA256,
            ChecksumAlgorithm.Sha1 => HashAlgorithmName.SHA1,
            ChecksumAlgorithm.Sha512 => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256
        };
        using var hasher = IncrementalHash.CreateHash(algo);
        byte[] buffer = new byte[81920];
        int read;
        while ((read = await data.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
        {
            hasher.AppendData(buffer, 0, read);
        }

        byte[] actualBytes = hasher.GetHashAndReset();

        if (spec.Algorithm == ChecksumAlgorithm.Sha512)
        {
            // NuGet form: base64-encoded SHA-512. Fall through to hex for any other source.
            try
            {
                byte[] expectedBytes = Convert.FromBase64String(spec.ExpectedValue);
                return CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytes);
            }
            catch { /* fall through to hex */ }
        }
        string actualHex = Convert.ToHexString(actualBytes).ToLowerInvariant();
        return string.Equals(actualHex, spec.ExpectedValue.ToLowerInvariant(), StringComparison.Ordinal);
    }

    private static bool VerifyHex(byte[] data, string expected, Func<byte[], byte[]> hashFn)
    {
        string actual = Convert.ToHexString(hashFn(data)).ToLowerInvariant();
        return string.Equals(actual, expected.ToLowerInvariant(), StringComparison.Ordinal);
    }

    private static bool VerifyBase64OrHex(byte[] data, string expected, Func<byte[], byte[]> hashFn)
    {
        byte[] actualBytes = hashFn(data);
        // Try base64 first (NuGet format)
        try
        {
            byte[] expectedBytes = Convert.FromBase64String(expected);
            return CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytes);
        }
        catch { /* fall through to hex */ }
        string actualHex = Convert.ToHexString(actualBytes).ToLowerInvariant();
        return string.Equals(actualHex, expected.ToLowerInvariant(), StringComparison.Ordinal);
    }
}
