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
        var idx = url.IndexOf("#sha256=", StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;
        var hash = url[(idx + 8)..];
        return new ChecksumSpec(ChecksumAlgorithm.Sha256, hash);
    }

    /// <summary>Parses npm integrity (SRI sha512-{base64}) or shasum (hex SHA-1).</summary>
    public static ChecksumSpec? ParseNpmIntegrity(string? integrity, string? shasum)
    {
        if (integrity is not null && integrity.StartsWith("sha512-", StringComparison.OrdinalIgnoreCase))
        {
            var b64 = integrity[7..];
            return new ChecksumSpec(ChecksumAlgorithm.Sha512, b64); // base64-encoded
        }
        if (shasum is not null)
            return new ChecksumSpec(ChecksumAlgorithm.Sha1, shasum); // hex SHA-1
        return null;
    }

    /// <summary>Parses NuGet packageHash (base64 SHA-512) + packageHashAlgorithm.</summary>
    public static ChecksumSpec? ParseNuGetHash(string? packageHash, string? algorithm)
    {
        if (string.IsNullOrEmpty(packageHash) || string.IsNullOrEmpty(algorithm))
            return null;
        if (!algorithm.Equals("SHA512", StringComparison.OrdinalIgnoreCase))
            return null; // Only SHA512 accepted; caller emits checksum_algorithm_unsupported
        return new ChecksumSpec(ChecksumAlgorithm.Sha512, packageHash); // base64-encoded
    }

    /// <summary>
    /// Verifies bytes against a ChecksumSpec.
    /// Returns true if valid (or spec is null — no verification possible).
    /// </summary>
    public static bool Verify(byte[] data, ChecksumSpec? spec)
    {
        if (spec is null) return true; // caller must decide whether to cache without checksum

        return spec.Algorithm switch
        {
            ChecksumAlgorithm.Sha256 => VerifyHex(data, spec.ExpectedValue, SHA256.HashData),
            ChecksumAlgorithm.Sha1   => VerifyHex(data, spec.ExpectedValue, SHA1.HashData),
            ChecksumAlgorithm.Sha512 => VerifyBase64OrHex(data, spec.ExpectedValue, SHA512.HashData),
            _ => false
        };
    }

    public static string ComputeSha256Hex(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private static bool VerifyHex(byte[] data, string expected, Func<byte[], byte[]> hashFn)
    {
        var actual = Convert.ToHexString(hashFn(data)).ToLowerInvariant();
        return string.Equals(actual, expected.ToLowerInvariant(), StringComparison.Ordinal);
    }

    private static bool VerifyBase64OrHex(byte[] data, string expected, Func<byte[], byte[]> hashFn)
    {
        var actualBytes = hashFn(data);
        // Try base64 first (NuGet format)
        try
        {
            var expectedBytes = Convert.FromBase64String(expected);
            return CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytes);
        }
        catch { /* fall through to hex */ }
        var actualHex = Convert.ToHexString(actualBytes).ToLowerInvariant();
        return string.Equals(actualHex, expected.ToLowerInvariant(), StringComparison.Ordinal);
    }
}
