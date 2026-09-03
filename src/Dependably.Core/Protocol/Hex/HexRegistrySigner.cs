using System.IO.Compression;
using System.Security.Cryptography;

namespace Dependably.Protocol.Hex;

/// <summary>
/// Signs and verifies Hex registry resources. The scheme is fixed by what every Hex client
/// checks: RSASSA-PKCS1-v1_5 over a SHA-512 digest of the raw payload, carried in a
/// <c>Signed</c> envelope, gzipped. PKCS#1 v1.5 is deterministic, so signing an unchanged
/// payload yields identical bytes and a resource's ETag stays stable across polls — which
/// hex_core relies on, sending <c>if-none-match</c> on every registry fetch.
/// </summary>
public static class HexRegistrySigner
{
    /// <summary>Decompressed bytes allowed when opening a resource fetched from an upstream.</summary>
    public const long MaxDecompressedBytes = HexRegistryCodec.MaxPayloadBytes;

    /// <summary>The size every signing key this registry generates has. hex.pm's own key is 2048 bits.</summary>
    public const int GeneratedKeyBits = 4096;

    public static byte[] Sign(ReadOnlySpan<byte> payload, RSA privateKey)
    {
        byte[] digest = SHA512.HashData(payload);
        return privateKey.SignHash(digest, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
    }

    public static bool Verify(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature, RSA publicKey)
    {
        byte[] digest = SHA512.HashData(payload);
        return publicKey.VerifyHash(digest, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
    }

    /// <summary>Wraps <paramref name="payload"/> in a signed envelope and gzips it: the bytes a registry serves.</summary>
    public static byte[] BuildResource(byte[] payload, RSA privateKey)
    {
        byte[] envelope = HexRegistryCodec.EncodeSigned(new HexSigned(payload, Sign(payload, privateKey)));
        return Gzip(envelope);
    }

    /// <summary>
    /// The inverse of <see cref="BuildResource"/> for a resource fetched from an upstream: gunzips
    /// under a byte cap, decodes the envelope, and returns the payload only when its signature
    /// verifies against <paramref name="publicKey"/>. A payload that fails to verify, or an
    /// envelope with no signature at all, is refused — an unsigned upstream index is not one this
    /// registry re-signs under its own key.
    /// </summary>
    public static byte[] OpenResource(ReadOnlySpan<byte> compressed, RSA publicKey)
    {
        byte[] envelope = Gunzip(compressed);
        var signed = HexRegistryCodec.DecodeSigned(envelope);
        return signed.Signature is not null && Verify(signed.Payload, signed.Signature, publicKey)
            ? signed.Payload
            : throw new HexProtocolException("Registry resource signature does not verify against the repository public key.");
    }

    public static byte[] Gzip(ReadOnlySpan<byte> data)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
        {
            gz.Write(data);
        }

        return ms.ToArray();
    }

    public static byte[] Gunzip(ReadOnlySpan<byte> compressed)
    {
        try
        {
            using var input = new MemoryStream(compressed.ToArray());
            using var limited = new LimitedReadStream(
                new GZipStream(input, CompressionMode.Decompress, leaveOpen: false),
                MaxDecompressedBytes, "Hex registry resource");
            using var output = new MemoryStream();
            limited.CopyTo(output);
            return output.ToArray();
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException)
        {
            throw new HexProtocolException("Registry resource is not valid gzip.", ex);
        }
    }

    /// <summary>Parses a PEM <c>PUBLIC KEY</c> (SubjectPublicKeyInfo) block, the form <c>/public_key</c> serves.</summary>
    public static RSA ParsePublicKeyPem(string pem)
    {
        try
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return rsa;
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            throw new HexProtocolException("Repository public key is not a PEM RSA public key.", ex);
        }
    }

    public static string ExportPublicKeyPem(RSA key) => key.ExportSubjectPublicKeyInfoPem() + "\n";

    /// <summary>Generates a fresh signing keypair of <see cref="GeneratedKeyBits"/> bits.</summary>
    public static RSA GenerateSigningKey() => RSA.Create(GeneratedKeyBits);
}
