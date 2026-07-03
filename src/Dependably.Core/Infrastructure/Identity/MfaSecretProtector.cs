using System.Security.Cryptography;

namespace Dependably.Infrastructure.Identity;

/// <summary>
/// AES-GCM implementation of <see cref="IMfaSecretProtector"/>. A single
/// <see cref="System.Security.Cryptography.AesGcm"/> instance is created lazily per protector
/// instance and reused across calls. <see cref="System.Security.Cryptography.AesGcm"/> is
/// thread-safe for concurrent Encrypt/Decrypt operations on .NET 8+.
/// </summary>
internal sealed class MfaSecretProtector : IMfaSecretProtector, IDisposable
{
    private const int KeySize = 32;     // 256-bit key — AES-256
    private const int NonceSize = 12;   // 96-bit nonce — GCM recommended minimum
    private const int TagSize = 16;      // 128-bit authentication tag

    private readonly AesGcm _aes;

    public MfaSecretProtector(byte[] key)
    {
        if (key.Length != KeySize)
        {
            throw new ArgumentException("AES-GCM key must be exactly 32 bytes (AES-256).", nameof(key));
        }

        _aes = new AesGcm(key, TagSize);
    }

    /// <inheritdoc/>
    public string Protect(string plaintext)
    {
        byte[] plaintextBytes = System.Text.Encoding.UTF8.GetBytes(plaintext);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] ciphertext = new byte[plaintextBytes.Length];
        byte[] tag = new byte[TagSize];

        _aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

        // Layout: nonce (12) || tag (16) || ciphertext (n)
        byte[] output = new byte[NonceSize + TagSize + ciphertext.Length];
        nonce.CopyTo(output, 0);
        tag.CopyTo(output, NonceSize);
        ciphertext.CopyTo(output, NonceSize + TagSize);

        return Convert.ToBase64String(output);
    }

    /// <inheritdoc/>
    public string Unprotect(string ciphertext)
    {
        byte[] raw;
        try
        {
            raw = Convert.FromBase64String(ciphertext);
        }
        catch (FormatException ex)
        {
            throw new MfaSecretProtectionException("MFA secret ciphertext is not valid base64.", ex);
        }

        if (raw.Length < NonceSize + TagSize)
        {
            throw new MfaSecretProtectionException("MFA secret ciphertext is too short to contain nonce and tag.");
        }

        byte[] nonce = raw[..NonceSize];
        byte[] tag = raw[NonceSize..(NonceSize + TagSize)];
        byte[] encryptedBytes = raw[(NonceSize + TagSize)..];
        byte[] plaintext = new byte[encryptedBytes.Length];

        try
        {
            _aes.Decrypt(nonce, encryptedBytes, tag, plaintext);
        }
        catch (CryptographicException ex)
        {
            throw new MfaSecretProtectionException("MFA secret authentication failed; the ciphertext may be tampered.", ex);
        }

        return System.Text.Encoding.UTF8.GetString(plaintext);
    }

    public void Dispose() => _aes.Dispose();
}
