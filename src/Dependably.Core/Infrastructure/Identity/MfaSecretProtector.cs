using System.Security.Cryptography;

namespace Dependably.Infrastructure.Identity;

/// <summary>
/// AES-GCM implementation of <see cref="IMfaSecretProtector"/>. One
/// <see cref="System.Security.Cryptography.AesGcm"/> instance is created per protector and reused
/// across calls, and every Encrypt/Decrypt on it is serialized under <see cref="_aesGate"/>.
///
/// <para>The lock is load-bearing. <see cref="System.Security.Cryptography.AesGcm"/> makes no
/// thread-safety guarantee for instance members, and on Linux it does not have it: the
/// OpenSSL-backed implementation keeps one cipher context per instance and re-keys its IV on
/// every call, so two overlapping calls trample each other's state. The result is an
/// authentication failure, a silently wrong plaintext, or — from <see cref="Protect"/> — stored
/// ciphertext that can never be decrypted. This type backs the singleton
/// <see cref="EnvelopeProtector"/> and <see cref="IMfaSecretProtector"/>, which concurrent
/// requests and the per-org delivery workers share, so overlap is the normal case, not an edge
/// one. The macOS implementation is stateless per call, which is why a race here does not
/// reproduce on a developer Mac.</para>
/// </summary>
internal sealed class MfaSecretProtector : IMfaSecretProtector, IDisposable
{
    private const int KeySize = 32;     // 256-bit key — AES-256
    private const int NonceSize = 12;   // 96-bit nonce — GCM recommended minimum
    private const int TagSize = 16;      // 128-bit authentication tag

    private readonly AesGcm _aes;
    private readonly Lock _aesGate = new();

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

        lock (_aesGate)
        {
            _aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);
        }

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
            lock (_aesGate)
            {
                _aes.Decrypt(nonce, encryptedBytes, tag, plaintext);
            }
        }
        catch (CryptographicException ex)
        {
            throw new MfaSecretProtectionException("MFA secret authentication failed; the ciphertext may be tampered.", ex);
        }

        return System.Text.Encoding.UTF8.GetString(plaintext);
    }

    public void Dispose()
    {
        lock (_aesGate)
        {
            _aes.Dispose();
        }
    }
}
