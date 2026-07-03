using System.Security.Cryptography;
using System.Text;

namespace Dependably.Infrastructure.Identity;

/// <summary>
/// Hashes MFA recovery codes for storage. Identity generates recovery codes from a reduced
/// alphabet (~10 chars, roughly 47 bits of entropy), so a bare unsalted SHA-256 over that
/// space is offline-brute-forceable from a database dump. This hasher keys the digest with
/// the per-instance MFA encryption key (HMAC-SHA256) and adds a per-code random salt, so the
/// stored form is neither precomputable nor multi-target-accelerable, and two identical codes
/// produce distinct stored values.
/// </summary>
internal interface IRecoveryCodeHasher
{
    /// <summary>
    /// Produces the salted, keyed stored form of a recovery code:
    /// <c>hmac:v1:base64(salt):base64(HMAC-SHA256(key, salt || code))</c>.
    /// </summary>
    string Hash(string code);

    /// <summary>
    /// Constant-time verification of <paramref name="code"/> against a value produced by
    /// <see cref="Hash"/>. Also accepts the legacy bare lowercase-hex SHA-256 format so codes
    /// issued before the keyed scheme keep redeeming during the transition.
    /// </summary>
    bool Verify(string code, string storedHash);

    /// <summary>
    /// True when <paramref name="storedHash"/> is a legacy bare SHA-256 hex value rather than
    /// the current keyed format, letting callers rewrite on the next successful use.
    /// </summary>
    bool IsLegacyFormat(string storedHash);
}

/// <summary>
/// HMAC-SHA256 + per-code-salt implementation of <see cref="IRecoveryCodeHasher"/>, keyed with
/// the per-instance MFA encryption key resolved by <see cref="MfaEncryptionKeyProvider"/>.
/// </summary>
internal sealed class RecoveryCodeHasher : IRecoveryCodeHasher
{
    private const string Prefix = "hmac:v1:";
    private const int SaltSize = 16;
    private readonly byte[] _key;

    public RecoveryCodeHasher(byte[] key)
    {
        // Defensive copy so external mutation of the caller's array cannot alter the key.
        _key = (byte[])key.Clone();
    }

    public string Hash(string code)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] mac = ComputeMac(salt, code);
        return $"{Prefix}{Convert.ToBase64String(salt)}:{Convert.ToBase64String(mac)}";
    }

    public bool Verify(string code, string storedHash)
    {
        if (string.IsNullOrEmpty(storedHash))
        {
            return false;
        }

        if (storedHash.StartsWith(Prefix, StringComparison.Ordinal))
        {
            string body = storedHash[Prefix.Length..];
            int sep = body.IndexOf(':', StringComparison.Ordinal);
            if (sep <= 0)
            {
                return false;
            }

            byte[] salt;
            byte[] expectedMac;
            try
            {
                salt = Convert.FromBase64String(body[..sep]);
                expectedMac = Convert.FromBase64String(body[(sep + 1)..]);
            }
            catch (FormatException)
            {
                return false;
            }

            byte[] actualMac = ComputeMac(salt, code);
            return CryptographicOperations.FixedTimeEquals(actualMac, expectedMac);
        }

        // Legacy bare SHA-256 hex, retained so pre-upgrade codes still redeem.
        byte[] legacy = SHA256.HashData(Encoding.UTF8.GetBytes(code));
        string legacyHex = Convert.ToHexString(legacy).ToLowerInvariant();
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(legacyHex),
            Encoding.UTF8.GetBytes(storedHash));
    }

    public bool IsLegacyFormat(string storedHash) =>
        !string.IsNullOrEmpty(storedHash) && !storedHash.StartsWith(Prefix, StringComparison.Ordinal);

    private byte[] ComputeMac(byte[] salt, string code)
    {
        byte[] codeBytes = Encoding.UTF8.GetBytes(code);
        byte[] message = new byte[salt.Length + codeBytes.Length];
        Buffer.BlockCopy(salt, 0, message, 0, salt.Length);
        Buffer.BlockCopy(codeBytes, 0, message, salt.Length, codeBytes.Length);
        return HMACSHA256.HashData(_key, message);
    }
}
