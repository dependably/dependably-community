using System.Security.Cryptography;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// RFC-6238 TOTP computation for integration tests. Produces the same code that
/// <c>AuthenticatorTokenProvider</c> would accept for a given base32-encoded key.
/// </summary>
public static class TotpTestHelper
{
    /// <summary>
    /// Computes the current 6-digit TOTP code for the given base32-encoded key.
    ///
    /// Identity's authenticator validator uses REAL UtcNow, NOT the DI TimeProvider,
    /// so FakeTimeProvider will not make TOTP deterministic. We read the clock once from
    /// <c>TimeProvider.System</c> and accept within the ±1 step that Identity allows.
    /// </summary>
    public static string Compute(string base32Key)
    {
        byte[] keyBytes = Base32Decode(base32Key);
        // now-ok: Identity's TOTP validator uses real UtcNow, not the injected TimeProvider.
        long unixSeconds = (long)TimeProvider.System.GetUtcNow().ToUnixTimeSeconds();
        long counter = unixSeconds / 30;
        return ComputeForCounter(keyBytes, counter);
    }

    /// <summary>
    /// Returns an array of codes for the current and adjacent time steps (n-1, n, n+1).
    /// Using step n is sufficient in most cases; steps n-1 and n+1 guard against a clock
    /// rollover occurring between the server and test client.
    /// </summary>
    public static string[] ComputeWindow(string base32Key)
    {
        byte[] keyBytes = Base32Decode(base32Key);
        // now-ok: Identity's TOTP validator uses real UtcNow, not the injected TimeProvider.
        long unixSeconds = (long)TimeProvider.System.GetUtcNow().ToUnixTimeSeconds();
        long counter = unixSeconds / 30;
        return
        [
            ComputeForCounter(keyBytes, counter - 1),
            ComputeForCounter(keyBytes, counter),
            ComputeForCounter(keyBytes, counter + 1),
        ];
    }

    private static string ComputeForCounter(byte[] key, long counter)
    {
        // RFC 4226: 8-byte big-endian counter.
        byte[] counterBytes = new byte[8];
        for (int i = 7; i >= 0; i--)
        {
            counterBytes[i] = (byte)(counter & 0xFF);
            counter >>= 8;
        }

        using var hmac = new HMACSHA1(key);
        byte[] hash = hmac.ComputeHash(counterBytes);

        // Dynamic truncation: low nibble of last byte selects the 4-byte window.
        int offset = hash[^1] & 0x0F;
        int code = ((hash[offset] & 0x7F) << 24)
                 | ((hash[offset + 1] & 0xFF) << 16)
                 | ((hash[offset + 2] & 0xFF) << 8)
                 | (hash[offset + 3] & 0xFF);

        return (code % 1_000_000).ToString("D6", System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Decodes a base32 string (RFC 4648, A-Z and 2-7 alphabet, no padding required).
    /// </summary>
    private static byte[] Base32Decode(string input)
    {
        // Strip padding and uppercase.
        string cleaned = input.TrimEnd('=').ToUpperInvariant();
        int bitCount = cleaned.Length * 5;
        byte[] output = new byte[bitCount / 8];

        int buffer = 0;
        int bitsLeft = 0;
        int outputIndex = 0;

        foreach (char c in cleaned)
        {
            int value = c switch
            {
                >= 'A' and <= 'Z' => c - 'A',
                >= '2' and <= '7' => c - '2' + 26,
                _ => throw new ArgumentException($"Invalid base32 character: {c}", nameof(input))
            };

            buffer = (buffer << 5) | value;
            bitsLeft += 5;

            if (bitsLeft >= 8)
            {
                output[outputIndex++] = (byte)(buffer >> (bitsLeft - 8));
                bitsLeft -= 8;
            }
        }

        return output;
    }
}
