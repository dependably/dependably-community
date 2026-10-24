using System.Security.Cryptography;
using Dependably.Infrastructure.Identity;

namespace Dependably.Tests.Unit.Identity;

/// <summary>
/// Unit tests for AES-GCM encryption in <see cref="MfaSecretProtector"/>. Verifies the
/// encrypt/decrypt round-trip, per-call nonce uniqueness, tamper detection, and key isolation.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MfaSecretProtectorTests
{
    private static MfaSecretProtector NewProtector() =>
        new(RandomNumberGenerator.GetBytes(32));

    // ── round-trip ────────────────────────────────────────────────────────────

    [Fact]
    public void Protect_Unprotect_RoundTrips()
    {
        var protector = NewProtector();
        string plaintext = "JBSWY3DPEHPK3PXP"; // typical TOTP base32 key

        string ciphertext = protector.Protect(plaintext);
        string recovered = protector.Unprotect(ciphertext);

        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void Protect_EmptyString_RoundTrips()
    {
        var protector = NewProtector();
        string ciphertext = protector.Protect(string.Empty);
        Assert.Equal(string.Empty, protector.Unprotect(ciphertext));
    }

    [Fact]
    public void Protect_UnicodeValue_RoundTrips()
    {
        var protector = NewProtector();
        const string value = "cléé-éé";
        Assert.Equal(value, protector.Unprotect(protector.Protect(value)));
    }

    // ── nonce uniqueness ──────────────────────────────────────────────────────

    [Fact]
    public void Protect_CalledTwice_ProducesDistinctCiphertexts()
    {
        var protector = NewProtector();
        string plaintext = "same-secret";

        string a = protector.Protect(plaintext);
        string b = protector.Protect(plaintext);

        Assert.NotEqual(a, b);
    }

    // ── tamper detection ──────────────────────────────────────────────────────

    [Fact]
    public void Unprotect_TamperedByte_ThrowsMfaSecretProtectionException()
    {
        var protector = NewProtector();
        byte[] raw = Convert.FromBase64String(protector.Protect("secret"));

        // Flip the last ciphertext byte.
        raw[^1] ^= 0xFF;

        Assert.Throws<MfaSecretProtectionException>(() =>
            protector.Unprotect(Convert.ToBase64String(raw)));
    }

    [Fact]
    public void Unprotect_TruncatedTag_ThrowsMfaSecretProtectionException()
    {
        var protector = NewProtector();
        byte[] raw = Convert.FromBase64String(protector.Protect("secret"));

        // Truncate to fewer bytes than nonce + tag.
        byte[] truncated = raw[..10];

        Assert.Throws<MfaSecretProtectionException>(() =>
            protector.Unprotect(Convert.ToBase64String(truncated)));
    }

    // ── wrong key ─────────────────────────────────────────────────────────────

    [Fact]
    public void Unprotect_WrongKey_ThrowsMfaSecretProtectionException()
    {
        var protectorA = NewProtector();
        var protectorB = NewProtector();

        string ciphertext = protectorA.Protect("secret");

        Assert.Throws<MfaSecretProtectionException>(() =>
            protectorB.Unprotect(ciphertext));
    }

    // ── malformed input ───────────────────────────────────────────────────────

    [Fact]
    public void Unprotect_NotBase64_ThrowsMfaSecretProtectionException()
    {
        var protector = NewProtector();
        Assert.Throws<MfaSecretProtectionException>(() =>
            protector.Unprotect("not-valid-base64!!!"));
    }

    // ── concurrency ───────────────────────────────────────────────────────────

    /// <summary>
    /// One protector, many threads — the shape production has, since this type backs the
    /// singleton <see cref="EnvelopeProtector"/> that every request and every per-org delivery
    /// worker decrypts through. Each thread decrypts its own org's stored secret and round-trips
    /// fresh values, and every call must return exactly its own plaintext.
    ///
    /// On Linux an unsynchronized shared <see cref="AesGcm"/> fails this on nearly every run
    /// (overlapping calls share one OpenSSL cipher context: authentication failures, wrong
    /// plaintexts, undecryptable ciphertext). It cannot fail on macOS, whose implementation is
    /// stateless per call, so a red run here is a Linux CI signal. Dedicated threads released by
    /// a barrier keep the overlap independent of thread-pool scheduling.
    /// </summary>
    [Fact]
    public void ProtectAndUnprotect_ConcurrentCallersOnOneInstance_EveryCallRoundTrips()
    {
        using var protector = NewProtector();
        const int threadCount = 8;
        const int iterations = 2_000;

        string[] plaintexts = Enumerable.Range(0, threadCount)
            .Select(i => $"https://hooks.slack.com/services/org{i}/secret")
            .ToArray();
        string[] stored = plaintexts.Select(protector.Protect).ToArray();

        var failures = new System.Collections.Concurrent.ConcurrentQueue<string>();
        using var start = new Barrier(threadCount);

        var threads = Enumerable.Range(0, threadCount).Select(t => new Thread(() =>
        {
            start.SignalAndWait();
            for (int i = 0; i < iterations; i++)
            {
                try
                {
                    string decrypted = protector.Unprotect(stored[t]);
                    if (decrypted != plaintexts[t])
                    {
                        failures.Enqueue($"thread {t}: decrypted a wrong plaintext");
                    }

                    string fresh = $"org{t}-value-{i}";
                    if (protector.Unprotect(protector.Protect(fresh)) != fresh)
                    {
                        failures.Enqueue($"thread {t}: round-trip returned a wrong plaintext");
                    }
                }
                catch (Exception ex)
                {
                    // Caught broadly on purpose: an unsynchronized Encrypt throws a raw
                    // CryptographicException, and anything escaping a dedicated thread would
                    // abort the whole test host instead of failing this test.
                    failures.Enqueue($"thread {t}: {ex.GetType().Name}: {ex.Message}");
                }
            }
        })).ToArray();

        foreach (var thread in threads)
        {
            thread.Start();
        }

        foreach (var thread in threads)
        {
            thread.Join();
        }

        Assert.True(failures.IsEmpty,
            $"{failures.Count} concurrent call(s) failed; first: {failures.FirstOrDefault()}");
    }

    // ── constructor guard ─────────────────────────────────────────────────────

    [Theory]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(0)]
    public void Constructor_NonThirtyTwoByteKey_Throws(int keyLen)
    {
        byte[] badKey = new byte[keyLen];
        Assert.Throws<ArgumentException>(() => new MfaSecretProtector(badKey));
    }
}
