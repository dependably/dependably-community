using System.Security.Cryptography;
using Dependably.Infrastructure.Identity;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Identity;

/// <summary>
/// Unit tests for <see cref="EnvFileMasterKeyProvider"/> and <see cref="EnvelopeProtector"/>.
/// Covers inline key loading, file-based key loading, blank/absent/invalid configurations,
/// round-trip encryption, legacy-plaintext pass-through, tamper detection, and unconfigured
/// provider behaviour.
/// </summary>
[Trait("Category", "Unit")]
public sealed class MasterKeyProviderTests : IDisposable
{
    private readonly List<string> _tempFiles = [];

    // ── helpers ───────────────────────────────────────────────────────────────

    private static byte[] NewKey() => RandomNumberGenerator.GetBytes(32);

    private static IConfiguration ConfigWith(string key, string value) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { [key] = value })
            .Build();

    private static IConfiguration EmptyConfig() =>
        new ConfigurationBuilder().AddInMemoryCollection([]).Build();

    private static EnvFileMasterKeyProvider ProviderFromInlineKey(byte[] key) =>
        new(ConfigWith("DEPENDABLY_MASTER_KEY", Convert.ToBase64String(key)));

    private string WriteTempFile(string contents)
    {
        string path = Path.GetTempFileName();
        _tempFiles.Add(path);
        File.WriteAllText(path, contents);
        return path;
    }

    public void Dispose()
    {
        foreach (string path in _tempFiles)
        {
            try { File.Delete(path); } catch { /* best-effort */ }
        }
    }

    // ── EnvFileMasterKeyProvider — inline base64 ──────────────────────────────

    [Fact]
    public void InlineBase64Key_IsConfigured_True()
    {
        byte[] key = NewKey();
        var provider = ProviderFromInlineKey(key);
        Assert.True(provider.IsConfigured);
    }

    [Fact]
    public void InlineBase64Key_GetMasterKey_ReturnsOriginalBytes()
    {
        byte[] key = NewKey();
        var provider = ProviderFromInlineKey(key);
        Assert.Equal(key, provider.GetMasterKey());
    }

    [Fact]
    public void InlineBase64Key_ProviderName_IsEnvFile()
    {
        var provider = ProviderFromInlineKey(NewKey());
        Assert.Equal("env-file", provider.ProviderName);
    }

    // ── EnvFileMasterKeyProvider — file path ──────────────────────────────────

    [Fact]
    public void FilePathKey_IsConfigured_True()
    {
        byte[] key = NewKey();
        string path = WriteTempFile(Convert.ToBase64String(key));

        var provider = new EnvFileMasterKeyProvider(
            ConfigWith("DEPENDABLY_MASTER_KEY", path));

        Assert.True(provider.IsConfigured);
    }

    [Fact]
    public void FilePathKey_GetMasterKey_ReturnsCorrectBytes()
    {
        byte[] key = NewKey();
        string path = WriteTempFile(Convert.ToBase64String(key) + "\n"); // trailing newline trimmed

        var provider = new EnvFileMasterKeyProvider(
            ConfigWith("DEPENDABLY_MASTER_KEY", path));

        Assert.Equal(key, provider.GetMasterKey());
    }

    // ── EnvFileMasterKeyProvider — blank / absent ─────────────────────────────

    [Fact]
    public void BlankKey_IsConfigured_False()
    {
        var provider = new EnvFileMasterKeyProvider(
            ConfigWith("DEPENDABLY_MASTER_KEY", "   "));
        Assert.False(provider.IsConfigured);
    }

    [Fact]
    public void AbsentKey_IsConfigured_False()
    {
        var provider = new EnvFileMasterKeyProvider(EmptyConfig());
        Assert.False(provider.IsConfigured);
    }

    [Fact]
    public void Unconfigured_GetMasterKey_Throws()
    {
        var provider = new EnvFileMasterKeyProvider(EmptyConfig());
        Assert.Throws<InvalidOperationException>(() => provider.GetMasterKey());
    }

    // ── EnvFileMasterKeyProvider — invalid values ─────────────────────────────

    [Fact]
    public void NotBase64_Constructor_Throws()
    {
        Assert.Throws<InvalidOperationException>(() =>
            new EnvFileMasterKeyProvider(
                ConfigWith("DEPENDABLY_MASTER_KEY", "not-valid-base64!!!")));
    }

    [Fact]
    public void WrongLength16Bytes_Constructor_Throws()
    {
        string b64 = Convert.ToBase64String(new byte[16]);
        Assert.Throws<InvalidOperationException>(() =>
            new EnvFileMasterKeyProvider(
                ConfigWith("DEPENDABLY_MASTER_KEY", b64)));
    }

    [Fact]
    public void NonexistentFilePath_Constructor_Throws()
    {
        string fakePath = Path.Combine(Path.GetTempPath(), "does-not-exist-" + Guid.NewGuid() + ".key");
        Assert.Throws<InvalidOperationException>(() =>
            new EnvFileMasterKeyProvider(
                ConfigWith("DEPENDABLY_MASTER_KEY", fakePath)));
    }

    // ── EnvelopeProtector — round-trip ────────────────────────────────────────

    [Fact]
    public void Protect_Unprotect_RoundTrip()
    {
        using var ep = new EnvelopeProtector(ProviderFromInlineKey(NewKey()));
        const string original = "super-secret-api-token";

        string protected_ = ep.Protect(original);
        string recovered = ep.Unprotect(protected_);

        Assert.Equal(original, recovered);
    }

    [Fact]
    public void Protect_Output_StartsWithPrefix()
    {
        using var ep = new EnvelopeProtector(ProviderFromInlineKey(NewKey()));
        string result = ep.Protect("value");
        Assert.StartsWith("enc:v1:", result, StringComparison.Ordinal);
    }

    [Fact]
    public void IsEncrypted_Protected_ReturnsTrue()
    {
        using var ep = new EnvelopeProtector(ProviderFromInlineKey(NewKey()));
        string protected_ = ep.Protect("value");
        Assert.True(ep.IsEncrypted(protected_));
    }

    [Fact]
    public void IsEncrypted_PlaintextValue_ReturnsFalse()
    {
        using var ep = new EnvelopeProtector(ProviderFromInlineKey(NewKey()));
        Assert.False(ep.IsEncrypted("plaintext-legacy-value"));
    }

    [Fact]
    public void IsConfigured_WithKey_ReturnsTrue()
    {
        using var ep = new EnvelopeProtector(ProviderFromInlineKey(NewKey()));
        Assert.True(ep.IsConfigured);
    }

    // ── EnvelopeProtector — legacy plaintext pass-through ─────────────────────

    [Fact]
    public void Unprotect_NonPrefixedValue_ReturnsUnchanged()
    {
        using var ep = new EnvelopeProtector(ProviderFromInlineKey(NewKey()));
        const string legacy = "my-old-plaintext-token";
        Assert.Equal(legacy, ep.Unprotect(legacy));
    }

    // ── EnvelopeProtector — tamper detection ──────────────────────────────────

    [Fact]
    public void Unprotect_TamperedBody_Throws()
    {
        using var ep = new EnvelopeProtector(ProviderFromInlineKey(NewKey()));
        string protected_ = ep.Protect("secret");

        // Flip a byte inside the encrypted envelope (nonce||tag||ciphertext) so the
        // value stays well-formed base64 and decryption actually runs — the GCM
        // authentication tag, not a base64 decode failure, is what must reject it.
        string body = protected_[EnvelopeProtector.EncryptedPrefix.Length..];
        byte[] raw = Convert.FromBase64String(body);
        raw[^1] ^= 0xFF;
        string tampered = EnvelopeProtector.EncryptedPrefix + Convert.ToBase64String(raw);

        Assert.Throws<MfaSecretProtectionException>(() => ep.Unprotect(tampered));
    }

    // ── EnvelopeProtector — unconfigured provider ─────────────────────────────

    [Fact]
    public void Unconfigured_IsConfigured_False()
    {
        using var ep = new EnvelopeProtector(new EnvFileMasterKeyProvider(EmptyConfig()));
        Assert.False(ep.IsConfigured);
    }

    [Fact]
    public void Unconfigured_Protect_Throws()
    {
        using var ep = new EnvelopeProtector(new EnvFileMasterKeyProvider(EmptyConfig()));
        Assert.Throws<InvalidOperationException>(() => ep.Protect("value"));
    }

    [Fact]
    public void Unconfigured_Unprotect_PrefixedValue_Throws()
    {
        using var ep = new EnvelopeProtector(new EnvFileMasterKeyProvider(EmptyConfig()));
        const string fakeEncrypted = "enc:v1:AAAAAAAAAAAAAAAA";
        Assert.Throws<InvalidOperationException>(() => ep.Unprotect(fakeEncrypted));
    }

    [Fact]
    public void Unconfigured_Unprotect_PlaintextValue_PassesThrough()
    {
        using var ep = new EnvelopeProtector(new EnvFileMasterKeyProvider(EmptyConfig()));
        const string legacy = "plaintext-pass-through";
        Assert.Equal(legacy, ep.Unprotect(legacy));
    }

    // ── EnvelopeProtector — mixed partial-failure scenario ────────────────────

    [Fact]
    public void MixedValues_OnlyPrefixedOnesDecrypted_LegacyPassThrough()
    {
        using var ep = new EnvelopeProtector(ProviderFromInlineKey(NewKey()));
        const string secret = "new-encrypted-value";
        const string legacy = "old-plaintext-value";

        string protected_ = ep.Protect(secret);

        // Batch of two: one encrypted, one legacy plaintext.
        string recoveredSecret = ep.Unprotect(protected_);
        string recoveredLegacy = ep.Unprotect(legacy);

        Assert.Equal(secret, recoveredSecret);
        Assert.Equal(legacy, recoveredLegacy);
    }
}
