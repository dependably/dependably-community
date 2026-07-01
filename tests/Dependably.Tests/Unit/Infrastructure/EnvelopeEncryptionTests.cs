using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Tests for envelope encryption of instance_settings secrets (jwt_secret and
/// mfa_encryption_key). Covers OrgRepository accessor round-trips, MfaEncryptionKeyProvider
/// plaintext and encrypted paths, and born-encrypted first-boot seeding. Startup migration
/// and fail-closed probe tests live in StartupServiceTests, which drives the real StartAsync.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EnvelopeEncryptionTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── helpers ───────────────────────────────────────────────────────────────

    private static byte[] NewKey() => RandomNumberGenerator.GetBytes(32);

    private static EnvelopeProtector ConfiguredEnvelope() =>
        new(new EnvFileMasterKeyProvider(
            new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                { ["DEPENDABLY_MASTER_KEY"] = Convert.ToBase64String(NewKey()) })
                .Build()));

    private static EnvelopeProtector UnconfiguredEnvelope() =>
        new(new EnvFileMasterKeyProvider(new ConfigurationBuilder().Build()));

    private OrgRepository BuildRepo(EnvelopeProtector envelope) =>
        new(_db, envelope: envelope);

    // deepcode ignore NoHardcodedCredentials: `key` is a settings-row name passed as a SQL parameter, not a credential.
    private async Task<string?> ReadRawAsync(string key)
    {
        await using var conn = await _db.OpenAsync();
        // xtenant: instance-global, not tenant-scoped.
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT value FROM instance_settings WHERE key = @key",
            new { key });
    }

    // deepcode ignore NoHardcodedCredentials: `key` is a settings-row name passed as a SQL parameter, not a credential.
    private async Task WriteRawAsync(string key, string value)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO instance_settings (key, value) VALUES (@key, @value) ON CONFLICT(key) DO UPDATE SET value = @value",
            new { key, value });
    }

    // ── OrgRepository round-trip — configured envelope ────────────────────────

    [Fact]
    public async Task SetGet_JwtSecret_WithConfiguredEnvelope_RoundTripsPlaintext()
    {
        using var ep = ConfiguredEnvelope();
        var repo = BuildRepo(ep);
        const string plaintext = "super-secret-jwt-token-value";

        await repo.SetInstanceSettingAsync("jwt_secret", plaintext);
        string? result = await repo.GetInstanceSettingAsync("jwt_secret");

        Assert.Equal(plaintext, result);
    }

    [Fact]
    public async Task SetGet_JwtSecret_WithConfiguredEnvelope_StoresEncryptedInDb()
    {
        using var ep = ConfiguredEnvelope();
        var repo = BuildRepo(ep);

        await repo.SetInstanceSettingAsync("jwt_secret", "my-secret");

        string? raw = await ReadRawAsync("jwt_secret");
        Assert.NotNull(raw);
        Assert.True(raw!.StartsWith(EnvelopeProtector.EncryptedPrefix, StringComparison.Ordinal),
            $"Expected enc:v1: prefix, got: {raw}");
    }

    [Fact]
    public async Task SetGet_NonSecretKey_WithConfiguredEnvelope_StoredAsPlaintext()
    {
        using var ep = ConfiguredEnvelope();
        var repo = BuildRepo(ep);
        const string value = "1073741824";

        await repo.SetInstanceSettingAsync("max_upload_bytes_npm", value);

        string? raw = await ReadRawAsync("max_upload_bytes_npm");
        Assert.Equal(value, raw);

        string? result = await repo.GetInstanceSettingAsync("max_upload_bytes_npm");
        Assert.Equal(value, result);
    }

    // ── OrgRepository round-trip — unconfigured envelope ─────────────────────

    [Fact]
    public async Task SetGet_JwtSecret_UnconfiguredEnvelope_StoredAsPlaintext()
    {
        using var ep = UnconfiguredEnvelope();
        var repo = BuildRepo(ep);

        await repo.SetInstanceSettingAsync("jwt_secret", "plain-secret");

        string? raw = await ReadRawAsync("jwt_secret");
        Assert.Equal("plain-secret", raw);

        string? result = await repo.GetInstanceSettingAsync("jwt_secret");
        Assert.Equal("plain-secret", result);
    }

    // ── OrgRepository — idempotency: already-encrypted value not double-wrapped ─

    [Fact]
    public async Task Set_AlreadyEncryptedValue_NotDoubleEncrypted()
    {
        using var ep = ConfiguredEnvelope();
        var repo = BuildRepo(ep);
        const string plaintext = "original-secret";

        await repo.SetInstanceSettingAsync("jwt_secret", plaintext);
        string? raw1 = await ReadRawAsync("jwt_secret");

        // Simulate a caller that passes the already-stored (encrypted) blob back in.
        // This must NOT double-encrypt it.
        await repo.SetInstanceSettingAsync("jwt_secret", raw1!);
        string? raw2 = await ReadRawAsync("jwt_secret");

        // The stored value must not have grown another enc:v1: prefix.
        Assert.False(raw2!.StartsWith(EnvelopeProtector.EncryptedPrefix + EnvelopeProtector.EncryptedPrefix,
            StringComparison.Ordinal), "Value was double-encrypted");

        // And reading through the accessor must still yield the original plaintext.
        string? recovered = await repo.GetInstanceSettingAsync("jwt_secret");
        Assert.Equal(plaintext, recovered);
    }

    // ── OrgRepository — ListInstanceSettingsAsync excludes both secrets ───────

    [Fact]
    public async Task ListInstanceSettings_ExcludesBothSecretKeys()
    {
        using var ep = ConfiguredEnvelope();
        var repo = BuildRepo(ep);

        await repo.SetInstanceSettingAsync("jwt_secret", "s1");
        await repo.SetInstanceSettingAsync("mfa_encryption_key", "s2");
        await repo.SetInstanceSettingAsync("max_upload_bytes", "1024");

        var dict = await repo.ListInstanceSettingsAsync();

        Assert.False(dict.ContainsKey("jwt_secret"), "jwt_secret must not appear in listing");
        Assert.False(dict.ContainsKey("mfa_encryption_key"), "mfa_encryption_key must not appear in listing");
        Assert.True(dict.ContainsKey("max_upload_bytes"), "non-secret key must appear");
    }

    // ── MfaEncryptionKeyProvider — configured: persists encrypted, returns bytes ─

    [Fact]
    public async Task MfaKeyProvider_ConfiguredEnvelope_PersistsEncryptedKey_ReturnsCorrectBytes()
    {
        using var ep = ConfiguredEnvelope();
        var provider = new MfaEncryptionKeyProvider(_db, NullLogger<MfaEncryptionKeyProvider>.Instance, ep);

        byte[] key = await provider.GetKeyAsync();

        // The stored row must be enc:v1:-prefixed.
        string? raw = await ReadRawAsync("mfa_encryption_key");
        Assert.NotNull(raw);
        Assert.True(raw!.StartsWith(EnvelopeProtector.EncryptedPrefix, StringComparison.Ordinal),
            $"Stored mfa_encryption_key should be encrypted, got: {raw}");

        // The returned key bytes must be 32 bytes (AES-256).
        Assert.Equal(32, key.Length);
    }

    [Fact]
    public async Task MfaKeyProvider_ConfiguredEnvelope_GetKeyAsync_IdempotentAcrossCalls()
    {
        using var ep = ConfiguredEnvelope();
        var provider = new MfaEncryptionKeyProvider(_db, NullLogger<MfaEncryptionKeyProvider>.Instance, ep);

        byte[] key1 = await provider.GetKeyAsync();
        byte[] key2 = await provider.GetKeyAsync();

        Assert.Equal(key1, key2);
    }

    // ── MfaEncryptionKeyProvider — legacy plaintext back-compat ──────────────

    [Fact]
    public async Task MfaKeyProvider_LegacyPlaintextRow_ReturnsCorrectBytesWithoutError()
    {
        // Seed a legacy plaintext base64 key row (pre-encryption migration).
        byte[] legacyKey = NewKey();
        string legacyBase64 = Convert.ToBase64String(legacyKey);
        await WriteRawAsync("mfa_encryption_key", legacyBase64);

        using var ep = ConfiguredEnvelope();
        var provider = new MfaEncryptionKeyProvider(_db, NullLogger<MfaEncryptionKeyProvider>.Instance, ep);

        byte[] result = await provider.GetKeyAsync();

        Assert.Equal(legacyKey, result);
    }

    [Fact]
    public async Task MfaKeyProvider_UnconfiguredEnvelope_LegacyPlaintextRow_ReturnsCorrectBytes()
    {
        byte[] legacyKey = NewKey();
        await WriteRawAsync("mfa_encryption_key", Convert.ToBase64String(legacyKey));

        using var ep = UnconfiguredEnvelope();
        var provider = new MfaEncryptionKeyProvider(_db, NullLogger<MfaEncryptionKeyProvider>.Instance, ep);

        byte[] result = await provider.GetKeyAsync();

        Assert.Equal(legacyKey, result);
    }

    // ── Born-encrypted first boot ─────────────────────────────────────────────

    [Fact]
    public async Task FirstBoot_ConfiguredEnvelope_SecretsStoredEncrypted()
    {
        using var ep = ConfiguredEnvelope();
        var svc = new FirstBootService(
            _db,
            new ConfigurationBuilder().Build(),
            NullLogger<FirstBootService>.Instance,
            ep);

        await svc.RunAsync();

        string? rawJwt = await ReadRawAsync("jwt_secret");
        string? rawMfa = await ReadRawAsync("mfa_encryption_key");

        Assert.NotNull(rawJwt);
        Assert.NotNull(rawMfa);
        Assert.True(ep.IsEncrypted(rawJwt!), "jwt_secret must be encrypted on first boot with configured KEK");
        Assert.True(ep.IsEncrypted(rawMfa!), "mfa_encryption_key must be encrypted on first boot with configured KEK");
    }

    [Fact]
    public async Task FirstBoot_UnconfiguredEnvelope_SecretsStoredPlaintext()
    {
        using var ep = UnconfiguredEnvelope();
        var svc = new FirstBootService(
            _db,
            new ConfigurationBuilder().Build(),
            NullLogger<FirstBootService>.Instance,
            ep);

        await svc.RunAsync();

        string? rawJwt = await ReadRawAsync("jwt_secret");
        string? rawMfa = await ReadRawAsync("mfa_encryption_key");

        Assert.NotNull(rawJwt);
        Assert.NotNull(rawMfa);
        Assert.False(ep.IsEncrypted(rawJwt!), "jwt_secret must be plaintext when no KEK is configured");
        Assert.False(ep.IsEncrypted(rawMfa!), "mfa_encryption_key must be plaintext when no KEK is configured");
    }

}
