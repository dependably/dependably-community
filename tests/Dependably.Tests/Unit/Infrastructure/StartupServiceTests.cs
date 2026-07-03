using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Startup-time JWT key handling and envelope-encryption migration. The JwtBearer options ship
/// with an all-zero placeholder signing key; <see cref="StartupService"/> must replace it from
/// instance_settings and must refuse to start (fail closed) when the secret is missing on an
/// already-bootstrapped instance, or when secrets are envelope-encrypted but DEPENDABLY_MASTER_KEY
/// is absent (lost-key scenario).
/// </summary>
[Trait("Category", "Unit")]
public sealed class StartupServiceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly StubJwtOptionsMonitor _jwtOptions = new();

    public Task InitializeAsync() => Task.CompletedTask;

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private static EnvelopeProtector UnconfiguredEnvelope() =>
        new(new EnvFileMasterKeyProvider(new ConfigurationBuilder().Build()));

    private static EnvelopeProtector ConfiguredEnvelope() =>
        new(new EnvFileMasterKeyProvider(
            new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                { ["DEPENDABLY_MASTER_KEY"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) })
                .Build()));

    private StartupService BuildService(IConfiguration? config = null, EnvelopeProtector? envelope = null)
    {
        config ??= new ConfigurationBuilder().Build();
        envelope ??= UnconfiguredEnvelope();
        return new StartupService(
            new SchemaInitializer(_db),
            new FirstBootService(_db, config, NullLogger<FirstBootService>.Instance, envelope),
            new OrgRepository(_db, envelope: envelope),
            _jwtOptions,
            config,
            StagingOptions.Resolve(config),
            NullLogger<StartupService>.Instance,
            envelope,
            _db,
            new EdgeMode(config),
            new InstanceLock(_db, config, TestTime.Frozen(), NullLogger<InstanceLock>.Instance));
    }

    // deepcode ignore NoHardcodedCredentials: `key` is a settings-row name passed as a SQL parameter, not a credential.
    private async Task<string?> ReadRawAsync(string key)
    {
        await using var conn = await _db.OpenAsync();
        // xtenant: instance-global, not tenant-scoped.
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT value FROM instance_settings WHERE key = @key",
            new { key });
    }

    [Fact]
    public async Task StartAsync_FirstBoot_LoadsGeneratedJwtSecretIntoOptions()
    {
        await BuildService().StartAsync(CancellationToken.None);

        var key = _jwtOptions.Get(JwtBearerDefaults.AuthenticationScheme)
            .TokenValidationParameters.IssuerSigningKey;
        var symmetric = Assert.IsType<SymmetricSecurityKey>(key);
        Assert.NotEqual(new byte[32], symmetric.Key);
    }

    [Fact]
    public async Task StartAsync_BootstrappedButJwtSecretMissing_Throws()
    {
        // First boot seeds org + user + jwt_secret …
        await BuildService().StartAsync(CancellationToken.None);

        // … then simulate a partial DB restore: tenant state survives, the
        // instance_settings row carrying the signing secret does not.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("DELETE FROM instance_settings WHERE key = 'jwt_secret'");
        }

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => BuildService().StartAsync(CancellationToken.None));
        Assert.Contains("jwt_secret", ex.Message);
    }

    // ── Envelope migration via real StartAsync ────────────────────────────────

    [Fact]
    public async Task StartAsync_ConfiguredEnvelope_MigratesPlaintextSecretsToEncrypted()
    {
        // Establish a bootstrapped instance (schema + first-boot seeds plaintext jwt_secret +
        // mfa_encryption_key when no KEK is configured). First pass: no KEK.
        await BuildService().StartAsync(CancellationToken.None);

        // Confirm both rows are plaintext after first boot without a KEK.
        string? rawJwtBefore = await ReadRawAsync("jwt_secret");
        Assert.NotNull(rawJwtBefore);
        Assert.False(rawJwtBefore!.StartsWith(EnvelopeProtector.EncryptedPrefix, StringComparison.Ordinal),
            "Precondition: jwt_secret must be plaintext before encryption migration");

        // Now restart with a configured KEK — MigrateSecretsToEnvelopeAsync must encrypt in place.
        using var ep = ConfiguredEnvelope();
        await BuildService(envelope: ep).StartAsync(CancellationToken.None);

        string? rawJwtAfter = await ReadRawAsync("jwt_secret");
        string? rawMfaAfter = await ReadRawAsync("mfa_encryption_key");

        Assert.True(ep.IsEncrypted(rawJwtAfter!),
            $"jwt_secret must be enc:v1:-prefixed after migration, got: {rawJwtAfter}");
        Assert.True(ep.IsEncrypted(rawMfaAfter!),
            $"mfa_encryption_key must be enc:v1:-prefixed after migration, got: {rawMfaAfter}");

        // GetInstanceSettingAsync must round-trip through decryption to the original plaintext.
        var repo = new OrgRepository(_db, envelope: ep);
        string? decryptedJwt = await repo.GetInstanceSettingAsync("jwt_secret");
        Assert.Equal(rawJwtBefore, decryptedJwt);

        // The JWT signing key in options must be the decrypted plaintext bytes, not the ciphertext.
        var signingKey = _jwtOptions.Get(JwtBearerDefaults.AuthenticationScheme)
            .TokenValidationParameters.IssuerSigningKey;
        var symmetric = Assert.IsType<SymmetricSecurityKey>(signingKey);
        Assert.Equal(System.Text.Encoding.UTF8.GetBytes(rawJwtBefore!), symmetric.Key);
    }

    [Fact]
    public async Task StartAsync_UnconfiguredEnvelope_EncryptedSecretPresent_Throws()
    {
        // Simulate a lost-key scenario: secrets were envelope-encrypted by a previous instance
        // start, but DEPENDABLY_MASTER_KEY is now absent.
        await BuildService().StartAsync(CancellationToken.None);

        // Overwrite the plaintext jwt_secret with an encrypted blob using a throwaway KEK.
        using var ep = ConfiguredEnvelope();
        string encrypted = ep.Protect("some-jwt-secret");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE instance_settings SET value = @v WHERE key = 'jwt_secret'",
                new { v = encrypted });
        }

        // Restart without a KEK — must fail closed rather than serve with a ciphertext key.
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => BuildService().StartAsync(CancellationToken.None));
        Assert.Contains("DEPENDABLY_MASTER_KEY", ex.Message);
    }

    [Fact]
    public async Task StartAsync_UnconfiguredEnvelope_PlaintextSecrets_BootsNormally()
    {
        // Normal first boot without a KEK: no migration, no exception, JWT key is loaded.
        await BuildService().StartAsync(CancellationToken.None);

        var signingKey = _jwtOptions.Get(JwtBearerDefaults.AuthenticationScheme)
            .TokenValidationParameters.IssuerSigningKey;
        var symmetric = Assert.IsType<SymmetricSecurityKey>(signingKey);
        Assert.NotEqual(new byte[32], symmetric.Key);
    }

    [Fact]
    public async Task StartAsync_ConfiguredEnvelope_RunTwice_IsIdempotent()
    {
        // First boot without a KEK seeds plaintext secrets; capture the originals.
        await BuildService().StartAsync(CancellationToken.None);
        string? plaintextJwt = await ReadRawAsync("jwt_secret");
        string? plaintextMfa = await ReadRawAsync("mfa_encryption_key");

        // Two consecutive starts with the SAME configured KEK. The second pass must skip the
        // already-prefixed rows rather than wrap them again (no enc:v1:enc:v1: double-encryption).
        using var ep = ConfiguredEnvelope();
        await BuildService(envelope: ep).StartAsync(CancellationToken.None);
        await BuildService(envelope: ep).StartAsync(CancellationToken.None);

        var repo = new OrgRepository(_db, envelope: ep);
        // A double-wrapped value would decrypt to "enc:v1:<inner>", not the original plaintext.
        Assert.Equal(plaintextJwt, await repo.GetInstanceSettingAsync("jwt_secret"));
        Assert.Equal(plaintextMfa, await repo.GetInstanceSettingAsync("mfa_encryption_key"));
    }

    [Fact]
    public async Task StartAsync_ConfiguredEnvelope_MixedState_BothEncryptedAfter()
    {
        // First boot without a KEK leaves both secrets plaintext; capture the originals.
        await BuildService().StartAsync(CancellationToken.None);
        string? plaintextJwt = await ReadRawAsync("jwt_secret");
        string? plaintextMfa = await ReadRawAsync("mfa_encryption_key");

        // Hand-craft a MIXED state: encrypt only jwt_secret, leave mfa_encryption_key plaintext —
        // exercising the migration loop's per-key skip guard on one secret while it encrypts the
        // other in the same pass.
        using var ep = ConfiguredEnvelope();
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE instance_settings SET value = @v WHERE key = 'jwt_secret'",
                new { v = ep.Protect(plaintextJwt!) });
        }

        await BuildService(envelope: ep).StartAsync(CancellationToken.None);

        // Both rows end encrypted, and both decrypt back to their ORIGINAL plaintext — the
        // already-encrypted jwt_secret must not have been wrapped a second time.
        Assert.True(ep.IsEncrypted((await ReadRawAsync("jwt_secret"))!));
        Assert.True(ep.IsEncrypted((await ReadRawAsync("mfa_encryption_key"))!));
        var repo = new OrgRepository(_db, envelope: ep);
        Assert.Equal(plaintextJwt, await repo.GetInstanceSettingAsync("jwt_secret"));
        Assert.Equal(plaintextMfa, await repo.GetInstanceSettingAsync("mfa_encryption_key"));
    }

    // ── Envelope migration for per-org secret-bearing tables (upstream + webhook) ──

    private async Task<string> FirstOrgIdAsync()
    {
        await using var conn = await _db.OpenAsync();
        return (await conn.ExecuteScalarAsync<string?>("SELECT id FROM orgs LIMIT 1"))!;
    }

    private async Task SeedUpstreamSecretAsync(string orgId, string secret)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO upstream_registry (id, org_id, ecosystem, url, auth_type, secret) " +
            "VALUES (@id, @org, 'npm', 'https://private.example/npm', 'bearer', @secret)",
            new { id = Guid.NewGuid().ToString("n"), org = orgId, secret });
    }

    private async Task SeedWebhookSecretAsync(string orgId, string secret)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO webhook_subscription (id, org_id, url, secret) " +
            "VALUES (@id, @org, 'https://hook.example/x', @secret)",
            new { id = Guid.NewGuid().ToString("n"), org = orgId, secret });
    }

    private async Task<string?> ReadColumnAsync(string table, string column, string orgId)
    {
        await using var conn = await _db.OpenAsync();
        // Table/column are test-fixed constants, not user input. Scope to non-null secrets so a
        // first-boot-seeded anonymous upstream row (NULL secret) does not shadow the seeded row.
        return await conn.ExecuteScalarAsync<string?>(
            $"SELECT {column} FROM {table} WHERE org_id = @org AND {column} IS NOT NULL LIMIT 1",
            new { org = orgId });
    }

    [Fact]
    public async Task StartAsync_ConfiguredEnvelope_MigratesPlaintextUpstreamAndWebhookSecrets()
    {
        // First boot without a KEK, then seed pre-retrofit plaintext secrets in the per-org tables.
        await BuildService().StartAsync(CancellationToken.None);
        string orgId = await FirstOrgIdAsync();
        await SeedUpstreamSecretAsync(orgId, "npm-upstream-token");
        await SeedWebhookSecretAsync(orgId, "webhook-hmac-secret");

        // Restart with a configured KEK — the migration must wrap both plaintext rows.
        using var ep = ConfiguredEnvelope();
        await BuildService(envelope: ep).StartAsync(CancellationToken.None);

        string? upstreamAfter = await ReadColumnAsync("upstream_registry", "secret", orgId);
        string? webhookAfter = await ReadColumnAsync("webhook_subscription", "secret", orgId);

        Assert.True(ep.IsEncrypted(upstreamAfter!),
            $"upstream_registry.secret must be enc:v1:-prefixed after migration, got: {upstreamAfter}");
        Assert.True(ep.IsEncrypted(webhookAfter!),
            $"webhook_subscription.secret must be enc:v1:-prefixed after migration, got: {webhookAfter}");
        Assert.DoesNotContain("npm-upstream-token", upstreamAfter!);
        Assert.DoesNotContain("webhook-hmac-secret", webhookAfter!);
    }

    [Fact]
    public async Task StartAsync_ConfiguredEnvelope_UpstreamSecretMigration_IsIdempotent()
    {
        await BuildService().StartAsync(CancellationToken.None);
        string orgId = await FirstOrgIdAsync();
        await SeedUpstreamSecretAsync(orgId, "npm-upstream-token");

        using var ep = ConfiguredEnvelope();
        await BuildService(envelope: ep).StartAsync(CancellationToken.None);
        string? afterFirst = await ReadColumnAsync("upstream_registry", "secret", orgId);

        // Second pass must skip the already-encrypted row (no enc:v1:enc:v1: double-wrap).
        await BuildService(envelope: ep).StartAsync(CancellationToken.None);
        string? afterSecond = await ReadColumnAsync("upstream_registry", "secret", orgId);

        Assert.Equal(afterFirst, afterSecond);
    }

    [Fact]
    public async Task StartAsync_UnconfiguredEnvelope_EncryptedUpstreamSecretPresent_Throws()
    {
        // First boot without a KEK, then simulate an upstream secret that a KEK-configured instance
        // encrypted — but the master key is now absent (lost-key scenario).
        await BuildService().StartAsync(CancellationToken.None);
        string orgId = await FirstOrgIdAsync();
        using var ep = ConfiguredEnvelope();
        await SeedUpstreamSecretAsync(orgId, ep.Protect("npm-upstream-token"));

        // Restart without a KEK — the probe must now cover the upstream table and fail closed.
        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(
            () => BuildService().StartAsync(CancellationToken.None));
        Assert.Contains("DEPENDABLY_MASTER_KEY", thrown.Message);
    }

    [Fact]
    public async Task StartAsync_UnconfiguredEnvelope_EncryptedWebhookSecretPresent_Throws()
    {
        await BuildService().StartAsync(CancellationToken.None);
        string orgId = await FirstOrgIdAsync();
        using var ep = ConfiguredEnvelope();
        await SeedWebhookSecretAsync(orgId, ep.Protect("webhook-hmac-secret"));

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(
            () => BuildService().StartAsync(CancellationToken.None));
        Assert.Contains("DEPENDABLY_MASTER_KEY", thrown.Message);
    }

    private sealed class StubJwtOptionsMonitor : IOptionsMonitor<JwtBearerOptions>
    {
        public JwtBearerOptions CurrentValue { get; } = new()
        {
            TokenValidationParameters = new TokenValidationParameters
            {
                // Same all-zero placeholder Program.cs seeds before startup runs.
                IssuerSigningKey = new SymmetricSecurityKey(new byte[32]),
            },
        };

        public JwtBearerOptions Get(string? name) => CurrentValue;

        public IDisposable? OnChange(Action<JwtBearerOptions, string?> listener) => null;
    }
}
