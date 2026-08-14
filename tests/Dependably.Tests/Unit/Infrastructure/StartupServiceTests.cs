using System.Security.Cryptography;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Mail;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Startup-time JWT key handling and envelope-encryption migration. The startup work is split
/// across two hosted services registered in order: <see cref="CoreStartupService"/> runs schema +
/// first-boot + envelope-encryption migration, then <see cref="StartupService"/> primes
/// <see cref="JwtSigningKeyProvider"/> from instance_settings. Both must fail closed — the JWT
/// service when the secret is missing on an already-bootstrapped instance, the Core service when
/// secrets are envelope-encrypted but DEPENDABLY_MASTER_KEY is absent (lost-key scenario). The
/// <see cref="StartupPair"/> helper starts both in registration order so these tests exercise the
/// composed behaviour exactly as the host does.
/// </summary>
[Trait("Category", "Unit")]
public sealed class StartupServiceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    // The provider built by the most recent BuildService call — the one whose StartAsync last ran,
    // and therefore the one holding the key the assertions are about.
    private JwtSigningKeyProvider _signingKeys = null!;

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

    private StartupPair BuildService(
        IConfiguration? config = null,
        EnvelopeProtector? envelope = null,
        ILogger<CoreStartupService>? logger = null)
    {
        config ??= new ConfigurationBuilder().Build();
        envelope ??= UnconfiguredEnvelope();
        var orgs = new OrgRepository(_db, envelope: envelope);
        var metricsAccess = new MetricsAccessConfig(orgs.GetInstanceSettingAsync, config, TestTime.Frozen());
        var core = new CoreStartupService(
            new SchemaInitializer(_db),
            new FirstBootService(_db, config, NullLogger<FirstBootService>.Instance, envelope,
                new AdminBootstrapper()),
            orgs,
            config,
            StagingOptions.Resolve(config),
            logger ?? NullLogger<CoreStartupService>.Instance,
            envelope,
            _db,
            new EdgeMode(config),
            new InstanceLock(_db, config, TestTime.Frozen(), NullLogger<InstanceLock>.Instance),
            metricsAccess);
        _signingKeys = new JwtSigningKeyProvider(
            orgs, TestTime.Frozen(), config, NullLogger<JwtSigningKeyProvider>.Instance);
        var jwt = new StartupService(_signingKeys, NullLogger<StartupService>.Instance);
        return new StartupPair(core, jwt);
    }

    // The single signing key the provider currently trusts. Asserting Single() also pins the
    // no-grace-window rule: the provider never trusts a superseded secret alongside the current one.
    private byte[] LoadedSigningKeyBytes() =>
        Assert.IsType<SymmetricSecurityKey>(Assert.Single(_signingKeys.CurrentKeys)).Key;

    // Runs the two startup hosted services in the same order the host registers them:
    // CoreStartupService (schema + first-boot + envelope migration) then StartupService (JWT key
    // load). Lets the existing single-call test bodies drive the composed startup path unchanged.
    private sealed class StartupPair
    {
        private readonly CoreStartupService _core;
        private readonly StartupService _jwt;

        public StartupPair(CoreStartupService core, StartupService jwt)
        {
            _core = core;
            _jwt = jwt;
        }

        public async Task StartAsync(CancellationToken ct)
        {
            await _core.StartAsync(ct);
            await _jwt.StartAsync(ct);
        }
    }

    // `key` is a settings-row name passed as a SQL parameter, not a credential.
    private async Task<string?> ReadRawAsync(string key)
    {
        await using var conn = await _db.OpenAsync();
        // xtenant: instance-global, not tenant-scoped.
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT value FROM instance_settings WHERE key = @key",
            new { key });
    }

    [Fact]
    public async Task StartAsync_FirstBoot_LoadsGeneratedJwtSecretIntoProvider()
    {
        await BuildService().StartAsync(CancellationToken.None);

        Assert.NotEqual(new byte[32], LoadedSigningKeyBytes());
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

        Assert.True(EnvelopeProtector.IsEncrypted(rawJwtAfter!),
            $"jwt_secret must be enc:v1:-prefixed after migration, got: {rawJwtAfter}");
        Assert.True(EnvelopeProtector.IsEncrypted(rawMfaAfter!),
            $"mfa_encryption_key must be enc:v1:-prefixed after migration, got: {rawMfaAfter}");

        // GetInstanceSettingAsync must round-trip through decryption to the original plaintext.
        var repo = new OrgRepository(_db, envelope: ep);
        string? decryptedJwt = await repo.GetInstanceSettingAsync("jwt_secret");
        Assert.Equal(rawJwtBefore, decryptedJwt);

        // The loaded signing key must be the decrypted plaintext bytes, not the ciphertext.
        Assert.Equal(System.Text.Encoding.UTF8.GetBytes(rawJwtBefore!), LoadedSigningKeyBytes());
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

        Assert.NotEqual(new byte[32], LoadedSigningKeyBytes());
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
        Assert.True(EnvelopeProtector.IsEncrypted((await ReadRawAsync("jwt_secret"))!));
        Assert.True(EnvelopeProtector.IsEncrypted((await ReadRawAsync("mfa_encryption_key"))!));
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

        Assert.True(EnvelopeProtector.IsEncrypted(upstreamAfter!),
            $"upstream_registry.secret must be enc:v1:-prefixed after migration, got: {upstreamAfter}");
        Assert.True(EnvelopeProtector.IsEncrypted(webhookAfter!),
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

    // ── TRUSTED_PROXIES unset + default metrics allowlist: co-located-proxy warning ────────
    //
    // When TRUSTED_PROXIES is unset, X-Forwarded-For is discarded (fail-closed) and
    // Connection.RemoteIpAddress reflects the raw socket peer. If the /metrics, /version, and
    // management docs/OpenAPI IP allowlist is still the loopback default, a reverse proxy
    // co-located on the same host/docker network makes every request it forwards arrive as
    // 127.0.0.1 — the allowlist then fails OPEN instead of closed. The condition is deliberately
    // narrow: it fires only when BOTH TRUSTED_PROXIES is unset AND the allowlist was never
    // overridden via env or instance_settings.

    private const string CoLocatedProxyWarningMarker = "silently defeats that allowlist";

    // Minimal logger that captures messages at or above a configurable floor, mirroring the
    // AirGapModeTests capture pattern. Defaults to Warning (and above); pass LogLevel.Information
    // to also capture the resolved-set audit log.
    private sealed class CapturingLogger(List<string> sink, LogLevel minLevel = LogLevel.Warning) : ILogger<CoreStartupService>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel level) => level >= minLevel;
        public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? ex, Func<TState, Exception?, string> formatter)
        {
            if (level >= minLevel)
            {
                sink.Add(formatter(state, ex));
            }
        }
    }

    private async Task<List<string>> StartAndCaptureWarningsAsync(IConfiguration config)
    {
        var warnings = new List<string>();
        var pair = BuildService(config: config, logger: new CapturingLogger(warnings));
        await pair.StartAsync(CancellationToken.None);
        return warnings;
    }

    private async Task<List<string>> StartAndCaptureLogsAsync(IConfiguration config, LogLevel minLevel)
    {
        var logs = new List<string>();
        var pair = BuildService(config: config, logger: new CapturingLogger(logs, minLevel));
        await pair.StartAsync(CancellationToken.None);
        return logs;
    }

    [Fact]
    public async Task StartAsync_TrustedProxiesUnset_AllowlistDefault_WarnsAboutCoLocatedProxy()
    {
        var config = new ConfigurationBuilder().Build();

        var warnings = await StartAndCaptureWarningsAsync(config);

        Assert.Contains(warnings, w => w.Contains(CoLocatedProxyWarningMarker, StringComparison.Ordinal));
    }

    [Fact]
    public async Task StartAsync_TrustedProxiesSet_AllowlistDefault_NoCoLocatedProxyWarning()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["TRUSTED_PROXIES"] = "10.0.0.5" })
            .Build();

        var warnings = await StartAndCaptureWarningsAsync(config);

        Assert.DoesNotContain(warnings, w => w.Contains(CoLocatedProxyWarningMarker, StringComparison.Ordinal));
    }

    [Fact]
    public async Task StartAsync_TrustedProxiesUnset_AllowlistCustomizedViaEnv_NoCoLocatedProxyWarning()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["METRICS_ALLOWED_IPS"] = "10.0.0.0/8" })
            .Build();

        var warnings = await StartAndCaptureWarningsAsync(config);

        Assert.DoesNotContain(warnings, w => w.Contains(CoLocatedProxyWarningMarker, StringComparison.Ordinal));
    }

    // ── Header tenancy needs TRUSTED_PROXIES ────────────────────────────────
    //
    // DEPLOYMENT_MODE=header resolves the tenant from a header the edge proxy injects, and that
    // header is only honoured from a peer in TRUSTED_PROXIES. Unset means no peer qualifies, so
    // the mode serves nothing at all — a startup warning is the difference between diagnosing
    // that in a minute and diagnosing it in an afternoon.

    private const string HeaderTenancyWarningMarker = "DEPLOYMENT_MODE=header requires TRUSTED_PROXIES";

    [Fact]
    public async Task StartAsync_HeaderModeWithoutTrustedProxies_WarnsThatTheHeaderIsNotHonoured()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["DEPLOYMENT_MODE"] = "header" })
            .Build();

        var warnings = await StartAndCaptureWarningsAsync(config);

        Assert.Contains(warnings, w => w.Contains(HeaderTenancyWarningMarker, StringComparison.Ordinal));
    }

    [Fact]
    public async Task StartAsync_HeaderModeWithTrustedProxies_NoHeaderTenancyWarning()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["DEPLOYMENT_MODE"] = "header",
                ["TRUSTED_PROXIES"] = "10.0.0.5"
            })
            .Build();

        var warnings = await StartAndCaptureWarningsAsync(config);

        Assert.DoesNotContain(warnings, w => w.Contains(HeaderTenancyWarningMarker, StringComparison.Ordinal));
    }

    [Fact]
    public async Task StartAsync_NonHeaderModeWithoutTrustedProxies_NoHeaderTenancyWarning()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["DEPLOYMENT_MODE"] = "multi" })
            .Build();

        var warnings = await StartAndCaptureWarningsAsync(config);

        Assert.DoesNotContain(warnings, w => w.Contains(HeaderTenancyWarningMarker, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("header", true)]
    [InlineData(" Header ", true)]
    [InlineData("multi", false)]
    [InlineData("single", false)]
    [InlineData(null, false)]
    public void IsHeaderTenancyMode_MatchesExpected(string? deploymentMode, bool expected)
    {
        Assert.Equal(expected, CoreStartupService.IsHeaderTenancyMode(deploymentMode));
    }

    [Theory]
    [InlineData(true, MetricsAccessConfig.Source.Default, true)]
    [InlineData(false, MetricsAccessConfig.Source.Default, false)]
    [InlineData(true, MetricsAccessConfig.Source.Env, false)]
    [InlineData(true, MetricsAccessConfig.Source.Db, false)]
    [InlineData(false, MetricsAccessConfig.Source.Env, false)]
    [InlineData(false, MetricsAccessConfig.Source.Db, false)]
    public void ShouldWarnCoLocatedProxyDefeatsMetricsAllowlist_MatchesExpected(
        bool trustedProxiesUnset, MetricsAccessConfig.Source allowlistSource, bool expected)
    {
        Assert.Equal(
            expected,
            CoreStartupService.ShouldWarnCoLocatedProxyDefeatsMetricsAllowlist(trustedProxiesUnset, allowlistSource));
    }

    // ── TRUSTED_PROXIES breadth warning: a broad but non-zero CIDR (e.g. a whole VPC range) ──
    //
    // makes every host inside it a trusted forwarding hop (ForwardLimit=null walks the chain to
    // the first untrusted hop), so an in-VPC client can present its own forged address as the
    // client-facing source IP. The warning fires per-family (IPv4 broader than /22, IPv6 broader
    // than /64) and never fails startup — a large proxy subnet can be a legitimate deployment.

    private const string BreadthWarningMarker = "is broader than the recommended";

    [Fact]
    public async Task StartAsync_BroadIpv4Cidr_Warns()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["TRUSTED_PROXIES"] = "10.0.0.0/16" })
            .Build();

        var warnings = await StartAndCaptureWarningsAsync(config);

        Assert.Contains(warnings, w => w.Contains(BreadthWarningMarker, StringComparison.Ordinal)
            && w.Contains("10.0.0.0/16", StringComparison.Ordinal));
    }

    [Fact]
    public async Task StartAsync_NarrowIpv4Cidr_DoesNotWarn()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["TRUSTED_PROXIES"] = "10.0.0.0/24" })
            .Build();

        var warnings = await StartAndCaptureWarningsAsync(config);

        Assert.DoesNotContain(warnings, w => w.Contains(BreadthWarningMarker, StringComparison.Ordinal));
    }

    [Fact]
    public async Task StartAsync_BroadIpv6Prefix_Warns()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["TRUSTED_PROXIES"] = "2001:db8::/56" })
            .Build();

        var warnings = await StartAndCaptureWarningsAsync(config);

        Assert.Contains(warnings, w => w.Contains(BreadthWarningMarker, StringComparison.Ordinal)
            && w.Contains("2001:db8::/56", StringComparison.Ordinal));
    }

    [Fact]
    public async Task StartAsync_NarrowIpv6Prefix_DoesNotWarn()
    {
        // A single routed /64 subnet is the conventional narrowest IPv6 allocation — not broader
        // than the threshold, so it should not warn.
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["TRUSTED_PROXIES"] = "2001:db8::/64" })
            .Build();

        var warnings = await StartAndCaptureWarningsAsync(config);

        Assert.DoesNotContain(warnings, w => w.Contains(BreadthWarningMarker, StringComparison.Ordinal));
    }

    [Fact]
    public async Task StartAsync_BroadIpv4MappedCidr_WarnsWithEffectiveIpv4Range()
    {
        // The entry's literal family is IPv6, but the /22 threshold named in the warning is the
        // IPv4 one it was actually judged against — the message must name the effective IPv4
        // range (10.0.0.0/8) rather than pairing the mapped entry's own /104 against /22, which
        // would read as a non sequitur.
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["TRUSTED_PROXIES"] = "::ffff:10.0.0.0/104" })
            .Build();

        var warnings = await StartAndCaptureWarningsAsync(config);

        Assert.Contains(warnings, w => w.Contains(BreadthWarningMarker, StringComparison.Ordinal)
            && w.Contains("effective IPv4 range (10.0.0.0/8)", StringComparison.Ordinal));
    }

    [Fact]
    public async Task StartAsync_MixedNarrowAndBroadEntries_WarnsOnlyForTheBroadOne()
    {
        // The production shape TRUSTED_PROXIES normally takes: a single proxy address, a narrow
        // subnet, and (the mistake this feature exists to catch) a broad range further along in
        // the list. Every entry must be inspected — a loop that only checks the first network
        // entry would silently miss the broad one here, since the narrow network sorts first.
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            { ["TRUSTED_PROXIES"] = "10.0.0.1,10.0.0.0/24,10.16.0.0/12" })
            .Build();

        var warnings = await StartAndCaptureWarningsAsync(config);

        var breadthWarnings = warnings
            .Where(w => w.Contains(BreadthWarningMarker, StringComparison.Ordinal))
            .ToList();

        Assert.Single(breadthWarnings);
        Assert.Contains("10.16.0.0/12", breadthWarnings[0], StringComparison.Ordinal);
        Assert.DoesNotContain(breadthWarnings, w => w.Contains("10.0.0.0/24", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("0.0.0.0/0")]
    [InlineData("::/0")]
    public async Task StartAsync_CatchAllRange_StillRejectedAtStartup(string value)
    {
        // The breadth warning is a distinct, lesser posture from the /0 catch-all case: /0 must
        // still fail startup outright rather than merely warn, exercised here through the real
        // hosted-service StartAsync path (not just ParseTrustedProxies directly), since the
        // breadth-warning code re-parses TRUSTED_PROXIES during startup.
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["TRUSTED_PROXIES"] = value })
            .Build();

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => BuildService(config: config).StartAsync(CancellationToken.None));
        Assert.Contains("TRUSTED_PROXIES", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task StartAsync_TrustedProxiesSet_LogsResolvedNetworkSetAtInformation()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            { ["TRUSTED_PROXIES"] = "10.0.0.0/24,172.18.0.1" })
            .Build();

        var logs = await StartAndCaptureLogsAsync(config, LogLevel.Information);

        Assert.Contains(logs, l => l.Contains("TRUSTED_PROXIES resolves to", StringComparison.Ordinal)
            && l.Contains("10.0.0.0/24", StringComparison.Ordinal)
            && l.Contains("172.18.0.1", StringComparison.Ordinal));
    }

    [Fact]
    public async Task StartAsync_TrustedProxiesUnset_NoResolvedSetLog()
    {
        var config = new ConfigurationBuilder().Build();

        var logs = await StartAndCaptureLogsAsync(config, LogLevel.Information);

        Assert.DoesNotContain(logs, l => l.Contains("TRUSTED_PROXIES resolves to", StringComparison.Ordinal));
    }
}
