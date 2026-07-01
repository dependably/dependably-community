using System.Reflection;
using System.Text;
using Dapper;
using Dependably.Infrastructure.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Dependably.Infrastructure;

/// <summary>
/// Runs mandatory startup work before the server begins accepting requests:
/// 1. Apply database schema (idempotent)
/// 2. First-boot initialization (default org, JWT secret, admin password)
/// 3. Envelope-encrypt instance secrets that are still stored as plaintext (idempotent migration)
/// 4. Load the JWT signing key from the database into the JWT options
/// </summary>
public sealed class StartupService : IHostedService
{
    private readonly SchemaInitializer _schema;
    private readonly FirstBootService _firstBoot;
    private readonly OrgRepository _orgs;
    private readonly IOptionsMonitor<JwtBearerOptions> _jwtOptions;
    private readonly IConfiguration _config;
    private readonly StagingOptions _staging;
    private readonly ILogger<StartupService> _logger;
    private readonly EnvelopeProtector _envelope;
    private readonly IMetadataStore _db;

    public StartupService(
        SchemaInitializer schema,
        FirstBootService firstBoot,
        OrgRepository orgs,
        IOptionsMonitor<JwtBearerOptions> jwtOptions,
        IConfiguration config,
        StagingOptions staging,
        ILogger<StartupService> logger,
        EnvelopeProtector envelope,
        IMetadataStore db)
    {
        _schema = schema;
        _firstBoot = firstBoot;
        _orgs = orgs;
        _jwtOptions = jwtOptions;
        _config = config;
        _staging = staging;
        _logger = logger;
        _envelope = envelope;
        _db = db;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        string version = typeof(StartupService).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? typeof(StartupService).Assembly.GetName().Version?.ToString()
            ?? "unknown";
        string dbPath = _config["DB_PATH"] ?? "/data/dependably.db";
        string storage = _config["STORAGE_BACKEND"] ?? "local";

        _logger.LogInformation(
            "dependably {Version} starting — db={DbPath} storage={Storage}",
            version, dbPath, storage);

        await _schema.InitializeAsync(cancellationToken);
        await _firstBoot.RunAsync(cancellationToken);
        await MigrateSecretsToEnvelopeAsync(cancellationToken);

        LogEnvironmentWarnings();
        string? baseUrl = _config["BASE_URL"];

        string? jwtSecret = await _orgs.GetInstanceSettingAsync("jwt_secret", cancellationToken);
        if (jwtSecret is not null)
        {
            _jwtOptions.Get(JwtBearerDefaults.AuthenticationScheme)
                .TokenValidationParameters.IssuerSigningKey =
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
        }
        else
        {
            // Fail closed. The JwtBearer options are seeded with a placeholder signing key on
            // startup; serving without replacing it would let anyone forge owner or system
            // session tokens offline using those known placeholder bytes. First-boot always
            // writes jwt_secret, so this state only arises from a partial DB restore or a
            // migration fault — an operator problem that must surface loudly, not be masked by
            // silently minting a new secret.
            throw new InvalidOperationException(
                "jwt_secret is missing from instance_settings even though the instance is already "
                + "bootstrapped (users/orgs exist). Refusing to start: serving with the placeholder "
                + "signing key would accept forged session tokens. Restore the instance_settings "
                + "table from backup (the jwt_secret row invalidates all existing sessions if "
                + "regenerated).");
        }

        var (_, tenantCount) = await _orgs.ListOrgsAsync(1, 0, includeDeleted: false, cancellationToken);

        _logger.LogInformation(
            "dependably ready — baseUrl={BaseUrl} tenants={TenantCount}",
            baseUrl ?? "(derived from request)", tenantCount);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>
    /// Idempotent startup migration: when a master key is configured, wraps any plaintext
    /// instance secrets with the envelope so they are encrypted at rest going forward. Secrets
    /// that already carry the <c>enc:v1:</c> prefix are skipped. Runs inside BEGIN IMMEDIATE
    /// so concurrent replica restarts cannot produce partial states.
    ///
    /// When no master key is configured, probes the raw stored values and THROWS if either
    /// secret is already prefixed (lost-key scenario) — the operator must supply the key used
    /// during encryption or restore an unencrypted database before the server can start.
    /// </summary>
    private async Task MigrateSecretsToEnvelopeAsync(CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);

        if (_envelope.IsConfigured)
        {
            await EncryptPlaintextInstanceSecretsAsync(conn);
        }
        else
        {
            await VerifyNoOrphanedEncryptedSecretsAsync(conn);
        }
    }

    // Wraps any plaintext instance secrets with the envelope so they are encrypted at rest going
    // forward. Secrets that already carry the enc:v1: prefix are skipped. Runs inside
    // BEGIN IMMEDIATE so concurrent replica restarts cannot produce partial states.
    private async Task EncryptPlaintextInstanceSecretsAsync(System.Data.Common.DbConnection conn)
    {
        await conn.ExecuteAsync("BEGIN IMMEDIATE");
        try
        {
            foreach (string key in OrgRepository.SecretKeys)
            {
                // xtenant: instance-global secret, not tenant-scoped.
                string? raw = await conn.ExecuteScalarAsync<string?>(
                    "SELECT value FROM instance_settings WHERE key = @key",
                    new { key });

                if (raw is null || _envelope.IsEncrypted(raw))
                {
                    continue;
                }

                string encrypted = _envelope.Protect(raw);
                // xtenant: instance-global secret, not tenant-scoped.
                await conn.ExecuteAsync(
                    "UPDATE instance_settings SET value = @value WHERE key = @key",
                    new { value = encrypted, key });
                _logger.LogInformation(
                    "Envelope-encrypted instance secret {Key} at rest", key);
            }

            await conn.ExecuteAsync("COMMIT");
        }
        catch
        {
            await conn.ExecuteAsync("ROLLBACK");
            throw;
        }
    }

    // Fail closed: if either secret was written by an envelope-configured instance, starting
    // without the master key would yield an unusable JWT signing key.
    private async Task VerifyNoOrphanedEncryptedSecretsAsync(System.Data.Common.DbConnection conn)
    {
        foreach (string key in OrgRepository.SecretKeys)
        {
            // xtenant: instance-global secret, not tenant-scoped.
            string? raw = await conn.ExecuteScalarAsync<string?>(
                "SELECT value FROM instance_settings WHERE key = @key",
                new { key });

            if (raw is not null && _envelope.IsEncrypted(raw))
            {
                throw new InvalidOperationException(
                    $"Instance secrets are envelope-encrypted at rest but DEPENDABLY_MASTER_KEY is not configured. " +
                    $"Set the master key to the value used when they were encrypted, or restore the " +
                    $"unencrypted DB. Refusing to start.");
            }
        }

        _logger.LogWarning(
            "Instance secrets (jwt_secret, mfa_encryption_key) are stored unencrypted. " +
            "Set DEPENDABLY_MASTER_KEY to envelope-encrypt them at rest, or ensure the " +
            "database is on an OS-encrypted volume.");
    }

    // Logs operator-facing warnings for missing or misconfigured environment variables.
    // None of these abort startup — they surface as LogWarning so the operator can act
    // without a restart. Called once per startup after schema init and first-boot.
    private void LogEnvironmentWarnings()
    {
        string? baseUrl = _config["BASE_URL"];
        if (baseUrl is null)
        {
            _logger.LogWarning(
                "BASE_URL is not set. Session cookies will not be marked Secure. " +
                "UseForwardedHeaders is enabled — if a TLS-terminating proxy is in front, " +
                "ensure it forwards X-Forwarded-Proto: https and set BASE_URL to https://...");
        }
        else if (!baseUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning(
                "BASE_URL {BaseUrl} is plain HTTP. Session cookies will not be marked Secure. " +
                "UseForwardedHeaders is enabled — if a TLS-terminating proxy is in front, " +
                "ensure it forwards X-Forwarded-Proto: https and update BASE_URL to https://...",
                baseUrl);
        }

        if (string.IsNullOrWhiteSpace(_config["TRUSTED_PROXIES"]))
        {
            _logger.LogWarning(
                "TRUSTED_PROXIES is not set. X-Forwarded-For, X-Forwarded-Proto, and " +
                "X-Forwarded-Host are ignored (fail-closed). Connection.RemoteIpAddress, " +
                "Request.Host, and Request.Scheme reflect the real socket peer. " +
                "If a TLS-terminating reverse proxy is in front, set TRUSTED_PROXIES to the " +
                "proxy's IP(s)/CIDR(s) so forwarded headers from that proxy are trusted and the " +
                "client-facing scheme and source IP are visible to the application.");
        }

        if (!BaseUrlHostHelper.IsUsableApexHost(_config["BASE_URL"]))
        {
            _logger.LogWarning(
                "BASE_URL is not set or contains a localhost host. Host header " +
                "filtering is permissive (AllowedHosts=*): any Host value is accepted. This " +
                "allows Host header injection into SAML SP entity IDs / ACS URLs, absolute links, " +
                "and CSRF Origin comparisons. In production, set BASE_URL to your public domain " +
                "(e.g. https://repo.example.com) so unknown Host headers are rejected before " +
                "reaching tenant resolution.");
        }

        bool isReplica =
            string.Equals(_config["REPLICA_HINT"], "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(_config["INSTANCE_ROLE"], "replica", StringComparison.OrdinalIgnoreCase);
        if (isReplica)
        {
            _logger.LogWarning(
                "Multi-replica deployment detected (REPLICA_HINT or INSTANCE_ROLE=replica). " +
                "OCI chunked uploads (/v2/*/blobs/uploads/*) append to a local staging file — " +
                "PATCH requests for an active upload session must reach the same replica that " +
                "issued the session UUID. Configure session affinity on your load balancer keyed " +
                "on the upload UUID path segment before routing OCI push traffic.");
        }

        if (_staging.FloorBytes == 0)
        {
            _logger.LogWarning(
                "STAGING_DISK_FLOOR_BYTES is set to 0. Staging-disk-full protection is disabled: " +
                "proxy fetches will no longer be rejected when the staging volume runs low, so a " +
                "full disk can cause partial writes and failed cache stores. This is a deliberate " +
                "operator opt-out. Unset the variable to restore the default 512 MiB floor.");
        }
    }
}
