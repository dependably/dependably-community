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
    private readonly IEdgeMode _edge;
    private readonly InstanceLock _instanceLock;

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Dependency-injection constructor: the parameter list is the declared dependency set; grouping it into an aggregate would hide dependencies without adding cohesion.")]
    public StartupService(
        SchemaInitializer schema,
        FirstBootService firstBoot,
        OrgRepository orgs,
        IOptionsMonitor<JwtBearerOptions> jwtOptions,
        IConfiguration config,
        StagingOptions staging,
        ILogger<StartupService> logger,
        EnvelopeProtector envelope,
        IMetadataStore db,
        IEdgeMode edge,
        InstanceLock instanceLock)
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
        _edge = edge;
        _instanceLock = instanceLock;
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

        // Claim the shared-SQLite single-writer lock before doing any further work or accepting
        // traffic. A live foreign holder throws here (fail-fast, message names the peer); a stale
        // holder is taken over. No-op for Postgres and in-memory SQLite (the guard self-skips).
        await _instanceLock.TryAcquireAsync(cancellationToken);

        await _firstBoot.RunAsync(cancellationToken);
        await MigrateSecretsToEnvelopeAsync(cancellationToken);
        await ReseedEdgeUpstreamsAsync(cancellationToken);
        await ReseedEdgeAccessTokenAsync(cancellationToken);

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
    /// that already carry the <c>enc:v1:</c> prefix are skipped. Runs inside a provider-aware
    /// serialized transaction so concurrent replica restarts cannot produce partial states.
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

    // Re-seeds the edge node's single-upstream rows on every boot so a changed EDGE_MASTER_URL or
    // EDGE_MASTER_TOKEN takes effect on restart. First boot creates the org and the initial rows;
    // this rewrites them idempotently to the current master. No-op outside edge mode.
    private async Task ReseedEdgeUpstreamsAsync(CancellationToken ct)
    {
        if (!_edge.IsEdge)
        {
            return;
        }

        var (orgs, _) = await _orgs.ListOrgsAsync(1, 0, includeDeleted: false, ct);
        string? orgId = orgs.FirstOrDefault()?.Id;
        if (orgId is null)
        {
            // First-boot always seeds the edge org; a missing org here means a partial restore.
            _logger.LogWarning(
                "Edge mode is active but no org exists to anchor upstream rows. Upstream re-seed skipped.");
            return;
        }

        await using var conn = await _db.OpenAsync(ct);
        await conn.BeginSerializedAsync(_db.Provider, ct);
        try
        {
            await EdgeUpstreamSeeder.SeedForEdgeAsync(
                conn, orgId, _edge.MasterUrl, _edge.MasterToken, _envelope, ct: ct);
            await conn.ExecuteAsync("COMMIT");
        }
        catch
        {
            await conn.ExecuteAsync("ROLLBACK");
            throw;
        }

        _logger.LogInformation(
            "Edge mode: seeded single-upstream registry rows pointing at master {MasterHost}",
            _edge.MasterHost);
    }

    // Re-seeds the edge node's inbound client-auth state on every boot so a rotated
    // EDGE_ACCESS_TOKEN takes effect on restart (old row deleted, new hash inserted) and the
    // anonymous/tokened mode always matches the current env. No-op outside edge mode. The token
    // value is never logged.
    private async Task ReseedEdgeAccessTokenAsync(CancellationToken ct)
    {
        if (!_edge.IsEdge)
        {
            return;
        }

        var (orgs, _) = await _orgs.ListOrgsAsync(1, 0, includeDeleted: false, ct);
        string? orgId = orgs.FirstOrDefault()?.Id;
        if (orgId is null)
        {
            _logger.LogWarning(
                "Edge mode is active but no org exists to anchor the access token. Inbound-auth re-seed skipped.");
            return;
        }

        string? accessToken = _config["EDGE_ACCESS_TOKEN"];

        await using var conn = await _db.OpenAsync(ct);
        await conn.BeginSerializedAsync(_db.Provider, ct);
        EdgeAccessTokenSeeder.SeedOutcome outcome;
        try
        {
            outcome = await EdgeAccessTokenSeeder.SeedForEdgeAsync(conn, orgId, accessToken, ct: ct);
            await conn.ExecuteAsync("COMMIT");
        }
        catch
        {
            await conn.ExecuteAsync("ROLLBACK");
            throw;
        }

        if (outcome == EdgeAccessTokenSeeder.SeedOutcome.Anonymous)
        {
            _logger.LogWarning(
                "edge node accepting anonymous clients — intended for trusted networks only");
        }
        else
        {
            _logger.LogInformation(
                "Edge mode: seeded inbound reader access token; anonymous pull disabled.");
        }
    }

    // Wraps any plaintext instance secrets with the envelope so they are encrypted at rest going
    // forward. Secrets that already carry the enc:v1: prefix are skipped. Runs inside a
    // provider-aware serialized transaction so concurrent replica restarts cannot produce partial states. Also
    // retrofits the per-org secret-bearing tables (upstream registry auth secrets, webhook HMAC
    // secrets) whose pre-retrofit rows were written in plaintext.
    private async Task EncryptPlaintextInstanceSecretsAsync(System.Data.Common.DbConnection conn)
    {
        await conn.BeginSerializedAsync(_db.Provider);
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

            int upstreamMigrated = await EncryptPlaintextColumnSecretsAsync(
                conn,
                // xtenant: one-shot instance-wide secret migration across every org's upstream rows.
                """
                SELECT id AS Id, secret AS Secret FROM upstream_registry WHERE secret IS NOT NULL
                """,
                // xtenant: keyed by the globally-unique primary key during a one-shot migration.
                """
                UPDATE upstream_registry SET secret = @value WHERE id = @id
                """);

            int webhookMigrated = await EncryptPlaintextColumnSecretsAsync(
                conn,
                // xtenant: one-shot instance-wide secret migration across every org's webhook rows.
                """
                SELECT id AS Id, secret AS Secret FROM webhook_subscription WHERE secret IS NOT NULL
                """,
                // xtenant: keyed by the globally-unique primary key during a one-shot migration.
                """
                UPDATE webhook_subscription SET secret = @value WHERE id = @id
                """);

            if (upstreamMigrated > 0 || webhookMigrated > 0)
            {
                _logger.LogInformation(
                    "Envelope-encrypted plaintext secrets at rest: {Upstream} upstream-registry, {Webhook} webhook",
                    upstreamMigrated, webhookMigrated);
            }

            await conn.ExecuteAsync("COMMIT");
        }
        catch
        {
            await conn.ExecuteAsync("ROLLBACK");
            throw;
        }
    }

    // Encrypts any plaintext (non-enc:v1:) secret values in a per-org secret-bearing column.
    // The select yields (Id, Secret); each plaintext row is re-written to its Protect()ed form
    // keyed by its primary key. Returns the number of rows migrated.
    private async Task<int> EncryptPlaintextColumnSecretsAsync(
        System.Data.Common.DbConnection conn, string selectSql, string updateSql)
    {
        var rows = (await conn.QueryAsync<SecretRow>(selectSql)).ToList();
        int migrated = 0;
        foreach (var row in rows)
        {
            if (string.IsNullOrEmpty(row.Secret) || _envelope.IsEncrypted(row.Secret))
            {
                continue;
            }

            await conn.ExecuteAsync(
                updateSql, new { value = _envelope.Protect(row.Secret), id = row.Id });
            migrated++;
        }

        return migrated;
    }

    // Fail closed: if any secret was written by an envelope-configured instance, starting
    // without the master key would yield an unusable JWT signing key or unusable upstream/webhook
    // credentials. Probing the per-org secret columns keeps the boot-time refusal intact for them
    // too, rather than deferring the failure to a runtime proxy fetch / webhook delivery.
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
                throw OrphanedSecretException();
            }
        }

        // xtenant: instance-wide fail-closed probe across every org's stored upstream/webhook secrets.
        bool anyUpstreamEncrypted = await AnyEncryptedSecretAsync(
            conn,
            // xtenant: instance-wide fail-closed probe, not tenant-scoped.
            """
            SELECT secret FROM upstream_registry WHERE secret IS NOT NULL
            """);
        bool anyWebhookEncrypted = await AnyEncryptedSecretAsync(
            conn,
            // xtenant: instance-wide fail-closed probe, not tenant-scoped.
            """
            SELECT secret FROM webhook_subscription WHERE secret IS NOT NULL
            """);

        if (anyUpstreamEncrypted || anyWebhookEncrypted)
        {
            throw OrphanedSecretException();
        }

        _logger.LogWarning(
            "Instance secrets (jwt_secret, mfa_encryption_key) and any upstream/webhook secrets are " +
            "stored unencrypted. Set DEPENDABLY_MASTER_KEY to envelope-encrypt them at rest, or " +
            "ensure the database is on an OS-encrypted volume.");
    }

    // Returns true when any row returned by the probe carries the enc:v1: envelope prefix.
    private async Task<bool> AnyEncryptedSecretAsync(
        System.Data.Common.DbConnection conn, string probeSql)
    {
        var secrets = await conn.QueryAsync<string?>(probeSql);
        return secrets.Any(s => s is not null && _envelope.IsEncrypted(s));
    }

    private static InvalidOperationException OrphanedSecretException() =>
        new("Secrets are envelope-encrypted at rest but DEPENDABLY_MASTER_KEY is not configured. "
            + "Set the master key to the value used when they were encrypted, or restore the "
            + "unencrypted DB. Refusing to start.");

    private sealed record SecretRow(string Id, string? Secret);

    // Logs operator-facing warnings for missing or misconfigured environment variables.
    // None of these abort startup — they surface as LogWarning so the operator can act
    // without a restart. Called once per startup after schema init and first-boot.
    private void LogEnvironmentWarnings()
    {
        bool requireSecureCookies = string.Equals(_config["REQUIRE_SECURE_COOKIES"], "true", StringComparison.OrdinalIgnoreCase);
        string? baseUrl = _config["BASE_URL"];
        if (baseUrl is null)
        {
            if (requireSecureCookies)
            {
                _logger.LogWarning(
                    "REQUIRE_SECURE_COOKIES is set but BASE_URL is not. Cookies will still be " +
                    "marked Secure on every request (REQUIRE_SECURE_COOKIES wins unconditionally), " +
                    "but browsers refuse Secure cookies over plain HTTP — if this deployment is not " +
                    "actually served over HTTPS, login will silently fail to persist a session. " +
                    "Set BASE_URL to https://... once a TLS-terminating proxy is in front.");
            }
            else
            {
                _logger.LogWarning(
                    "BASE_URL is not set. Session cookies will not be marked Secure — a MITM on " +
                    "plain HTTP can capture the session JWT. UseForwardedHeaders is enabled — if a " +
                    "TLS-terminating proxy is in front, ensure it forwards X-Forwarded-Proto: https " +
                    "and set BASE_URL to https://..., or set REQUIRE_SECURE_COOKIES=true once this " +
                    "deployment is HTTPS-only.");
            }
        }
        else if (!baseUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            if (requireSecureCookies)
            {
                _logger.LogWarning(
                    "REQUIRE_SECURE_COOKIES is set but BASE_URL {BaseUrl} is plain HTTP. Cookies " +
                    "will still be marked Secure on every request, but browsers refuse Secure " +
                    "cookies over plain HTTP — if this deployment is not actually served over " +
                    "HTTPS, login will silently fail to persist a session. Update BASE_URL to " +
                    "https://... once a TLS-terminating proxy is in front.",
                    baseUrl);
            }
            else
            {
                _logger.LogWarning(
                    "BASE_URL {BaseUrl} is plain HTTP. Session cookies will not be marked Secure — " +
                    "a MITM on plain HTTP can capture the session JWT. UseForwardedHeaders is " +
                    "enabled — if a TLS-terminating proxy is in front, ensure it forwards " +
                    "X-Forwarded-Proto: https and update BASE_URL to https://..., or set " +
                    "REQUIRE_SECURE_COOKIES=true once this deployment is HTTPS-only.",
                    baseUrl);
            }
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

        string deploymentMode = (_config["DEPENDABLY_DEPLOYMENT_MODE"] ?? "standalone").ToLowerInvariant();
        string storageBackend = (_config["STORAGE_BACKEND"] ?? "local").ToLowerInvariant();
        if (deploymentMode == "ha" && storageBackend == "local"
            && string.IsNullOrWhiteSpace(_config["STORAGE_BACKEND_REGISTRY"]))
        {
            _logger.LogWarning(
                "DEPENDABLY_DEPLOYMENT_MODE=ha with STORAGE_BACKEND=local: the local blob store is "
                + "node-local, so replicas will not see each other's published artefacts unless the "
                + "path is a shared volume. Use a shared object store (STORAGE_BACKEND=s3 or azure, "
                + "or the per-tier _REGISTRY override) for the durable registry tier in HA.");
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
