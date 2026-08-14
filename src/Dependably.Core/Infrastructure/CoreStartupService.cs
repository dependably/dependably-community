using System.Reflection;
using Dapper;
using Dependably.Infrastructure.Identity;
using Dependably.Security;

namespace Dependably.Infrastructure;

/// <summary>
/// Runs the mandatory Core startup work before the server begins accepting requests — the work a
/// protocol-only (edge) host needs, with no JwtBearer coupling:
/// 1. Apply database schema (idempotent)
/// 2. Claim the shared-SQLite single-writer instance lock (fail-fast on a live peer)
/// 3. First-boot initialization (default org, JWT/MFA secrets; admin bootstrap via the optional
///    <see cref="IAdminBootstrapper"/> — absent on an edge host by construction)
/// 4. Envelope-encrypt instance secrets that are still stored as plaintext (idempotent migration)
/// 5. Re-seed edge upstream + access-token rows on every boot (no-op outside edge mode)
///
/// The JWT signing-key load — priming <c>JwtSigningKeyProvider</c> from <c>jwt_secret</c> and the
/// fail-closed guard when it is missing — is a separate management hosted service registered
/// immediately after this one, so it runs once first-boot has written the secret. Both are
/// <see cref="IHostedService"/>s; hosted services start in registration order.
/// </summary>
public sealed class CoreStartupService : IHostedService
{
    private readonly SchemaInitializer _schema;
    private readonly FirstBootService _firstBoot;
    private readonly OrgRepository _orgs;
    private readonly IConfiguration _config;
    private readonly StagingOptions _staging;
    private readonly ILogger<CoreStartupService> _logger;
    private readonly EnvelopeProtector _envelope;
    private readonly IMetadataStore _db;
    private readonly IEdgeMode _edge;
    private readonly InstanceLock _instanceLock;
    private readonly MetricsAccessConfig _metricsAccess;

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Dependency-injection constructor: the parameter list is the declared dependency set; grouping it into an aggregate would hide dependencies without adding cohesion.")]
    public CoreStartupService(
        SchemaInitializer schema,
        FirstBootService firstBoot,
        OrgRepository orgs,
        IConfiguration config,
        StagingOptions staging,
        ILogger<CoreStartupService> logger,
        EnvelopeProtector envelope,
        IMetadataStore db,
        IEdgeMode edge,
        InstanceLock instanceLock,
        MetricsAccessConfig metricsAccess)
    {
        _schema = schema;
        _firstBoot = firstBoot;
        _orgs = orgs;
        _config = config;
        _staging = staging;
        _logger = logger;
        _envelope = envelope;
        _db = db;
        _edge = edge;
        _instanceLock = instanceLock;
        _metricsAccess = metricsAccess;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        string version = typeof(CoreStartupService).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? typeof(CoreStartupService).Assembly.GetName().Version?.ToString()
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

        await LogEnvironmentWarningsAsync(cancellationToken);

        var (_, tenantCount) = await _orgs.ListOrgsAsync(1, 0, includeDeleted: false, cancellationToken);

        _logger.LogInformation(
            "dependably core ready — baseUrl={BaseUrl} tenants={TenantCount}",
            _config["BASE_URL"] ?? "(derived from request)", tenantCount);
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
        string? orgId = orgs.Count > 0 ? orgs[0].Id : null;
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
        string? orgId = orgs.Count > 0 ? orgs[0].Id : null;
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

                if (raw is null || EnvelopeProtector.IsEncrypted(raw))
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
            if (string.IsNullOrEmpty(row.Secret) || EnvelopeProtector.IsEncrypted(row.Secret))
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

            if (raw is not null && EnvelopeProtector.IsEncrypted(raw))
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

        // The edge host has no login or MFA layer, so it stores neither a JWT signing secret nor
        // an MFA encryption key — enumerating them here would be misleading. The recoverable secret
        // it does hold at rest is the seeded master enrollment token (EDGE_MASTER_TOKEN, in the
        // upstream_registry secret column). Name what each host actually protects. (The inbound
        // EDGE_ACCESS_TOKEN is stored as a one-way SHA-256 hash, so the master key does not apply
        // to it.)
        if (_edge.IsEdge)
        {
            _logger.LogWarning(
                "The edge master enrollment token (EDGE_MASTER_TOKEN), used to authenticate upstream " +
                "fetches from the master, is stored unencrypted in the edge database. Set " +
                "DEPENDABLY_MASTER_KEY to envelope-encrypt it at rest, or ensure the database is on " +
                "an OS-encrypted volume.");
        }
        else
        {
            _logger.LogWarning(
                "Instance secrets (jwt_secret, mfa_encryption_key) and any upstream/webhook secrets are " +
                "stored unencrypted. Set DEPENDABLY_MASTER_KEY to envelope-encrypt them at rest, or " +
                "ensure the database is on an OS-encrypted volume.");
        }
    }

    // Returns true when any row returned by the probe carries the enc:v1: envelope prefix.
    private static async Task<bool> AnyEncryptedSecretAsync(
        System.Data.Common.DbConnection conn, string probeSql)
    {
        var secrets = await conn.QueryAsync<string?>(probeSql);
        return secrets.Any(s => s is not null && EnvelopeProtector.IsEncrypted(s));
    }

    private static InvalidOperationException OrphanedSecretException() =>
        new("Secrets are envelope-encrypted at rest but DEPENDABLY_MASTER_KEY is not configured. "
            + "Set the master key to the value used when they were encrypted, or restore the "
            + "unencrypted DB. Refusing to start.");

    private sealed record SecretRow(string Id, string? Secret);

    // Logs operator-facing warnings for missing or misconfigured environment variables.
    // None of these abort startup — they surface as LogWarning so the operator can act
    // without a restart. Called once per startup after schema init and first-boot.
    private async Task LogEnvironmentWarningsAsync(CancellationToken ct)
    {
        LogBaseUrlCookieWarning();
        await LogTrustedProxiesWarningAsync(ct);
        LogTrustedProxiesBreadthAndResolvedSet();
        LogApexHostWarning();
        LogReplicaAffinityWarning();
        LogHaLocalStorageWarning();
        LogStagingFloorWarning();
        LogLegacySmtpWarning();
    }

    // The SMTP_* environment variables that once configured invite email delivery. Email
    // configuration is DB-backed; nothing reads these, and there is no env-to-DB seed, so an
    // upgraded deployment that still sets them would otherwise lose invite email silently.
    private static readonly string[] LegacySmtpVariables =
    [
        "SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD", "SMTP_FROM", "SMTP_STARTTLS",
    ];

    private void LogLegacySmtpWarning()
    {
        // The edge host carries no management plane: it has neither an invite mailer nor the
        // Settings UI this warning points at, so naming that path there would be impossible advice.
        if (_edge.IsEdge)
        {
            return;
        }

        string[] present = LegacySmtpVariables
            .Where(name => !string.IsNullOrWhiteSpace(_config[name]))
            .ToArray();

        if (present.Length == 0)
        {
            return;
        }

        // Names only — never the values; SMTP_PASSWORD is among them.
        _logger.LogWarning(
            "Legacy SMTP environment variables are set but ignored: {LegacySmtpVariables}. Email " +
            "configuration is database-backed and there is no environment-to-database seed, so " +
            "these values have no effect. Configure the relay at Settings -> Instance settings -> " +
            "Instance email (SMTP); it is the single transport every outgoing message uses, " +
            "including invites, password resets, account-security notices and alert email. Until " +
            "then an invite returns its link in the API response instead of emailing it. Remove " +
            "these variables once the transport is configured.",
            string.Join(", ", present));
    }

    private void LogBaseUrlCookieWarning()
    {
        // The edge host has no session/login layer, so it never issues session cookies. The
        // Host-filtering half of the BASE_URL guidance still applies on edge and is covered by
        // LogApexHostWarning; emitting the cookie warning here would give impossible advice, so
        // it is suppressed in edge mode.
        if (_edge.IsEdge)
        {
            return;
        }

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
    }

    private async Task LogTrustedProxiesWarningAsync(CancellationToken ct)
    {
        bool trustedProxiesUnset = string.IsNullOrWhiteSpace(_config["TRUSTED_PROXIES"]);
        if (!trustedProxiesUnset)
        {
            return;
        }

        _logger.LogWarning(
            "TRUSTED_PROXIES is not set. X-Forwarded-For, X-Forwarded-Proto, and " +
            "X-Forwarded-Host are ignored (fail-closed). Connection.RemoteIpAddress, " +
            "Request.Host, and Request.Scheme reflect the real socket peer. " +
            "If a TLS-terminating reverse proxy is in front, set TRUSTED_PROXIES to the " +
            "proxy's IP(s)/CIDR(s) so forwarded headers from that proxy are trusted and the " +
            "client-facing scheme and source IP are visible to the application.");

        // Header tenancy rides on the same trust boundary: the tenant header decides which org's
        // packages a request is served, including on the unauthenticated protocol surfaces, so it
        // is honoured only from a peer listed in TRUSTED_PROXIES. Unset means no peer qualifies and
        // every request resolves uninitialized — the deployment does not work at all, which is the
        // intended failure mode for a header nobody can authenticate.
        if (IsHeaderTenancyMode(_config["DEPLOYMENT_MODE"]))
        {
            _logger.LogWarning(
                "DEPLOYMENT_MODE=header requires TRUSTED_PROXIES. The tenant header selects the org " +
                "a request is served — including on anonymous protocol routes — so it is accepted " +
                "only from a socket peer listed in TRUSTED_PROXIES; with none listed, every request " +
                "resolves to no tenant and the deployment serves nothing. Set TRUSTED_PROXIES to the " +
                "edge proxy's IP(s)/CIDR(s).");
        }

        // Layered on top of the base warning above: when the metrics/version/management-docs IP
        // allowlist is still the hard-coded loopback default (never overridden via env or DB), an
        // unset TRUSTED_PROXIES has a second, sharper consequence beyond ignored forwarded headers.
        // A reverse proxy co-located on this host or docker network (a sidecar scraper, an nginx
        // container on the same compose network) makes every request it forwards arrive with
        // Connection.RemoteIpAddress == 127.0.0.1 — indistinguishable from a genuine loopback
        // caller. The allowlist then treats every client that proxy forwards as an allowlisted
        // operator: it fails OPEN, not closed.
        var resolved = await _metricsAccess.ResolveAsync(ct);
        if (ShouldWarnCoLocatedProxyDefeatsMetricsAllowlist(trustedProxiesUnset, resolved.AllowlistSource))
        {
            _logger.LogWarning(
                "TRUSTED_PROXIES is unset and the /metrics, /version, and management docs/OpenAPI " +
                "IP allowlist is still the default (127.0.0.1, ::1). A reverse proxy co-located on " +
                "this host or docker network silently defeats that allowlist: every request it " +
                "forwards arrives as Connection.RemoteIpAddress=127.0.0.1, so any client the proxy " +
                "forwards is treated as an allowlisted operator instead of being denied. Set " +
                "TRUSTED_PROXIES to the proxy's IP(s)/CIDR(s) so the allowlist evaluates the real " +
                "client IP instead of the proxy's loopback peer address.");
        }
    }

    // When TRUSTED_PROXIES is set, logs the resolved trusted-network set at Information so the
    // effective configuration is auditable, and warns (never fails closed) on any entry broader
    // than ConfigurationExtensions.IsBroadTrustedProxyNetwork's per-family threshold. ForwardLimit
    // is null (ConfigureDependablyForwardedHeaders walks the X-Forwarded-For chain to the first
    // untrusted hop), so every host inside a broad trusted network is itself a trusted hop and can
    // present its own forged source address as the client IP — minting a fresh rate-limit
    // partition per request and forging audit_log.source_ip. A large proxy subnet can be a
    // legitimate deployment choice, so this stays a warning rather than a startup failure.
    private void LogTrustedProxiesBreadthAndResolvedSet()
    {
        string? raw = _config["TRUSTED_PROXIES"];
        if (string.IsNullOrWhiteSpace(raw))
        {
            return;
        }

        var (networks, proxies) = ConfigurationExtensions.ParseTrustedProxies(raw);

        foreach (var network in networks)
        {
            if (!ConfigurationExtensions.IsBroadTrustedProxyNetwork(network))
            {
                continue;
            }

            int threshold = ConfigurationExtensions.BroadThresholdFor(network);

            if (network.BaseAddress.IsIPv4MappedToIPv6)
            {
                // The entry's literal family is IPv6, but the threshold named here is the IPv4
                // one it was judged against — naming the effective IPv4 range alongside it avoids
                // a nonsensical-looking pairing like "/104 ... /22 for its address family".
                var (_, effectivePrefixLength) = ConfigurationExtensions.NormalizeTrustedProxyNetwork(network);
                _logger.LogWarning(
                    "TRUSTED_PROXIES entry {Entry} is broader than the recommended /{Threshold} " +
                    "for its effective IPv4 range ({EffectiveRange}). Every host inside this " +
                    "network is a trusted forwarding hop — ForwardLimit is null, so the " +
                    "forwarded-header walk trusts each hop in turn — and can present its own " +
                    "forged address as the client-facing source IP, minting a fresh per-IP " +
                    "rate-limit partition per request and forging audit_log.source_ip. This is " +
                    "not rejected: a large proxy subnet can be a legitimate deployment. Narrow " +
                    "the entry to the actual reverse-proxy address(es) if the wider range was " +
                    "not intentional.",
                    network, threshold, $"{network.BaseAddress.MapToIPv4()}/{effectivePrefixLength}");
            }
            else
            {
                _logger.LogWarning(
                    "TRUSTED_PROXIES entry {Entry} is broader than the recommended threshold " +
                    "(/{Threshold} for its address family). Every host inside this network is a " +
                    "trusted forwarding hop — ForwardLimit is null, so the forwarded-header walk " +
                    "trusts each hop in turn — and can present its own forged address as the " +
                    "client-facing source IP, minting a fresh per-IP rate-limit partition per " +
                    "request and forging audit_log.source_ip. This is not rejected: a large proxy " +
                    "subnet can be a legitimate deployment. Narrow the entry to the actual " +
                    "reverse-proxy address(es) if the wider range was not intentional.",
                    network, threshold);
            }
        }

        _logger.LogInformation(
            "TRUSTED_PROXIES resolves to {NetworkCount} trusted network(s) [{Networks}] and " +
            "{ProxyCount} trusted single address(es) [{Proxies}] for forwarded-header processing.",
            networks.Count, string.Join(", ", networks),
            proxies.Count, string.Join(", ", proxies));
    }

    /// <summary>
    /// True exactly when TRUSTED_PROXIES is unset AND the metrics/version/management-docs
    /// allowlist has never been overridden via env var or <c>instance_settings</c> — i.e. it is
    /// still the hard-coded loopback default that a co-located reverse proxy defeats. Exposed
    /// internally so the warning condition is unit-testable without a full DB-backed startup.
    /// </summary>
    internal static bool ShouldWarnCoLocatedProxyDefeatsMetricsAllowlist(
        bool trustedProxiesUnset, MetricsAccessConfig.Source allowlistSource) =>
        trustedProxiesUnset && allowlistSource == MetricsAccessConfig.Source.Default;

    /// <summary>
    /// True when <c>DEPLOYMENT_MODE</c> selects header-based tenancy, whose tenant header is only
    /// honoured from a <c>TRUSTED_PROXIES</c> peer. Exposed internally so the warning condition is
    /// unit-testable without a full DB-backed startup.
    /// </summary>
    internal static bool IsHeaderTenancyMode(string? deploymentMode) =>
        string.Equals(deploymentMode?.Trim(), "header", StringComparison.OrdinalIgnoreCase);

    private void LogApexHostWarning()
    {
        if (!BaseUrlHostHelper.IsUsableApexHost(_config["BASE_URL"]))
        {
            _logger.LogWarning(
                "BASE_URL is not set or contains a localhost host. Host header " +
                "filtering falls back to loopback hostnames only (localhost/127.0.0.1/[::1]); any " +
                "request arriving through a reverse proxy under a real domain is rejected (400) " +
                "until BASE_URL is configured. Set BASE_URL to your public domain " +
                "(e.g. https://repo.example.com) so that domain's Host headers are accepted and " +
                "unknown ones are still rejected before reaching tenant resolution.");
        }
    }

    private void LogReplicaAffinityWarning()
    {
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
    }

    private void LogHaLocalStorageWarning()
    {
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
    }

    private void LogStagingFloorWarning()
    {
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
