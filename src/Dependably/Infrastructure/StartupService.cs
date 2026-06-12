using System.Reflection;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Dependably.Infrastructure;

/// <summary>
/// Runs mandatory startup work before the server begins accepting requests:
/// 1. Apply database schema (idempotent)
/// 2. First-boot initialization (default org, JWT secret, admin password)
/// 3. Load the JWT signing key from the database into the JWT options
/// </summary>
public sealed class StartupService : IHostedService
{
    private readonly SchemaInitializer _schema;
    private readonly FirstBootService _firstBoot;
    private readonly OrgRepository _orgs;
    private readonly IOptionsMonitor<JwtBearerOptions> _jwtOptions;
    private readonly IConfiguration _config;
    private readonly ILogger<StartupService> _logger;

    public StartupService(
        SchemaInitializer schema,
        FirstBootService firstBoot,
        OrgRepository orgs,
        IOptionsMonitor<JwtBearerOptions> jwtOptions,
        IConfiguration config,
        ILogger<StartupService> logger)
    {
        _schema = schema;
        _firstBoot = firstBoot;
        _orgs = orgs;
        _jwtOptions = jwtOptions;
        _config = config;
        _logger = logger;
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
                "X-Forwarded-Host are accepted from any client. Concrete consequences: " +
                "(1) the /metrics and /version IP allowlist can be bypassed by forging " +
                "X-Forwarded-For; (2) rate-limit buckets are keyed by the spoofable client IP, " +
                "so per-IP limits are ineffective; (3) audit source_ip records the attacker-supplied " +
                "value rather than the real connection address; (4) in DEPLOYMENT_MODE=multi, " +
                "X-Forwarded-Host can spoof tenant resolution. " +
                "Set TRUSTED_PROXIES to your reverse proxy's IP(s)/CIDR(s) to restrict this.");
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

        if (!string.IsNullOrWhiteSpace(_config["Rpm:Upstream"])
            && string.IsNullOrWhiteSpace(_config["Rpm:GpgKey"]))
        {
            _logger.LogWarning(
                "Rpm:GpgKey is not set. The RPM proxy fetches repomd.xml from upstream but does NOT " +
                "verify its detached OpenPGP signature (repomd.xml.asc), so a hostile or MITM upstream " +
                "can serve tampered metadata that poisons the package-checksum chain. Set Rpm:GpgKey to " +
                "your repo's pinned public key to enforce signature verification.");
        }

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
}
