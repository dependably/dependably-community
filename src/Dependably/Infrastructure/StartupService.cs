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
        var version = typeof(StartupService).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? typeof(StartupService).Assembly.GetName().Version?.ToString()
            ?? "unknown";
        var dbPath = _config["DB_PATH"] ?? "/data/dependably.db";
        var storage = _config["STORAGE_BACKEND"] ?? "local";

        _logger.LogInformation(
            "dependably {Version} starting — db={DbPath} storage={Storage}",
            version, dbPath, storage);

        await _schema.InitializeAsync(cancellationToken);
        await _firstBoot.RunAsync(cancellationToken);

        var baseUrl = _config["BASE_URL"];
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
                "TRUSTED_PROXIES is not set. Forwarded headers (X-Forwarded-For / -Proto) are " +
                "accepted from any client, so a directly-reachable instance can spoof its source " +
                "IP (affecting the /metrics allowlist, rate-limit keys, and audit source_ip). " +
                "Set TRUSTED_PROXIES to your reverse proxy's IP(s)/CIDR(s) to restrict this.");
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

        var jwtSecret = await _orgs.GetInstanceSettingAsync("jwt_secret", cancellationToken);
        if (jwtSecret is not null)
        {
            _jwtOptions.Get(JwtBearerDefaults.AuthenticationScheme)
                .TokenValidationParameters.IssuerSigningKey =
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
        }
        else
        {
            _logger.LogWarning("JWT secret not found in instance settings after first-boot.");
        }

        var (_, tenantCount) = await _orgs.ListOrgsAsync(1, 0, includeDeleted: false, cancellationToken);

        _logger.LogInformation(
            "dependably ready — baseUrl={BaseUrl} tenants={TenantCount}",
            baseUrl ?? "(derived from request)", tenantCount);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
