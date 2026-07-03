using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Dependably.Infrastructure;

/// <summary>
/// Management-host startup work that must run after <see cref="CoreStartupService"/> (schema +
/// first-boot): loads the JWT signing key from <c>instance_settings.jwt_secret</c> into the
/// JwtBearer options so cookie sessions validate against the real secret rather than the placeholder
/// key. Registered as a hosted service immediately after the Core startup service, so first-boot has
/// always written <c>jwt_secret</c> by the time this runs.
///
/// Fail-closed: a bootstrapped instance (orgs/users exist) with no <c>jwt_secret</c> row refuses to
/// start — serving with the placeholder key would accept forged session tokens.
/// </summary>
public sealed class StartupService : IHostedService
{
    private readonly OrgRepository _orgs;
    private readonly IOptionsMonitor<JwtBearerOptions> _jwtOptions;
    private readonly ILogger<StartupService> _logger;

    public StartupService(
        OrgRepository orgs,
        IOptionsMonitor<JwtBearerOptions> jwtOptions,
        ILogger<StartupService> logger)
    {
        _orgs = orgs;
        _jwtOptions = jwtOptions;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        string? jwtSecret = await _orgs.GetInstanceSettingAsync("jwt_secret", cancellationToken);
        if (jwtSecret is not null)
        {
            _jwtOptions.Get(JwtBearerDefaults.AuthenticationScheme)
                .TokenValidationParameters.IssuerSigningKey =
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
            _logger.LogInformation("dependably management ready — JWT signing key loaded");
            return;
        }

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

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
