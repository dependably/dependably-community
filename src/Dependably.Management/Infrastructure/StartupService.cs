namespace Dependably.Infrastructure;

/// <summary>
/// Management-host startup work that must run after <see cref="CoreStartupService"/> (schema +
/// first-boot): primes <see cref="JwtSigningKeyProvider"/> from <c>instance_settings.jwt_secret</c>
/// so the first authenticated request validates against the real secret without waiting on a
/// refresh. Registered as a hosted service immediately after the Core startup service, so
/// first-boot has always written <c>jwt_secret</c> by the time this runs.
///
/// This is a priming step, not the only load: the JwtBearer scheme resolves its key from the
/// provider on every validation, so a secret rotated later (see the system jwt-secret rotation
/// endpoint) is honoured without a restart.
///
/// Fail-closed: a bootstrapped instance (orgs/users exist) with no <c>jwt_secret</c> row refuses to
/// start rather than serving with no loaded key.
/// </summary>
public sealed class StartupService : IHostedService
{
    private readonly JwtSigningKeyProvider _signingKeys;
    private readonly ILogger<StartupService> _logger;

    public StartupService(
        JwtSigningKeyProvider signingKeys,
        ILogger<StartupService> logger)
    {
        _signingKeys = signingKeys;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (await _signingKeys.TryReloadAsync(cancellationToken))
        {
            _logger.LogInformation("dependably management ready — JWT signing key loaded");
            return;
        }

        // Fail closed. With no key loaded the provider hands the bearer scheme an empty key set
        // and every session token is rejected — correct, but a silent authentication outage.
        // First-boot always writes jwt_secret, so this state only arises from a partial DB restore
        // or a migration fault — an operator problem that must surface loudly, not be masked by
        // silently minting a new secret.
        throw new InvalidOperationException(
            "jwt_secret is missing from instance_settings even though the instance is already "
            + "bootstrapped (users/orgs exist). Refusing to start: with no signing key loaded no "
            + "session can authenticate. Restore the instance_settings table from backup (the "
            + "jwt_secret row invalidates all existing sessions if regenerated).");
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
