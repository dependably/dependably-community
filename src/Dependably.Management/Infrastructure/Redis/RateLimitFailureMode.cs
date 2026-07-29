using Microsoft.Extensions.Configuration;

namespace Dependably.Infrastructure.Redis;

/// <summary>
/// Operator switch for what the Redis-backed abuse-prevention limiters (login, invite,
/// token-create) do when Redis cannot be reached and no counter is available to decide with.
///
/// <c>open</c> (the default) grants the request: a Redis outage does not lock every operator out
/// of the product, at the cost of running with no login rate limiting for the duration. Every
/// such grant is logged at Warning and counted on
/// <c>dependably.rate_limit.backend_unavailable</c>, so the exposure window is visible and
/// alertable rather than silent.
///
/// <c>closed</c> denies the request with a 429 instead, keeping the abuse budget enforced through
/// the outage at the cost of blocking legitimate logins. Deployments that treat credential
/// stuffing as the higher risk than a login outage set this.
///
/// The value is validated when the management composition root wires these policies: an
/// unrecognized spelling throws rather than silently resolving to the permissive default, so a
/// typo in <c>closed</c> can never read as configured fail-closed while behaving fail-open. The
/// edge root registers only in-process limiters and never reads this setting, so it neither
/// validates nor honours it.
/// </summary>
public static class RateLimitFailureMode
{
    /// <summary>Configuration key carrying the posture.</summary>
    public const string ConfigKey = "RATE_LIMIT_REDIS_FAILURE_MODE";

    /// <summary>Grant the request when the backend is unreachable. The default.</summary>
    public const string Open = "open";

    /// <summary>Deny the request when the backend is unreachable.</summary>
    public const string Closed = "closed";

    /// <summary>
    /// Resolves the configured posture. Unset, empty, or <c>open</c> resolves to fail-open;
    /// <c>closed</c> resolves to fail-closed. Any other value is rejected by
    /// <see cref="Validate"/> at startup and never reaches here.
    /// </summary>
    public static bool ResolveFailOpen(IConfiguration cfg) =>
        !string.Equals(Normalize(cfg[ConfigKey]), Closed, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Throws when the configured value is set to something other than <c>open</c> or
    /// <c>closed</c>. Called during startup wiring so a misspelled posture fails the boot
    /// instead of quietly falling back to the permissive default.
    /// </summary>
    public static void Validate(IConfiguration cfg)
    {
        string? raw = Normalize(cfg[ConfigKey]);
        if (raw is null
            || string.Equals(raw, Open, StringComparison.OrdinalIgnoreCase)
            || string.Equals(raw, Closed, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        throw new InvalidOperationException(
            $"{ConfigKey}='{cfg[ConfigKey]}' is not a recognized rate-limit failure posture. "
            + $"Use '{Open}' (grant requests when Redis is unreachable — the default) or "
            + $"'{Closed}' (deny them). See CONTRIBUTING.md -> Rate limiting.");
    }

    private static string? Normalize(string? value)
    {
        string? trimmed = value?.Trim();
        return string.IsNullOrEmpty(trimmed) ? null : trimmed;
    }
}
