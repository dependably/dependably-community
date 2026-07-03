using NetTools;

namespace Dependably.Security;

/// <summary>
/// Shared editing helpers for the <c>/metrics</c> access config, used by both the multi-mode
/// system surface (<c>SystemController</c>) and the single-mode instance surface
/// (<c>InstanceController</c>). Centralising the CIDR validation and the env-locked conflict
/// body keeps the two PUT handlers behaviourally identical — a malformed entry is rejected the
/// same way, and a broad <c>/0</c> entry produces the same warning, on either surface.
/// </summary>
public static class MetricsAccessEditing
{
    /// <summary>
    /// Strict CIDR validation. Returns the first malformed entry (so the caller can reject the
    /// whole request and keep junk out of <c>instance_settings</c>), or <c>null</c> when every
    /// entry parses. Appends a warning for each all-addresses entry that would disable the gate.
    /// </summary>
    public static string? FindInvalidEntry(IReadOnlyList<string> allowed, List<string> warnings)
    {
        foreach (string raw in allowed)
        {
            if (!IPAddressRange.TryParse(raw, out _))
            {
                return raw;
            }

            if (raw is "0.0.0.0/0" or "::/0")
            {
                warnings.Add($"Allowlist entry \"{raw}\" matches all addresses — this disables the IP gate entirely.");
            }
        }

        return null;
    }

    /// <summary>
    /// RFC 7807-shaped body returned (with HTTP 409) when an env var locks a knob, so no silent
    /// DB write happens behind an env override.
    /// </summary>
    public static object EnvLockedConflictBody(string field, string envVar) => new
    {
        type = "/problems/env-var-locked",
        title = $"{field} is locked by env var",
        detail = $"{envVar} is set; unset the env var to manage via UI.",
    };
}
