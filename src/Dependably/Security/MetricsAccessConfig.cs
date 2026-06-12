using System.Text.Json;
using NetTools;

namespace Dependably.Security;

/// <summary>
/// Resolves the effective <c>/metrics</c> access configuration from the
/// env-var → instance_settings → hard-coded-default precedence chain.
/// Wraps the resolution in a 5-second TTL cache so the hot-path
/// <see cref="MetricsAccessMiddleware"/> never hits the DB per scrape.
///
/// <para><b>Env-var precedence is strict.</b> When the env var for a
/// knob is set (any value, including empty string), it wins; the
/// corresponding <c>instance_settings</c> row is neither read nor
/// written for that knob. This is what makes the UI "locked by env"
/// banner accurate: removing the env var later returns precedence to
/// the DB → default chain, with no dormant UI state to surface
/// unexpectedly.</para>
/// </summary>
public sealed class MetricsAccessConfig
{
    private static readonly string[] DefaultAllowlist = { "127.0.0.1", "::1" };

    private readonly Func<string, CancellationToken, Task<string?>> _instanceSettingReader;
    private readonly IConfiguration _config;

    private readonly SemaphoreSlim _lock = new(1, 1);
    private ResolvedConfig? _cached;
    private DateTimeOffset _expiry;

    /// <summary>
    /// Constructs the resolver against an instance-setting reader (the
    /// production wiring passes <c>OrgRepository.GetInstanceSettingAsync</c>;
    /// unit tests pass a stub that avoids needing a real DB).
    /// </summary>
    public MetricsAccessConfig(
        Func<string, CancellationToken, Task<string?>> instanceSettingReader,
        IConfiguration config)
    {
        _instanceSettingReader = instanceSettingReader;
        _config = config;
    }

    public enum Source { Env, Db, Default }

    public sealed record ResolvedConfig(
        bool Enabled,
        IReadOnlyList<IPAddressRange> Allowed,
        IReadOnlyList<string> AllowedRaw,
        Source EnabledSource,
        Source AllowlistSource,
        bool EnabledLockedByEnv,
        bool AllowlistLockedByEnv);

    public async Task<ResolvedConfig> ResolveAsync(CancellationToken ct = default)
    {
        if (_cached is not null && DateTimeOffset.UtcNow < _expiry)
        {
            return _cached;
        }

        await _lock.WaitAsync(ct);
        try
        {
            if (_cached is not null && DateTimeOffset.UtcNow < _expiry)
            {
                return _cached;
            }

            var resolved = await ResolveFromSourcesAsync(ct);
            _cached = resolved;
            _expiry = DateTimeOffset.UtcNow.AddSeconds(5);
            return resolved;
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>
    /// Invalidates the cache so the next <see cref="ResolveAsync"/>
    /// re-reads from sources. Called by <c>SystemController</c> after a
    /// successful settings update so UI edits take effect immediately
    /// instead of waiting for the 5s TTL.
    /// </summary>
    public void Invalidate()
    {
        _cached = null;
    }

    private async Task<ResolvedConfig> ResolveFromSourcesAsync(CancellationToken ct)
    {
        string? envEnabled = _config["METRICS_ENABLED"];
        string? envAllowlist = _config["METRICS_ALLOWED_IPS"];

        bool enabled;
        Source enabledSource;
        if (envEnabled is not null)
        {
            enabled = ParseBool(envEnabled, fallback: true);
            enabledSource = Source.Env;
        }
        else
        {
            string? dbEnabled = await _instanceSettingReader("metrics_enabled", ct);
            if (dbEnabled is not null)
            {
                enabled = ParseBool(dbEnabled, fallback: true);
                enabledSource = Source.Db;
            }
            else
            {
                enabled = true;
                enabledSource = Source.Default;
            }
        }

        IReadOnlyList<string> rawList;
        Source allowlistSource;
        if (envAllowlist is not null)
        {
            rawList = ParseCsv(envAllowlist);
            allowlistSource = Source.Env;
        }
        else
        {
            string? dbAllowlist = await _instanceSettingReader("metrics_allowed_ips", ct);
            if (dbAllowlist is not null && TryParseJsonArray(dbAllowlist, out var parsed))
            {
                rawList = parsed;
                allowlistSource = Source.Db;
            }
            else
            {
                rawList = DefaultAllowlist;
                allowlistSource = Source.Default;
            }
        }

        // Bad entries during resolution shouldn't take the middleware
        // down — drop them silently and rely on the PUT-side validator
        // (which rejects malformed CIDRs before they reach the DB) to
        // keep the source data clean.
        var parsedRanges = new List<IPAddressRange>(rawList.Count);
        foreach (string raw in rawList)
        {
            if (IPAddressRange.TryParse(raw, out var range))
            {
                parsedRanges.Add(range);
            }
        }

        return new ResolvedConfig(
            Enabled: enabled,
            Allowed: parsedRanges,
            AllowedRaw: rawList,
            EnabledSource: enabledSource,
            AllowlistSource: allowlistSource,
            EnabledLockedByEnv: envEnabled is not null,
            AllowlistLockedByEnv: envAllowlist is not null);
    }

    private static bool ParseBool(string raw, bool fallback) => raw switch
    {
        "1" or "true" or "TRUE" or "True" => true,
        "0" or "false" or "FALSE" or "False" => false,
        _ => fallback,
    };

    private static string[] ParseCsv(string csv) =>
        csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static bool TryParseJsonArray(string json, out IReadOnlyList<string> values)
    {
        try
        {
            string[]? arr = JsonSerializer.Deserialize<string[]>(json);
            if (arr is null)
            {
                values = Array.Empty<string>();
                return false;
            }
            values = arr;
            return true;
        }
        catch (JsonException)
        {
            values = Array.Empty<string>();
            return false;
        }
    }
}
