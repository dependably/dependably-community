namespace Dependably.Infrastructure;

/// <summary>
/// Maps inbound <c>Host</c> headers to ecosystem path prefixes for transparent intercept (#43).
/// Configured via <c>HOST_ROUTING</c> as comma-separated <c>host=ecosystem</c> pairs:
/// <code>HOST_ROUTING=registry.npmjs.org=npm,pypi.org=pypi,files.pythonhosted.org=pypi,api.nuget.org=nuget</code>
///
/// Recognised ecosystem values are <c>npm</c>, <c>pypi</c>, <c>nuget</c>; anything else is
/// rejected at parse time. Hosts are compared case-insensitively after stripping the port.
/// </summary>
public sealed class HostEcosystemMap
{
    private static readonly HashSet<string> KnownEcosystems = new(StringComparer.OrdinalIgnoreCase)
    {
        "npm", "pypi", "nuget"
    };

    private readonly Dictionary<string, string> _map;

    public HostEcosystemMap(IConfiguration config)
    {
        var raw = config["HOST_ROUTING"];
        _map = Parse(raw);
    }

    /// <summary>Test seam: build directly from a dictionary.</summary>
    public HostEcosystemMap(IDictionary<string, string> map)
    {
        _map = new Dictionary<string, string>(map, StringComparer.OrdinalIgnoreCase);
    }

    public bool IsEmpty => _map.Count == 0;

    /// <summary>
    /// Returns the ecosystem path prefix (<c>/npm</c>, <c>/pypi</c>, <c>/nuget</c>) for the
    /// given host, or null if the host isn't mapped.
    /// </summary>
    public string? PrefixForHost(string? host)
    {
        if (string.IsNullOrEmpty(host)) return null;
        var lower = host.ToLowerInvariant();
        var colon = lower.IndexOf(':');
        if (colon >= 0) lower = lower[..colon];
        return _map.TryGetValue(lower, out var ecosystem) ? "/" + ecosystem : null;
    }

    private static Dictionary<string, string> Parse(string? raw)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(raw)) return map;

        foreach (var pair in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq <= 0 || eq == pair.Length - 1)
                throw new InvalidOperationException(
                    $"HOST_ROUTING entry '{pair}' is malformed; expected 'host=ecosystem'.");
            var host = pair[..eq].Trim().ToLowerInvariant();
            var ecosystem = pair[(eq + 1)..].Trim();
            if (!KnownEcosystems.Contains(ecosystem))
                throw new InvalidOperationException(
                    $"HOST_ROUTING ecosystem '{ecosystem}' is not recognised; expected one of: {string.Join(", ", KnownEcosystems)}.");
            map[host] = ecosystem.ToLowerInvariant();
        }
        return map;
    }
}
