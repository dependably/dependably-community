namespace Dependably.Infrastructure;

/// <summary>
/// Maps inbound <c>Host</c> headers to ecosystem path prefixes for transparent intercept (#43).
/// Configured via <c>HOST_ROUTING</c> as comma-separated <c>host=ecosystem</c> pairs:
/// <code>HOST_ROUTING=registry.npmjs.org=npm,pypi.org=pypi,files.pythonhosted.org=pypi,api.nuget.org=nuget,repo.maven.apache.org=maven,registry-1.docker.io=oci</code>
///
/// Recognised ecosystem values are <c>npm</c>, <c>pypi</c>, <c>nuget</c>, <c>maven</c>, <c>rpm</c>,
/// and <c>oci</c>; anything else is rejected at parse time. Hosts are compared
/// case-insensitively after stripping the port.
/// </summary>
public sealed class HostEcosystemMap
{
    private static readonly HashSet<string> KnownEcosystems = new(StringComparer.OrdinalIgnoreCase)
    {
        "npm", "pypi", "nuget", "maven", "rpm", "oci"
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
    /// Returns the ecosystem path prefix (<c>/npm</c>, <c>/pypi</c>, <c>/nuget</c>,
    /// <c>/maven</c>, <c>/rpm</c>, <c>/v2</c>) for the given host, or null if the host isn't
    /// mapped. OCI's protocol route is <c>/v2/</c> per the OCI Distribution Spec — the
    /// ecosystem key is still <c>oci</c> internally, only the on-wire prefix differs.
    /// </summary>
    public string? PrefixForHost(string? host)
    {
        if (string.IsNullOrEmpty(host)) return null;
        var lower = host.ToLowerInvariant();
        var colon = lower.IndexOf(':');
        if (colon >= 0) lower = lower[..colon];
        if (!_map.TryGetValue(lower, out var ecosystem)) return null;
        return ecosystem == "oci" ? "/v2" : "/" + ecosystem;
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
