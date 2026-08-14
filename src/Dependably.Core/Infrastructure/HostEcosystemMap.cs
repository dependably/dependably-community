namespace Dependably.Infrastructure;

/// <summary>
/// Maps inbound <c>Host</c> headers (and, for PyPI, the request path) to ecosystem path
/// prefixes for transparent intercept. Configured via <c>HOST_ROUTING</c> as comma-separated
/// <c>host=ecosystem</c> pairs:
/// <code>HOST_ROUTING=registry.npmjs.org=npm,pypi.org=pypi,files.pythonhosted.org=pypi,api.nuget.org=nuget,repo.maven.apache.org=maven,registry-1.docker.io=oci</code>
///
/// Recognised ecosystem values are <c>npm</c>, <c>pypi</c>, <c>nuget</c>, <c>maven</c>, <c>rpm</c>,
/// and <c>oci</c>; anything else is rejected at parse time. Hosts are compared
/// case-insensitively after stripping the port. Mapping <c>files.pythonhosted.org</c> only
/// widens the host allowlist for the flat, root-relative <c>/packages/{file}</c> links
/// Dependably itself renders into its PEP 503 index — it does not make the CDN-shaped,
/// multi-segment lockfile URLs pip-tools/poetry pin (<c>/packages/&lt;2&gt;/&lt;2&gt;/&lt;sha256&gt;/{file}</c>)
/// resolve; those still 404.
///
/// <c>pypi</c> is the one ecosystem whose prefix depends on the request path, not just the
/// host: PyPI's protocol surface is split across PEP 503's unprefixed <c>/simple/</c> and the
/// download host's unprefixed <c>/packages/</c> — those already are the served routes, so a
/// request under either is left alone — while the legacy JSON API and twine upload genuinely
/// live under <c>/pypi</c> (e.g. <c>upload.pypi.org</c>'s stock endpoint is bare-host
/// <c>/legacy/</c>, which needs the segment prepended to reach <c>POST /pypi/legacy/</c>).
/// Every other ecosystem's protocol surface lives entirely under its own prefix, so the
/// bare-host request genuinely needs it prepended regardless of path.
/// </summary>
public sealed class HostEcosystemMap
{
    private static readonly HashSet<string> KnownEcosystems = new(StringComparer.OrdinalIgnoreCase)
    {
        "npm", "pypi", "nuget", "maven", "rpm", "oci"
    };

    // Path segments PyPI already serves unprefixed (or that already carry the /pypi segment);
    // a request under one of these needs no rewrite. Anything else routed to the pypi
    // ecosystem (the legacy upload endpoint chief among them) needs /pypi prepended.
    private static readonly string[] PyPiUnprefixedSegments = ["/simple", "/packages", "/pypi"];

    private readonly Dictionary<string, string> _map;

    public HostEcosystemMap(IConfiguration config)
    {
        string? raw = config["HOST_ROUTING"];
        _map = Parse(raw);
    }

    /// <summary>Test seam: build directly from a dictionary.</summary>
    public HostEcosystemMap(IDictionary<string, string> map)
    {
        _map = new Dictionary<string, string>(map, StringComparer.OrdinalIgnoreCase);
    }

    public bool IsEmpty => _map.Count == 0;

    /// <summary>
    /// Returns the ecosystem path prefix (<c>/npm</c>, <c>/nuget</c>, <c>/maven</c>,
    /// <c>/rpm</c>, <c>/v2</c>, or — path-dependent — <c>/pypi</c> / empty) for the given host
    /// and request path, or null if the host isn't mapped. OCI's protocol route is <c>/v2/</c>
    /// per the OCI Distribution Spec — the ecosystem key is still <c>oci</c> internally, only
    /// the on-wire prefix differs. Every ecosystem but <c>pypi</c> ignores <paramref name="path"/>
    /// entirely. <c>pypi</c> resolves to an empty prefix when the path already starts with the
    /// <c>/simple</c>, <c>/packages</c>, or <c>/pypi</c> segment — those already match the
    /// served routes unprefixed (or already carry the segment) — and to <c>/pypi</c> otherwise,
    /// so a bare-host request to e.g. <c>/legacy/</c> (twine's upload path) is prepended to
    /// reach the route that actually exists.
    /// </summary>
    public string? PrefixForHost(string? host, string path)
    {
        if (string.IsNullOrEmpty(host))
        {
            return null;
        }

        string lower = host.ToLowerInvariant();
        int colon = lower.IndexOf(':');
        if (colon >= 0)
        {
            lower = lower[..colon];
        }

        return !_map.TryGetValue(lower, out string? ecosystem)
            ? null
            : ecosystem switch
            {
                "oci" => "/v2",
                "pypi" => PyPiPrefixFor(path),
                _ => "/" + ecosystem,
            };
    }

    private static string PyPiPrefixFor(string path)
    {
        return PyPiUnprefixedSegments.Any(segment => MatchesSegment(path, segment))
            ? string.Empty
            : "/pypi";
    }

    /// <summary>Segment-boundary match: "/simplefoo" must not be treated as under "/simple".</summary>
    private static bool MatchesSegment(string path, string segment)
    {
        return path.StartsWith(segment, StringComparison.Ordinal)
            && (path.Length == segment.Length || path[segment.Length] == '/');
    }

    private static Dictionary<string, string> Parse(string? raw)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return map;
        }

        foreach (string pair in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int eq = pair.IndexOf('=');
            if (eq <= 0 || eq == pair.Length - 1)
            {
                throw new InvalidOperationException(
                    $"HOST_ROUTING entry '{pair}' is malformed; expected 'host=ecosystem'.");
            }

            string host = pair[..eq].Trim().ToLowerInvariant();
            string ecosystem = pair[(eq + 1)..].Trim();
            if (!KnownEcosystems.Contains(ecosystem))
            {
                throw new InvalidOperationException(
                    $"HOST_ROUTING ecosystem '{ecosystem}' is not recognised; expected one of: {string.Join(", ", KnownEcosystems)}.");
            }

            map[host] = ecosystem.ToLowerInvariant();
        }
        return map;
    }
}
