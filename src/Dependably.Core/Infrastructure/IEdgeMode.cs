namespace Dependably.Infrastructure;

/// <summary>
/// Reports whether the deployment runs as a headless cache-only edge node whose sole upstream
/// for every ecosystem is one central "master" dependably instance. When true, first boot seeds
/// one <c>upstream_registry</c> row per ecosystem pointing at <see cref="MasterUrl"/> (authenticated
/// with the edge's reader token) instead of the standard public-registry defaults, and the SSRF
/// guard admits <see cref="MasterHost"/> so an internal/private master over a LAN link is reachable.
///
/// Selected by <c>DEPLOYMENT_MODE=edge</c>. When edge is selected, <c>EDGE_MASTER_URL</c> and
/// <c>EDGE_MASTER_TOKEN</c> are both required — startup fails fast when either is missing. Read
/// once at startup; the setting does not change at runtime.
/// </summary>
public interface IEdgeMode
{
    /// <summary>True when <c>DEPLOYMENT_MODE=edge</c>.</summary>
    bool IsEdge { get; }

    /// <summary>
    /// The master base URL (<c>EDGE_MASTER_URL</c>), trailing slash trimmed. Empty when not edge.
    /// </summary>
    string MasterUrl { get; }

    /// <summary>
    /// The host portion of <see cref="MasterUrl"/>, used by the SSRF allowlist to admit exactly
    /// the master while every other private/internal host stays blocked. Empty when not edge or
    /// when the URL has no parseable host.
    /// </summary>
    string MasterHost { get; }

    /// <summary>
    /// The edge's reader pull token (<c>EDGE_MASTER_TOKEN</c>) presented to the master on every
    /// upstream fetch. Empty when not edge. Held in memory from configuration; the value is
    /// threaded into the seeded upstream auth rows (encrypted at rest) at first boot.
    /// </summary>
    string MasterToken { get; }
}

/// <summary>
/// Reads the edge-mode configuration once at startup. Construction never throws on a missing
/// master URL/token — the fail-fast validation lives in the startup contradiction guard so the
/// error surfaces as a single clear operator message rather than a DI activation failure.
/// </summary>
public sealed class EdgeMode : IEdgeMode
{
    public bool IsEdge { get; }
    public string MasterUrl { get; }
    public string MasterHost { get; }
    public string MasterToken { get; }

    public EdgeMode(IConfiguration config)
    {
        string mode = (config["DEPLOYMENT_MODE"] ?? "single").Trim().ToLowerInvariant();
        IsEdge = mode == "edge";

        string rawUrl = (config["EDGE_MASTER_URL"] ?? "").Trim();
        MasterUrl = IsEdge ? rawUrl.TrimEnd('/') : "";
        MasterToken = IsEdge ? (config["EDGE_MASTER_TOKEN"] ?? "").Trim() : "";
        MasterHost = IsEdge && Uri.TryCreate(MasterUrl, UriKind.Absolute, out var uri) ? uri.Host : "";
    }
}
