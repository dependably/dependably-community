using Dependably.Infrastructure;
using Microsoft.Extensions.Logging;

namespace Dependably.Protocol.Hex;

/// <summary>
/// Supplies the Hex public key of an edge node's master upstream — the one Hex upstream whose key
/// cannot come from its <c>upstream_registry</c> row. <c>EdgeUpstreamSeeder</c> writes that row at
/// boot, when the master may be unreachable, and the master's key rotates without the edge being
/// reseeded. A source with no key is skipped outright by <see cref="HexUpstreamPackageFetcher"/>,
/// so on an edge that gap answers 404 for every tarball and docs fetch of a package the node does
/// not already hold.
///
/// The key is read from the master's own <c>public_key</c> resource through
/// <see cref="UpstreamClient.GetOrFetchMetadataAsync(string, string?, CancellationToken)"/> and so
/// inherits that path's TTL cache — on by default in edge mode — rather than adding a second
/// expiry to reason about. A rotation is picked up when the cached entry lapses.
///
/// It applies to the master and to nothing else: only in edge mode, only for a source whose host
/// is <see cref="IEdgeMode.MasterHost"/>, and only when the row carries no key of its own. A
/// configured upstream without a key stays skipped, because there a missing key means "not
/// trusted", while here it means "not yet read from the node's one configured trust root". The
/// fetched PEM is parsed before it is handed on, so an error page or a truncated body fails here
/// with a clear reason instead of surfacing later as an unverifiable index.
/// </summary>
public sealed class HexMasterKeyResolver
{
    private readonly IEdgeMode _edge;
    private readonly UpstreamClient _upstream;
    private readonly ILogger<HexMasterKeyResolver> _logger;

    public HexMasterKeyResolver(IEdgeMode edge, UpstreamClient upstream, ILogger<HexMasterKeyResolver> logger)
    {
        _edge = edge;
        _upstream = upstream;
        _logger = logger;
    }

    /// <summary>
    /// The same sources, with the master's key filled in where this node is an edge and the row
    /// has none. Every other source is returned untouched, and a master whose key cannot be read
    /// is left keyless so the fetcher's skip-an-unkeyed-upstream rule still decides what happens.
    /// </summary>
    public async Task<IReadOnlyList<UpstreamSource>> WithMasterKeyAsync(
        IReadOnlyList<UpstreamSource> sources, CancellationToken ct = default)
    {
        if (!_edge.IsEdge || sources.Count == 0)
        {
            return sources;
        }

        var resolved = new List<UpstreamSource>(sources.Count);
        foreach (var source in sources)
        {
            resolved.Add(source.PublicKeyPem is null && IsMaster(source.Url)
                ? source with { PublicKeyPem = await FetchMasterKeyAsync(source, ct) }
                : source);
        }

        return resolved;
    }

    private bool IsMaster(string url) =>
        _edge.MasterHost.Length > 0
        && Uri.TryCreate(url, UriKind.Absolute, out var uri)
        && string.Equals(uri.Host, _edge.MasterHost, StringComparison.OrdinalIgnoreCase);

    private async Task<string?> FetchMasterKeyAsync(UpstreamSource source, CancellationToken ct)
    {
        string url = $"{source.Url.TrimEnd('/')}/public_key";
        try
        {
            var response = await _upstream.GetOrFetchMetadataAsync(url, source.AuthorizationHeader, ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning(
                    "Master {Url} answered {Status} for its Hex public key; the upstream stays unkeyed.",
                    url, response.StatusCode);
                return null;
            }

            string pem = System.Text.Encoding.UTF8.GetString(response.Body);
            using (HexRegistrySigner.ParsePublicKeyPem(pem))
            {
                return pem;
            }
        }
        catch (Exception ex) when (ex is HexProtocolException or System.Security.Cryptography.CryptographicException
            or FormatException or ArgumentException)
        {
            _logger.LogWarning("Master {Url} served an unusable Hex public key: {ExceptionType}", url, ex.GetType().Name);
            return null;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            _logger.LogWarning("Reading the master's Hex public key from {Url} failed: {ExceptionType}", url, ex.GetType().Name);
            return null;
        }
    }
}
