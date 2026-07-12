using System.Diagnostics;

namespace Dependably.Protocol;

/// <summary>
/// npm packument fetch with an abbreviated-document fallback. npm registries content-negotiate
/// two documents at the same URL: the full packument (default) and the abbreviated
/// install-metadata document (<c>application/vnd.npm.install-v1+json</c>, "corgi") carrying
/// only the per-version fields installs need — dependencies, dist, bin, engines, deprecated.
/// Very large packages (vite, aws-sdk, typescript, …) have full packuments past
/// <see cref="UpstreamClient.MaxMetadataResponseBytes"/>; without the fallback every packument
/// fetch for such a name fails and the caller degrades to local-only metadata that breaks
/// downstream installs (empty dependency lists). The abbreviated document is 10–20× smaller.
///
/// Degradation contract: the abbreviated document has no <c>time</c> map and no per-version
/// <c>license</c>. Every consumer already tolerates their absence (third-party registries omit
/// them from full documents too): the release-age gate fails open, publish timestamps read as
/// unknown, and license extraction yields null. That is strictly better than the alternative —
/// no packument at all.
/// </summary>
public static class NpmPackumentFetcher
{
    /// <summary>The npm abbreviated ("corgi") packument media type.</summary>
    public const string AbbreviatedAccept = "application/vnd.npm.install-v1+json";

    /// <summary>
    /// Fetches the full packument at <paramref name="url"/>; when the full document overflows
    /// the metadata byte cap, retries once with the abbreviated Accept header. Any other
    /// failure (network, 5xx, SSRF/air-gap policy) propagates unchanged — the fallback exists
    /// solely for the oversized-document case, which no retry of the full fetch can ever fix.
    /// </summary>
    public static async Task<UpstreamMetadataResponse> FetchAsync(
        UpstreamClient upstream, string url, string? authorizationHeader, ILogger? logger, CancellationToken ct)
    {
        try
        {
            return await upstream.GetOrFetchMetadataAsync(url, authorizationHeader, ct);
        }
        catch (UpstreamResponseTooLargeException ex)
        {
            logger?.LogWarning(
                "{ExceptionType}: full npm packument for {Url} exceeds the metadata byte cap; retrying with the abbreviated install-v1 document (no time map or per-version license). TraceId {TraceId}",
                ex.GetType().Name, url, Activity.Current?.TraceId.ToString());
            return await upstream.GetOrFetchMetadataAsync(
                url, UpstreamClient.MaxMetadataResponseBytes, authorizationHeader, AbbreviatedAccept, ct);
        }
    }
}
