using System.Text.Json;
using System.Text.Json.Nodes;
using Dependably.Protocol;
using Dependably.Security;
using Microsoft.Extensions.Logging;

namespace Dependably.Api.NuGetProtocol;

/// <summary>
/// Reads the listing state of every version of one NuGet package from an upstream registration
/// index, for the deprecation refresh.
///
/// One registration index is fetched per package (<c>registration5-gz-semver2</c>, the SemVer 2
/// superset), from the org's configured sources in priority order; the first live 2xx that parses
/// as a JSON object carrying an <c>items</c> page array is the answer. A body the metadata cache
/// served stale (<see cref="UpstreamMetadataResponse.IsStale"/>) is no answer, for the index and
/// for each externalized page. Pages the index externalizes are inlined through
/// <see cref="NuGetRegistrationHelpers.InlineExternalizedPagesAsync"/>, host-pinned to the source
/// that served the index and fetched with that source's credential only. Each leaf's state comes
/// from <see cref="NuGetNupkgProxyHelper.ParseUnlistedDeprecation"/>, the parser the first fetch
/// and the registration-index gate use, so all three read a leaf the same way.
///
/// The result maps a normalized version to its verdict: the "Unlisted upstream" label, or null for
/// a listed version. A version missing from the map has no verdict this pass (its page could not
/// be fetched or lies past the page cap, or the index does not list it) and the caller records nothing for it. A null result
/// means no source answered, so nothing is recorded for any version.
/// </summary>
internal static class NuGetUpstreamListingFetcher
{
    internal static async Task<IReadOnlyDictionary<string, string?>?> FetchAsync(
        UpstreamClient upstream, IReadOnlyList<UpstreamSource> sources, string normalizedId,
        ILogger logger, CancellationToken ct)
    {
        // Path-shaped ids never reach an upstream URL; ids from cache_artifact were validated at
        // fetch time, so this is defence in depth.
        if (normalizedId.Contains('/') || normalizedId.Contains("..", StringComparison.Ordinal))
        {
            return null;
        }

        string id = normalizedId.ToLowerInvariant();
        foreach (var source in sources)
        {
            UpstreamMetadataResponse response;
            try
            {
                response = await upstream.GetOrFetchMetadataAsync(
                    $"{source.Url}/registration5-gz-semver2/{id}/index.json", source.AuthorizationHeader, ct);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                // A transport fault on one source is no answer from it, like a non-2xx status.
                logger.LogWarning(ex, "NuGet registration index fetch failed for {Package}: {ExceptionType}",
                    id, ex.GetType().Name);
                continue;
            }

            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning(
                    "NuGet registration index fetch returned {StatusCode} for {Package}.", response.StatusCode, id);
                continue;
            }

            // A body the metadata cache served past its TTL because the upstream failed is the
            // last index this source gave, which can predate an unlisting, so it is no answer.
            if (response.IsStale)
            {
                logger.LogWarning(
                    "NuGet registration index for {Package} was served stale from the metadata cache because the upstream failed; trying the next source.",
                    id);
                continue;
            }

            string indexJson = await NuGetRegistrationHelpers.InlineExternalizedPagesAsync(
                response.BodyAsString(),
                (pageUrl, pageCt) => FetchPageAsync(upstream, source, pageUrl, logger, pageCt),
                NuGetRegistrationHandler.MaxExternalizedPagesPerIndex,
                ct);

            var listing = ParseListing(indexJson);
            if (listing is not null)
            {
                return listing;
            }

            logger.LogWarning("NuGet registration index for {Package} is not a JSON object with an items array; trying the next source.", id);
        }

        return null;
    }

    // Maps each leaf's normalized catalogEntry.version to its listing verdict. Null when the
    // document is not a JSON object with an items array. A page that is still externalized (not
    // fetched) contributes no leaves. A leaf with no usable version, or whose catalogEntry is not
    // an object, is skipped. When two leaves name the same version and disagree, the unlisted one
    // wins.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1168:Empty arrays and collections should be returned instead of null",
        Justification = "Null means the document is not a registration index, which the caller tells apart from an index "
                        + "with no leaves.")]
    internal static Dictionary<string, string?>? ParseListing(string indexJson)
    {
        JsonObject? root;
        try { root = JsonNode.Parse(indexJson) as JsonObject; }
        catch (JsonException) { return null; }
        if (root is null)
        {
            return null;
        }

        // A 2xx body with no page array (an error document served with 200, say) is not a
        // registration index, so it is no answer and the next source is asked.
        if (root["items"] is not JsonArray pages)
        {
            return null;
        }

        var listing = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        var leaves = pages
            .OfType<JsonObject>()
            .SelectMany(p => (p["items"] as JsonArray)?.OfType<JsonObject>() ?? []);
        foreach (var leaf in leaves)
        {
            if (leaf["catalogEntry"] is not JsonObject catalogEntry
                || NuGetRegistrationHelpers.TryGetString(catalogEntry["version"]) is not { Length: > 0 } version)
            {
                continue;
            }

            string key = NuGetNormalization.NormalizeVersion(version);
            string? verdict = NuGetNupkgProxyHelper.ParseUnlistedDeprecation(leaf);
            if (!listing.TryGetValue(key, out string? existing) || existing is null)
            {
                listing[key] = verdict;
            }
        }

        return listing;
    }

    // One externalized page, or null when it is not on the host of the source that served the
    // index, did not answer a live 2xx (a stale cached page is not one), or the fetch failed; its leaves then carry no verdict this pass. The page @id is upstream-controlled, so the host pin keeps it
    // from aiming a request, and this source's credential, at another host.
    private static async Task<string?> FetchPageAsync(
        UpstreamClient upstream, UpstreamSource source, string pageUrl, ILogger logger, CancellationToken ct)
    {
        if (!UpstreamHostPin.IsSameOrigin(source.Url, pageUrl))
        {
            logger.LogWarning(
                "NuGet registration page {Url} is not on the host of the upstream that served its index; not fetching it.",
                pageUrl);
            return null;
        }

        try
        {
            var response = await upstream.GetOrFetchMetadataAsync(pageUrl, source.AuthorizationHeader, ct);
            if (response is { IsSuccessStatusCode: true, IsStale: false })
            {
                return response.BodyAsString();
            }

            if (response.IsStale)
            {
                logger.LogWarning(
                    "NuGet registration page {Url} was served stale from the metadata cache because the upstream failed; its versions get no verdict.",
                    pageUrl);
            }
            else
            {
                logger.LogWarning("NuGet registration page fetch returned {StatusCode} for {Url}.", response.StatusCode, pageUrl);
            }
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            logger.LogWarning(ex, "NuGet registration page fetch failed for {Url}: {ExceptionType}", pageUrl, ex.GetType().Name);
        }

        return null;
    }
}
