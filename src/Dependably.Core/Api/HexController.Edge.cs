using System.Security.Cryptography;
using Dependably.Protocol;
using Dependably.Protocol.Hex;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// The edge half of the Hex read plane. An edge node signs nothing: a Hex client checks a
/// resource's signature against the key it registered and the payload's embedded repository
/// name against the name it configured, and every node here signs under the one well-known
/// name, so a node re-signing with a key of its own would be indistinguishable from a tampered
/// master to any client that has ever talked to the master. The five signed resources are
/// therefore the master's own bytes, passed through unchanged; only the tarball and docs paths
/// stay local, because those are artifacts and chain through the ordinary proxy-fetch pipeline.
///
/// The per-ecosystem passthrough switch does not gate this. On a master that switch decides
/// whether an upstream is consulted while the index itself is still built locally; an edge has no
/// local index to fall back to, so honouring it here would leave the node unable to answer any
/// resource rather than merely answering from its own holdings.
/// </summary>
public sealed partial class HexController
{
    private async Task<IActionResult> ServeFromMasterAsync(ResourceRequest request, string orgId, CancellationToken ct)
    {
        var sources = await _svc.Registries.ResolveAsync(orgId, Ecosystem, ct);
        var master = sources.Count > 0 ? sources[0] : null;
        if (master is null)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable,
                "This edge node has no Hex upstream configured, so it cannot serve the master's signed resources.");
        }

        string url = $"{master.Url.TrimEnd('/')}/{MasterResourcePath(request)}";
        UpstreamMetadataResponse response;
        try
        {
            response = await _svc.Upstream.GetOrFetchMetadataAsync(url, master.AuthorizationHeader, ct);
        }
        catch (Exception ex) when (ex is SsrfBlockedException or UpstreamResponseTooLargeException or HttpRequestException or IOException)
        {
            _svc.Logger.LogWarning(ex, "Hex resource {Url} could not be read from the master: {ExceptionType}", url, ex.GetType().Name);
            return StatusCode(StatusCodes.Status503ServiceUnavailable, "The master could not be reached for this Hex resource; retry.");
        }

        return response.StatusCode == StatusCodes.Status404NotFound
            ? NotFound()
            : !response.IsSuccessStatusCode
            ? RefusalOrUnavailable(response.StatusCode, url, master.AuthorizationHeader)
            : request.Kind == ResourceKind.PublicKey
            ? PublicKeyFromMaster(response.Body)
            : SignedResourceFromMaster(response.Body, request.Kind);
    }

    /// <summary>
    /// The upstream-refusal contract applied to the master. A refusal is a deterministic verdict
    /// about the edge's own credential and no retry fixes it (502); anything else is the master
    /// being temporarily unable to answer, which a client should retry (503). Collapsing the two
    /// into one status is what makes a master restart look permanent to every Mix and Rebar3
    /// client on the network. An anonymous 403 stays retryable for the same reason it does
    /// elsewhere, though an edge always presents its token.
    /// </summary>
    private IActionResult RefusalOrUnavailable(int status, string url, string? authorization)
    {
        bool refused = status == StatusCodes.Status401Unauthorized
            || (status == StatusCodes.Status403Forbidden && authorization is not null);

        _svc.Logger.LogWarning(
            "Master answered {Status} for Hex resource {Url} (authenticated={Authenticated}); answering {Answer}.",
            status, url, authorization is not null, refused ? "502" : "503");

        return refused
            ? StatusCode(StatusCodes.Status502BadGateway, "The master refused this Hex resource (auth/policy).")
            : StatusCode(StatusCodes.Status503ServiceUnavailable, "The master could not serve this Hex resource; retry.");
    }

    private IActionResult PublicKeyFromMaster(byte[] body)
    {
        Response.Headers.CacheControl = "private, max-age=300";
        return Content(System.Text.Encoding.UTF8.GetString(body), "text/plain");
    }

    private IActionResult SignedResourceFromMaster(byte[] body, ResourceKind kind)
    {
        // Identical bytes under the same formula the master uses, so a client polling an edge and
        // a client polling the master compute the same tag and the 304 path holds across both.
        string etag = "\"" + Convert.ToHexString(SHA256.HashData(body))[..32].ToLowerInvariant() + "\"";
        Response.Headers.ETag = etag;

        // A package resource is the one whose content moves when an upstream release appears, and
        // an edge cannot tell whether the master built this one from an upstream answer. It takes
        // the shorter of the master's two lifetimes rather than risk holding a stale index longer
        // than the master would have.
        Response.Headers.CacheControl = kind == ResourceKind.Package ? "private, max-age=60" : "private, max-age=300";
        return Request.Headers.IfNoneMatch.Any(v => v == etag)
            ? StatusCode(StatusCodes.Status304NotModified)
            : File(body, ProtobufContentType);
    }

    private static string MasterResourcePath(ResourceRequest request) => request.Kind switch
    {
        ResourceKind.PublicKey => "public_key",
        ResourceKind.Names => "names",
        ResourceKind.Versions => "versions",
        ResourceKind.Package => $"packages/{Uri.EscapeDataString(request.Name)}",
        // The policy resource is only ever addressed through the organization form, so the master
        // is asked for it by the same spelling the client used here.
        _ => $"repos/{HexIndexBuilder.RepositoryName}/policies/{Uri.EscapeDataString(request.Name)}",
    };
}
