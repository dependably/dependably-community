using Dapper;
using Dependably.Protocol;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

// Tags-list read path: local tag rows unioned with a best-effort upstream fetch, paginated per
// the Distribution Spec's n=/last= contract. Split out of OciController.cs (partial class) to
// keep any single file under the 1000-line cap; see that file for the dispatchers, shared auth
// helpers, and the OciControllerServices bundle.
public sealed partial class OciController
{
    // Maximum page size for tags/list responses. OCI clients that request n= larger than
    // this receive exactly this many tags with a Link: rel="next" header when more exist.
    private const int TagsMaxPageSize = 1000;

    private async Task<IActionResult> ListTagsAsync(string name, CancellationToken ct)
    {
        var auth = await AuthorizePullAsync(ct);
        if (auth.Unauthorized is not null)
        {
            return auth.Unauthorized;
        }

        if (!OciCoordinatesParser.IsValidRepositoryName(name))
        {
            return OciError(StatusCodes.Status400BadRequest, OciErrorCode.NAME_INVALID, "Invalid repository name.");
        }

        string orgId = CurrentTenantId();

        var (n, nZero) = ParseTagsPageSize();
        // last=: lexical continuation token — return tags strictly after this value.
        string? last = Request.Query["last"].FirstOrDefault();

        // OCI spec: n=0 returns an empty tag list with no Link header.
        if (nZero)
        {
            return new JsonResult(new { name, tags = Array.Empty<string>() });
        }

        // ── Local tag list ─────────────────────────────────────────────────────
        // xtenant: (org_id, repository) index is tenant-scoped.
        await using var conn = await _svc.Db.OpenAsync(ct);
        var localTags = (await conn.QueryAsync<string>(
            "SELECT tag FROM oci_tags WHERE org_id = @orgId AND repository = @repo ORDER BY tag ASC",
            new { orgId, repo = name })).ToList();

        var upstreamTags = await FetchUpstreamTagsOrDegradeAsync(name, ct);
        var allTags = MergeTags(localTags, upstreamTags);

        return allTags.Count == 0
            ? OciError(StatusCodes.Status404NotFound, OciErrorCode.NAME_UNKNOWN, "Repository unknown.")
            : BuildTagsPage(name, allTags, n, last);
    }

    /// <summary>
    /// Parses the <c>n=</c> page-size query parameter on the current request: the number of
    /// results per page (clamped to <see cref="TagsMaxPageSize"/>). <c>n=0</c> returns an
    /// empty list per the OCI Distribution Spec; omitted or negative values use the page maximum.
    /// </summary>
    private (int N, bool NZero) ParseTagsPageSize()
    {
        if (!Request.Query.TryGetValue("n", out var nVal) ||
            !int.TryParse(nVal.FirstOrDefault(), out int nParsed))
        {
            return (TagsMaxPageSize, false);
        }

        if (nParsed == 0)
        {
            return (TagsMaxPageSize, true);
        }

        return nParsed > 0
            ? (Math.Min(nParsed, TagsMaxPageSize), false)
            : (TagsMaxPageSize, false);
    }

    /// <summary>
    /// Fetches the upstream tag list (attempted when the proxy is enabled), degrading to
    /// <c>null</c> — a local-only listing — on failure. AirGappedException means upstream is
    /// intentionally unreachable; any other transport failure is also degraded so a network
    /// error never 503s a local listing.
    /// </summary>
    private async Task<List<string>?> FetchUpstreamTagsOrDegradeAsync(string name, CancellationToken ct)
    {
        try
        {
            return await _svc.Upstream.FetchTagsAsync(CurrentTenantId(), name, ct);
        }
        catch (AirGappedException)
        {
            // Air-gap mode: upstream unreachable by design; serve local tags only.
            return null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Transport or parse failure: degrade to local tags; a warning is already
            // emitted inside FetchTagsAsync for the upstream-error case.
            _ = ex; // suppressed; logged upstream
            return null;
        }
    }

    /// <summary>
    /// Merged listing: local union upstream, deduplicated, sorted lexically.
    /// Local tags win on collision only in the sense that one name always maps to
    /// exactly one digest — the tag name list itself is just strings, no collision.
    /// </summary>
    private static List<string> MergeTags(List<string> localTags, List<string>? upstreamTags)
    {
        if (upstreamTags is not { Count: > 0 })
        {
            return localTags;
        }

        // Union: add upstream tags not already present locally.
        var merged = new SortedSet<string>(localTags, StringComparer.Ordinal);
        foreach (string t in upstreamTags)
        {
            merged.Add(t);
        }
        return new List<string>(merged);
    }

    /// <summary>
    /// Applies the <c>last=</c> continuation and the page size to the merged tag list,
    /// emitting a Link header when a further page exists.
    /// </summary>
    private JsonResult BuildTagsPage(string name, List<string> allTags, int n, string? last)
    {
        IEnumerable<string> filtered = allTags;
        if (!string.IsNullOrEmpty(last))
        {
            filtered = allTags.Where(t => string.Compare(t, last, StringComparison.Ordinal) > 0);
        }

        var page = filtered.Take(n + 1).ToList(); // fetch one extra to detect "has next page"
        bool hasMore = page.Count > n;
        if (hasMore)
        {
            page.RemoveAt(page.Count - 1);
        }

        if (hasMore && page.Count > 0)
        {
            string lastTag = page[^1];
            // RFC 5988 Link header for pagination continuation per the OCI Distribution Spec.
            Response.Headers.Link = $"</v2/{name}/tags/list?n={n}&last={lastTag}>; rel=\"next\"";
        }

        return new JsonResult(new { name, tags = page });
    }
}
