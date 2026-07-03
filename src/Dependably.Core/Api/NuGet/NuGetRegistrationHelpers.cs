using System.Text.Json;
using System.Text.Json.Nodes;
using Dependably.Infrastructure;
using NuGet.Versioning;

namespace Dependably.Api;

/// <summary>
/// Pure-static JSON helpers for building and rewriting NuGet v3 registration index and leaf documents.
/// Shared by <see cref="NuGetController"/> and test harnesses.
/// </summary>
internal static class NuGetRegistrationHelpers
{
    // JSON serialization options that preserve characters like '+' (SemVer build metadata) without
    // escaping them as \uXXXX, keeping round-tripped registration JSON readable and spec-valid.
    internal static readonly JsonSerializerOptions RelaxedJsonOptions = new()
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    // Splice local-only versions into upstream registration JSON as an extra CatalogPage.
    // Dedupes by version against the upstream catalog entries already present so a name with
    // a privately uploaded build of an upstream version doesn't appear twice. Rewrites upstream
    // leaf URLs (packageContent, @id) to local routes before returning. Public so unit tests can
    // verify the splice without spinning up the controller.
    internal static string MergeLocalIntoUpstreamRegistration(
        string upstreamJson, IReadOnlyList<PackageVersion> localVersions, Package pkg, string id,
        string? baseUrl = null)
    {
        string normalizedId = id.ToLowerInvariant();
        JsonObject? root;
        try { root = JsonNode.Parse(upstreamJson) as JsonObject; }
        catch (JsonException) { return upstreamJson; }
        if (root is null)
        {
            return upstreamJson;
        }

        var upstreamVersionSet = CollectUpstreamVersions(root);
        var localOnly = localVersions
            .Where(v => !v.Yanked && !upstreamVersionSet.Contains(v.Version))
            .ToList();

        if (baseUrl is not null)
        {
            RewriteAllLeafUrls(root, normalizedId, baseUrl);
        }

        if (localOnly.Count == 0)
        {
            return root.ToJsonString(RelaxedJsonOptions);
        }

        var localPage = BuildLocalPage(localOnly, normalizedId, pkg.Name);
        AppendPage(root, localPage);
        return root.ToJsonString(RelaxedJsonOptions);
    }

    // Rewrites packageContent and leaf @id fields in a full upstream registration index document
    // (all pages, all leaves) to local flatcontainer and registration routes. Tolerates absent
    // or non-string fields — upstream JSON is untrusted input.
    internal static string RewriteRegistrationIndexUrls(string indexJson, string normalizedId, string baseUrl)
    {
        JsonObject? root;
        try { root = JsonNode.Parse(indexJson) as JsonObject; }
        catch (JsonException) { return indexJson; }
        if (root is null)
        {
            return indexJson;
        }

        RewriteAllLeafUrls(root, normalizedId, baseUrl);
        return root.ToJsonString(RelaxedJsonOptions);
    }

    // Rewrites packageContent and @id in an upstream registration leaf JSON document so that
    // all download and leaf URLs resolve to this instance rather than the upstream registry.
    // Tolerates absent or non-string fields — upstream JSON is untrusted input.
    internal static string RewriteRegistrationLeafUrls(string leafJson, string normalizedId, string baseUrl)
    {
        JsonObject? leaf;
        try { leaf = JsonNode.Parse(leafJson) as JsonObject; }
        catch (JsonException) { return leafJson; }
        if (leaf is null)
        {
            return leafJson;
        }

        RewriteLeafNode(leaf, normalizedId, baseUrl);
        return leaf.ToJsonString(RelaxedJsonOptions);
    }

    // Walks the pages and leaf entries inside a parsed registration index and rewrites each
    // leaf's @id and packageContent to local routes. Page @id fields are informational (the
    // server inlines all pages and never externalises them), but rewriting them avoids leaking
    // upstream URLs into the document. Absent or non-object nodes are silently skipped.
    internal static void RewriteAllLeafUrls(JsonObject root, string normalizedId, string baseUrl)
    {
        if (root["items"] is not JsonArray pages)
        {
            return;
        }

        foreach (var pageNode in pages.OfType<JsonObject>())
        {
            if (pageNode["items"] is not JsonArray leaves)
            {
                continue;
            }

            foreach (var leafNode in leaves.OfType<JsonObject>())
            {
                RewriteLeafNode(leafNode, normalizedId, baseUrl);
            }
        }
    }

    // Rewrites the leaf @id and packageContent fields (at the leaf root and inside catalogEntry)
    // to local registration and flatcontainer routes. catalogEntry @id is intentionally left
    // unchanged — it is an upstream catalog resource URI, not a download path.
    internal static void RewriteLeafNode(JsonObject leaf, string normalizedId, string baseUrl)
    {
        // Leaf @id: `{registrationBase}/{id}/{version}.json` — rewrite to local registration route.
        string? version = TryGetString(leaf["catalogEntry"]?["version"]);
        if (!string.IsNullOrEmpty(version))
        {
            leaf["@id"] = $"{baseUrl}/registration/{normalizedId}/{version}.json";
        }

        // packageContent at leaf root and inside catalogEntry both point at a flatcontainer .nupkg.
        string? localPackageContent = !string.IsNullOrEmpty(version)
            ? $"{baseUrl}/flatcontainer/{normalizedId}/{version}/{normalizedId}.{version}.nupkg"
            : null;
        if (localPackageContent is not null)
        {
            if (leaf["packageContent"] is not null)
            {
                leaf["packageContent"] = localPackageContent;
            }
            if (leaf["catalogEntry"] is JsonObject catalogEntry && catalogEntry["packageContent"] is not null)
            {
                catalogEntry["packageContent"] = localPackageContent;
            }
        }
    }

    internal static HashSet<string> CollectUpstreamVersions(JsonObject root)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (root["items"] is not JsonArray pages)
        {
            return set;
        }

        var entries = pages
            .OfType<JsonObject>()
            .SelectMany(p => (p["items"] as JsonArray)?.OfType<JsonObject>() ?? []);
        foreach (var entry in entries)
        {
            string? v = TryGetString(entry["catalogEntry"]?["version"]);
            if (v is not null)
            {
                set.Add(v);
            }
        }
        return set;
    }

    // Returns the string value of a JsonNode when it is a JSON string, or null for any other
    // type (number, bool, array, object, null). GetValue<string>() throws InvalidOperationException
    // for non-string nodes, so this helper is used on all upstream-controlled fields to avoid
    // a hostile or malformed upstream crashing the registration response path.
    internal static string? TryGetString(JsonNode? node) =>
        node is JsonValue jv && jv.TryGetValue<string>(out string? s) ? s : null;

    // BaseUrl isn't available in a static context — leaves reference our own registration/
    // flatcontainer at relative paths. NuGet clients combine these with the service-index
    // base, so relative URLs resolve correctly.
    internal static JsonObject BuildLocalLeaf(PackageVersion v, string normalizedId, string pkgName) => new()
    {
        ["@id"] = $"/nuget/registration/{normalizedId}/{v.Version}.json",
        ["@type"] = "Package",
        ["catalogEntry"] = new JsonObject
        {
            ["id"] = pkgName,
            ["version"] = v.Version,
            ["listed"] = true,
            ["packageContent"] = $"/nuget/flatcontainer/{normalizedId}/{v.Version}/{normalizedId}.{v.Version}.nupkg"
        }
    };

    internal static JsonObject BuildLocalPage(IReadOnlyList<PackageVersion> localOnly, string normalizedId, string pkgName)
    {
        var localItems = new JsonArray(localOnly
            .Select(v => (JsonNode)BuildLocalLeaf(v, normalizedId, pkgName))
            .ToArray());
        var (lower, upper) = ComputeRange(localOnly);
        return new JsonObject
        {
            ["@id"] = $"/nuget/registration/{normalizedId}/index.json#page/local",
            ["@type"] = "catalog:CatalogPage",
            ["count"] = localItems.Count,
            ["items"] = localItems,
            ["lower"] = lower,
            ["upper"] = upper,
            ["parent"] = $"/nuget/registration/{normalizedId}/index.json"
        };
    }

    internal static (string Lower, string Upper) ComputeRange(IReadOnlyList<PackageVersion> localOnly)
    {
        var sorted = localOnly
            .Select(v => (Parsed: NuGetVersion.TryParse(v.Version, out var nv) ? nv : null, Raw: v.Version))
            .Where(t => t.Parsed is not null)
            .OrderBy(t => t.Parsed)
            .Select(t => t.Raw)
            .ToList();
        return sorted.Count > 0
            ? (sorted[0], sorted[^1])
            : (localOnly[0].Version, localOnly[^1].Version);
    }

    internal static void AppendPage(JsonObject root, JsonObject page)
    {
        if (root["items"] is not JsonArray pages)
        {
            pages = new JsonArray();
            root["items"] = pages;
        }
        pages.Add(page);
        if (root["count"] is not null)
        {
            root["count"] = pages.Count;
        }
    }
}
