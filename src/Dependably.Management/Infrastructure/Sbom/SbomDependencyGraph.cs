using System.Text.Json;

namespace Dependably.Infrastructure.Sbom;

/// <summary>Where one component sits in the dependency graph the SBOM declared.</summary>
/// <param name="Kind">direct, transitive or graph-unknown; null when the document declared no graph.</param>
/// <param name="PathJson">
/// JSON array of component identities from the root's first hop to this component, or null.
/// Entries are purls (falling back to <c>name@version</c>), never bom-refs: a bom-ref is
/// document-local and a producer is free to renumber it between uploads, so a stored path of
/// bom-refs would stop meaning anything on the next upload — and the export, which names
/// components by purl, would emit edges pointing at refs no component carries.
/// </param>
public sealed record SbomGraphPosition(string? Kind, string? PathJson);

/// <summary>
/// Walks a CycloneDX <c>dependencies[]</c> array to answer, for each component, whether the
/// application depends on it directly and by what route.
///
/// <para>The adjacency has no column of its own, so it is persisted where it is read: the
/// shortest route from the application to a component becomes that component's
/// <c>dependency_path</c>, and its distance becomes <c>dependency_kind</c>. A reachability scan
/// later overwrites both with what it observed, which is strictly better information — this
/// walk is what a version has to work with until one arrives.</para>
///
/// <para>A component the graph never reaches is <c>graph-unknown</c> rather than transitive:
/// a producer that emits a partial graph is common, and calling an unplaced component
/// transitive would assert a route that was never declared. A document with no graph at all
/// leaves every component's position null, which is a different statement again — nothing was
/// claimed, so nothing is recorded.</para>
/// </summary>
public static class SbomDependencyGraph
{
    /// <summary>Resolves every component's graph position, keyed by the component's bom-ref.</summary>
    public static IReadOnlyDictionary<string, SbomGraphPosition> Resolve(CycloneDxDocument document)
    {
        var positions = new Dictionary<string, SbomGraphPosition>(StringComparer.Ordinal);
        if (document.Dependencies.Count == 0)
        {
            return positions;
        }

        string? rootRef = ResolveRootRef(document);
        var paths = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        if (rootRef is not null)
        {
            BreadthFirst(document.Dependencies, rootRef, paths);
        }

        var identityOf = BuildIdentityMap(document);
        foreach (var component in document.Components)
        {
            string? reference = component.BomRef ?? component.Purl;
            if (reference is not null)
            {
                positions[reference] = PositionOf(reference, paths, identityOf);
            }
        }

        return positions;
    }

    // Each component's display identity, keyed by the ref the graph refers to it by. A component
    // the document gives neither a bom-ref nor a purl cannot be referred to at all, so it has no
    // entry rather than an entry under an invented key.
    private static Dictionary<string, string> BuildIdentityMap(CycloneDxDocument document)
    {
        var identityOf = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var c in document.Components)
        {
            string? r = c.BomRef ?? c.Purl;
            if (r is not null)
            {
                identityOf[r] = c.Purl ?? (c.Version is null ? c.Name ?? r : $"{c.Name}@{c.Version}");
            }
        }

        return identityOf;
    }

    private static SbomGraphPosition PositionOf(
        string reference,
        Dictionary<string, List<string>> paths,
        Dictionary<string, string> identityOf)
    {
        if (!paths.TryGetValue(reference, out var path))
        {
            return new SbomGraphPosition("graph-unknown", null);
        }

        // A ref the document never declared as a component keeps its raw spelling — there is
        // no identity to translate it to, and dropping the hop would silently shorten the path.
        var identities = path
            .Select(r => identityOf.TryGetValue(r, out string? id) ? id : r)
            .ToList();

        return new SbomGraphPosition(
            path.Count <= 1 ? "direct" : "transitive",
            JsonSerializer.Serialize(identities));
    }

    // The root is the document's own subject. Its bom-ref is what dependencies[] refers to;
    // a producer that omits the bom-ref names the entry by name@version instead, and one that
    // declares neither leaves the graph unrooted, which the caller reads as graph-unknown.
    private static string? ResolveRootRef(CycloneDxDocument document)
    {
        var root = document.Root;
        if (root is null)
        {
            return null;
        }

        if (root.BomRef is not null && document.Dependencies.ContainsKey(root.BomRef))
        {
            return root.BomRef;
        }

        if (root.Name is null)
        {
            return null;
        }

        string composed = root.Version is null ? root.Name : $"{root.Name}@{root.Version}";
        return document.Dependencies.ContainsKey(composed) ? composed : root.BomRef;
    }

    // Shortest route wins: a component reachable both directly and through a chain is direct,
    // because that is what the application actually declares about it.
    private static void BreadthFirst(
        IReadOnlyDictionary<string, IReadOnlyList<string>> graph,
        string rootRef,
        Dictionary<string, List<string>> paths)
    {
        var queue = new Queue<string>();
        queue.Enqueue(rootRef);
        var visited = new HashSet<string>(StringComparer.Ordinal) { rootRef };

        while (queue.Count > 0)
        {
            string current = queue.Dequeue();
            if (!graph.TryGetValue(current, out var children))
            {
                continue;
            }

            paths.TryGetValue(current, out var currentPath);
            foreach (string child in children)
            {
                if (!visited.Add(child))
                {
                    continue;
                }

                List<string> childPath = currentPath is null ? [] : [.. currentPath];
                childPath.Add(child);
                paths[child] = childPath;
                queue.Enqueue(child);
            }
        }
    }
}
