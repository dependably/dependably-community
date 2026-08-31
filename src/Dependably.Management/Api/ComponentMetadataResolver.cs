using Dependably.Infrastructure;

namespace Dependably.Api;

/// <summary>
/// Where a component row's presentation metadata comes from, once both sources have been
/// consulted.
/// </summary>
public static class ComponentMetadataSources
{
    /// <summary>Every resolved value came from this tenant's own registry row.</summary>
    public const string Registry = "registry";

    /// <summary>Every resolved value came from the uploaded SBOM.</summary>
    public const string Sbom = "sbom";

    /// <summary>Some fields resolved from the registry, the rest from the SBOM.</summary>
    public const string Mixed = "mixed";
}

/// <summary>The four fields both planes can describe, plus where the answers came from.</summary>
public sealed record ResolvedComponentMetadata(
    string? Description,
    string? Author,
    string? WebsiteUrl,
    string? VcsUrl,
    string? Source);

/// <summary>
/// Resolves the presentation metadata a component row renders from the two places that describe
/// it: this tenant's own <c>packages</c> row, and the uploaded SBOM's component entry.
///
/// <para><b>The registry wins, field by field.</b> Its values come from the artifact manifest
/// this instance itself fetched, hashed and stored — on the hosted publish path and on the proxy
/// first-fetch path alike, since both write the same row. An SBOM is a third party's description
/// of a component, produced by whatever tool built it, and it can be stale, wrong about a
/// package it never fetched, or simply describing a different build of the same coordinate.
/// When this registry already knows what the package says about itself, that is the better
/// answer, so an uploaded document never overwrites it on screen.</para>
///
/// <para><b>Per field, not per component.</b> A registry row that carries a description but no
/// author must not suppress the author the SBOM did carry: preferring the whole registry record
/// whenever any part of it exists would lose real information to fill a gap with nothing. The
/// fallback is therefore per field, and <see cref="ResolvedComponentMetadata.Source"/> reports
/// <see cref="ComponentMetadataSources.Mixed"/> when both contributed rather than naming one and
/// implying the other was silent.</para>
///
/// <para><b>Both facts stay recorded.</b> This resolves what is displayed, not what is stored —
/// <c>sbom_components</c> keeps the document's own claim verbatim, so an export re-emits what was
/// ingested and a later registry fetch can change the displayed answer without a re-upload. The
/// alternative, folding precedence into the write, would bake in whichever order the SBOM upload
/// and the first proxy fetch happened to arrive.</para>
///
/// <para>The fields with no registry equivalent — copyright, group, the issue-tracker and
/// distribution links, the declared hashes — are SBOM-only and are not resolved here at all.</para>
/// </summary>
public static class ComponentMetadataResolver
{
    /// <summary>
    /// Picks each field from the registry facts when they carry it, else from the component's own
    /// SBOM columns. <paramref name="facts"/> is null for a coordinate this registry has never
    /// served, which is the ordinary case for a component the tenant only reads about in an SBOM.
    /// </summary>
    public static ResolvedComponentMetadata Resolve(AnalysisComponentRow component, ComponentRegistryFacts? facts)
    {
        int fromRegistry = 0;
        int fromSbom = 0;

        string? description = Pick(facts?.Description, component.Description, ref fromRegistry, ref fromSbom);
        string? author = Pick(facts?.Author, component.ComponentAuthor, ref fromRegistry, ref fromSbom);
        string? website = Pick(facts?.Homepage, component.WebsiteUrl, ref fromRegistry, ref fromSbom);
        string? vcs = Pick(facts?.RepositoryUrl, component.VcsUrl, ref fromRegistry, ref fromSbom);

        return new ResolvedComponentMetadata(
            description,
            author,
            website,
            vcs,
            Source(fromRegistry, fromSbom));
    }

    // Empty and whitespace are treated as absent, not as a registry answer of "nothing": a blank
    // column would otherwise suppress a real value the SBOM carried.
    private static string? Pick(string? registry, string? sbom, ref int fromRegistry, ref int fromSbom)
    {
        if (!string.IsNullOrWhiteSpace(registry))
        {
            fromRegistry++;
            return registry;
        }

        if (!string.IsNullOrWhiteSpace(sbom))
        {
            fromSbom++;
            return sbom;
        }

        return null;
    }

    // Null when neither source said anything — the caller renders no provenance line rather than
    // claiming a source for an empty section.
    private static string? Source(int fromRegistry, int fromSbom) =>
        (fromRegistry, fromSbom) switch
        {
            (0, 0) => null,
            ( > 0, 0) => ComponentMetadataSources.Registry,
            (0, > 0) => ComponentMetadataSources.Sbom,
            _ => ComponentMetadataSources.Mixed,
        };
}
