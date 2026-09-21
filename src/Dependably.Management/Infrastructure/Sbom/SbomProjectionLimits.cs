namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// Presentation-field bounds shared by every parser that lands rows in the <c>sbom_components</c>
/// projection, so CycloneDX and SPDX describing the same fact clip it at the same length rather
/// than each parser inventing its own ceiling. Kept separate from
/// <see cref="SbomDocumentLimits"/>, which bounds how much of a document is admitted at all —
/// these bound how wide one already-admitted field is allowed to land.
/// </summary>
internal static class SbomProjectionLimits
{
    /// <summary>The bound on a component's free-form description.</summary>
    public const int MaxDescriptionLength = 1000;

    /// <summary>The bound on the shorter presentation fields — author, producer, copyright, group, a linked URL.</summary>
    public const int MaxTextLength = 400;

    /// <summary>The bound on the serialized hashes array.</summary>
    public const int MaxHashesJsonLength = 2000;
}
