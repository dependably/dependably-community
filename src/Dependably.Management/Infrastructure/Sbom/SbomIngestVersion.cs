namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// The revision of the ingest projection — what the parsers extract and what the merge writes
/// into the derived tables.
///
/// <para>It exists because ingest short-circuits on the stored document's SHA-256: re-uploading
/// bytes already held is a 200 that does no work, which is correct while the projection is
/// fixed and wrong the moment it widens. A build that starts recording a field its predecessor
/// discarded would otherwise leave every already-stored document's rows exactly as the older
/// build wrote them, and the only thing that would ever repopulate them is the project's
/// content happening to change — so the projects whose dependencies are most stable are
/// precisely the ones the new columns would stay empty for, indefinitely and silently.</para>
///
/// <para>Bump this whenever a change makes the derived rows differ for an unchanged document:
/// a new column the parser fills, a corrected extraction, a changed normalization. Do not bump
/// it for a change that only affects how stored rows are read or rendered — that costs a
/// re-merge of every document on the next upload and buys nothing.</para>
/// </summary>
public static class SbomIngestVersion
{
    /// <summary>
    /// Revision 3: the manifest dev-dependency declaration (<c>ManifestDevDeclared</c>) now fills
    /// <c>dependency_scope</c> for a component still at its 'unknown' default. A document
    /// re-uploaded byte-for-byte would otherwise leave every component that a reachability
    /// scanner has not yet classified exactly at 'unknown' forever — precisely the common case
    /// (a clean scan, or no SARIF uploaded yet) this revision exists to fix.
    ///
    /// <para>Revision 2 was the two component fields CycloneDX 1.7 added — versionRange and
    /// isExternal. A re-merge is the only thing that fills them for a document already stored.</para>
    ///
    /// <para>Revision 1 was component presentation metadata — description, author, copyright,
    /// group, the four linked external-reference URLs, and the hashes array. A document stored
    /// under any earlier revision re-merges once on its next upload.</para>
    /// </summary>
    public const int Current = 3;
}
