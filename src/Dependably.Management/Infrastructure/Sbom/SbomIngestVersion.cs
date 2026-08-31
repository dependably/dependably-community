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
    /// Revision 1: component presentation metadata — description, author, copyright, group, the
    /// four linked external-reference URLs, and the hashes array. Documents stored before this
    /// column existed read as 0 and re-merge once.
    /// </summary>
    public const int Current = 1;
}
