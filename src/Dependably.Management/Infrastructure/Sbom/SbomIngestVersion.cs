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
    /// Revision 10: five widened parser extractions, none of which any earlier revision's
    /// derived columns already carried correctly. <c>component_producer</c> now reads CycloneDX's
    /// <c>component.supplier</c> (falling back to the older <c>publisher</c> string) instead of
    /// <c>publisher</c> alone, and <c>component_author</c> now falls back to
    /// <c>component.manufacturer</c> when neither <c>authors[]</c> nor <c>author</c> is present —
    /// a document naming only <c>supplier</c>/<c>manufacturer</c> previously stored NULL for both
    /// columns. <c>explicit_unknown_fields</c> widens from two CycloneDX-readable members
    /// (Producer/License) to four (also Version/Identifier), read from
    /// <c>dependably:version-status</c>/<c>dependably:identifier-status</c>.
    /// <c>project_documents.tool_version_explicit_unknown</c> is newly captured from the named
    /// tool's own <c>dependably:tool-version-status</c> property. And SPDX ingest now also reads
    /// the six scoped <c>*_DEPENDENCY_OF</c> relationship types into the dependency graph
    /// alongside <c>DEPENDS_ON</c>/<c>DEPENDENCY_OF</c>, plus <c>CONTAINS</c> into the new
    /// <c>sbom_components.containment_declared</c> — a D17-only signal, deliberately never folded
    /// into <c>dependency_kind</c>/<c>dependency_path</c> (see
    /// <c>CycloneDxComponent.ContainmentDeclared</c>'s own doc comment). A document re-uploaded
    /// byte-for-byte would otherwise leave every one of these columns exactly as an older build
    /// left them forever, for a project whose dependencies happen not to change.
    ///
    /// <para>Revision 9 was: CISA D2 (SBOM Author Signature) admission-time verification. Not a
    /// parser extraction — <c>project_documents.signature_status</c>/<c>signature_key_id</c> are
    /// written directly by the upload endpoint from <c>SbomSignatureVerifier</c>'s verdict over
    /// the staged raw bytes, never from a projected/derived table. The bump exists for the same
    /// dedup-short-circuit reason every prior revision bumped it: a byte-identical re-upload is
    /// what makes the new admission check run at all for a document already stored, and the
    /// projects with the most stable dependencies are exactly the ones that never otherwise
    /// re-upload. Without the bump, a document ingested before this revision reads
    /// <c>signature_status</c> NULL forever, indistinguishable from "verification was off".</para>
    ///
    /// <para>Revision 8 was: <c>explicit_unknown_fields</c> — CISA X4/P4a's explicit-unknown-vs-silent-
    /// absence signal. <see cref="SpdxParser"/> tracks whether <c>supplier</c> (Component
    /// Producer) and <c>licenseConcluded</c>/<c>licenseDeclared</c> (Component Licence) were
    /// explicitly asserted <c>NOASSERTION</c>/<c>NONE</c> rather than simply absent from the
    /// document, previously indistinguishable once folded to null. <see cref="CycloneDxParser"/>
    /// populates the same column ONLY from this registry's own <c>dependably:producer-status</c>/
    /// <c>dependably:license-status</c> component properties read back on a re-upload — plain
    /// CycloneDX defines no generic equivalent token, so any other producer's document still
    /// leaves the column null. A document re-uploaded byte-for-byte would otherwise leave the
    /// column NULL forever for a project whose dependencies happen not to change.</para>
    ///
    /// <para>Revision 7 was: <c>additional_identifiers</c> — CISA D13c/D13d. Newly captured: CycloneDX's
    /// <c>cpe</c>, <c>swhid</c>, <c>omniborId</c> and <c>pedigree.commits[].uid</c>, an
    /// <c>externalReferences</c> entry whose url is a <c>urn:uuid:</c> URN, and SPDX's
    /// <c>externalRefs</c> SECURITY (<c>cpe22Type</c>/<c>cpe23Type</c>) and PERSISTENT-ID
    /// (<c>swh</c>/<c>gitoid</c>) categories — all previously parsed away. A document re-uploaded
    /// byte-for-byte would otherwise leave the column NULL forever for a project whose
    /// dependencies happen not to change.</para>
    ///
    /// <para>Revision 6 was: <c>license_is_named</c>/<c>license_url</c> — CISA D16c. <c>license_is_named</c>
    /// is the discriminator (does <c>license_spdx</c> hold a free-text <c>license.name</c> rather
    /// than a genuine SPDX identifier/expression?) that makes a name-only licence — with or
    /// without a <c>license.url</c> — representable at export time at all; <c>license_url</c> is
    /// the URL fallback carried alongside it when the document offered one. Both resolve from a
    /// single <c>license.name</c> entry with no SPDX <c>id</c>. A document re-uploaded
    /// byte-for-byte would otherwise leave both columns NULL forever for a project whose
    /// dependencies happen not to change.</para>
    ///
    /// <para>Revision 5 was: SPDX 2.3 joins CycloneDX as a second front end onto this projection
    /// (<see cref="SpdxParser"/>), reading <c>sbom_components</c> from <c>supplier</c>/
    /// <c>originator</c>, <c>checksums</c> and <c>relationships[]</c> the same way the CycloneDX
    /// front end reads <c>publisher</c>/<c>authors</c>, <c>hashes</c> and <c>dependencies[]</c>.
    /// No already-stored CycloneDX document's own derived rows change shape by this revision
    /// alone, but the bump keeps <c>ingest_version</c> a precise boundary of "what this build's
    /// parsers can produce" rather than implicitly "what the CycloneDX parser alone produces" — a
    /// distinction that starts to matter the day a later revision changes SPDX-side extraction
    /// only, which must not read as already covered by a revision that predates SPDX ingest.</para>
    ///
    /// <para>Revision 4 was: <c>component_author</c> no longer absorbs <c>publisher</c> — a separate
    /// <c>component_producer</c> column now carries it, per CISA's 2026 baseline splitting
    /// Component Producer from Component Author. <c>project_documents.lifecycles</c> is also
    /// newly captured from <c>metadata.lifecycles</c>, previously dropped entirely. A document
    /// re-uploaded byte-for-byte would otherwise leave both columns NULL forever for a project
    /// whose dependencies happen not to change.</para>
    ///
    /// <para>Revision 3 was the manifest dev-dependency declaration (<c>ManifestDevDeclared</c>)
    /// filling <c>dependency_scope</c> for a component still at its 'unknown' default. A document
    /// re-uploaded byte-for-byte would otherwise leave every component that a reachability
    /// scanner has not yet classified exactly at 'unknown' forever — precisely the common case
    /// (a clean scan, or no SARIF uploaded yet) this revision exists to fix.</para>
    ///
    /// <para>Revision 2 was the two component fields CycloneDX 1.7 added — versionRange and
    /// isExternal. A re-merge is the only thing that fills them for a document already stored.</para>
    ///
    /// <para>Revision 1 was component presentation metadata — description, author, copyright,
    /// group, the four linked external-reference URLs, and the hashes array. A document stored
    /// under any earlier revision re-merges once on its next upload.</para>
    /// </summary>
    public const int Current = 10;
}
