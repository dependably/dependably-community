using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Dapper;
using Dependably.Infrastructure.Sbom;

namespace Dependably.Infrastructure;

/// <summary>
/// CISA D6/D9 (SBOM Timestamp / SBOM Version): revision identity for a RENDERED export,
/// persisted in <c>sbom_export_revisions</c> rather than minted fresh on every call.
///
/// <para><b>Decision — serial stable, version incrementing (D9f).</b> A document's
/// <c>serialNumber</c> is minted once, at first render, and never changes; its <c>version</c>
/// starts at 1 and increments only when the data changes. A stable serial with an incrementing
/// version lets a consumer recognize two documents as revisions of the SAME subject (D9a) — the
/// alternative (a fresh serial per revision) throws that relationship away. <c>version</c> is an
/// integer, matching how CycloneDX defines the field — D9c's SemVer guidance applies only to a
/// format that carries a SemVer string, which this one does not; do not "fix" this to
/// <c>"1.0.0"</c>.</para>
///
/// <para><b>Decision — one revision line per document SHAPE, not per project version (the
/// export-options interaction).</b> <c>doc_kind</c> (<c>inventory</c>/<c>vdr</c>/<c>vex</c>)
/// and <c>scope_filter</c> (<c>all</c>/<c>prod</c>/<c>dev</c>) each select a genuinely different
/// set of assertions from the same project version — a <c>scope=prod</c> render and a
/// <c>scope=all</c> render omit and include different components, and an <c>inventory</c> render
/// omits every vulnerability a <c>vdr</c> render carries. Two such documents are not revisions of
/// each other; they are different documents about the same subject, so each combination gets its
/// own serial and its own revision counter. <c>format</c> is part of the key for the same reason,
/// even though only <c>cyclonedx-json</c> exists today — a second export format would be a
/// different document too, and the key should not need widening when one ships.
/// <c>specVersion</c> is deliberately NOT part of the key, on the strict condition that a 1.6 and
/// a 1.7 render assert IDENTICAL facts — the wire encoding may differ (a hash algorithm native or
/// disclosed-only), but a fact present in one and silently dropped in the other would make the
/// premise false. <c>isExternal</c> was exactly that case (a bare 1.7 field with no 1.6
/// equivalent) until <see cref="BuildComponentProperties"/> relocated it into the
/// <c>dependably:is-external</c> property under 1.6 — the same treatment <c>versionRange</c>
/// already had. With that fixed, every fact a 1.6 document can carry has a 1.7 equivalent and vice
/// versa, which is what makes keeping <c>specVersion</c> out of the key correct rather than merely
/// convenient.</para>
///
/// <para><b>What counts as a content change.</b> <see cref="ComputeContentFingerprint"/> and
/// <see cref="ComputeVexContentFingerprint"/> hash exactly the facts a document asserts: the
/// component set and its dependency graph (for <c>inventory</c>/<c>vdr</c>), the vulnerability
/// findings and their analysis state (for <c>vdr</c>/<c>vex</c>), and the provenance metadata
/// every producer asserts (<c>metadata.authors</c>/<c>metadata.tools</c> — D1/D7/D8). It excludes
/// every render-time or freshness-only value: the render's own timestamp, NVD/SSVC/KEV
/// last-checked-at stamps, coverage counts, and the affected-application count (an aggregate
/// across this SAME tenant's OTHER project versions — <c>CountAffectedApplicationsAsync</c> is
/// <c>WHERE org_id = @orgId</c>, so it is within-tenant, not cross-tenant; it is excluded because
/// it is not data ABOUT this component, not because it crosses a tenant boundary). Folding a
/// freshness stamp in would bump the version every night a re-scan runs even when it found
/// nothing new, which turns "version" back into a render counter — the exact defect D9 exists to
/// fix. A rating VALUE (severity, CVSS, KEV/EPSS/SSVC signals, analysis state) is real content and
/// is included; only the "when was this observed" companion timestamp is excluded.
///
/// <para><b>CISA P2/P4/X4 additions (component completeness, D16c, the unknown/withheld
/// vocabulary).</b> <c>license_url</c> and <c>license_is_named</c> (D16c's URL fallback and its
/// discriminator) are genuinely new persisted component facts and are both fingerprinted
/// alongside <c>licenseSpdx</c> in <see cref="FingerprintComponent"/> — <c>license_is_named</c>
/// changes which native <c>licenseChoice</c> SHAPE a re-render produces for byte-identical
/// <c>license_spdx</c>/<c>license_url</c> values, so it is real asserted content, not bookkeeping.
/// <c>additional_identifiers</c> (CISA D13c/D13d — CPE/SWHID/OmniBOR/commit-hash/UUID) is
/// fingerprinted the same way: a backfill that starts capturing an identifier a component's
/// source document always asserted is a real change to what the rendered document says, whether
/// the identifier lands as a native field (<c>cpe</c>/<c>swhid</c>/<c>omniborId</c>) or a
/// <c>dependably:identifier:*</c> property. Every OTHER X4/P4a "indicate unknown" status property (<c>ProducerStatus</c>/
/// <c>VersionStatus</c>/<c>HashStatus</c>/<c>LicenseStatus</c>/<c>ToolVersionStatus</c>/
/// <c>IdentifierStatus</c>) and the D16d non-SPDX-listed-licence marker are pure DERIVATIONS of
/// fields already in this hash — a component's producer/version/hash/licence/identifier-set
/// either changing or disappearing already changes the fingerprint via the field itself (purl via
/// <c>ref</c>, the rest via <c>additionalIdentifiers</c> just above), so the derived status needs
/// no separate entry.
/// <c>dependably:full-inventory-rendered</c> (P2) needs none either: on the <c>inventory</c>/
/// <c>vdr</c> lines it is a function of <c>scope_filter</c> (already part of this revision LINE's
/// own key, not its content) AND the kept component COUNT, which the component array itself
/// already hashes structurally — a set shrinking to zero already changes
/// <see cref="FingerprintComponents"/>'s own output. On the <c>vex</c> line the value is a fixed
/// structural constant (always <c>false</c>), never computed from anything this fingerprint
/// covers, so it contributes nothing to hash either way. A document whose full-inventory claim
/// differs for any other reason is, by construction, a document whose underlying content already
/// differs.</para>
///
/// <para>A standalone VEX document (<c>doc_kind = 'vex'</c>) asserts no <c>components[]</c> of its
/// own, but it is not vulnerability-only either: each vulnerability entry's <c>properties[]</c>
/// carries <see cref="EffectivePriority"/>'s derived priority, which reads the referenced
/// component's <c>dependencyKind</c>/<c>dependencyScope</c> and install-script presence — a
/// component whose scope moved <c>dev</c>→<c>runtime</c> changes the rendered priority with no
/// change to any vulnerability row at all. <see cref="VexVulnFingerprintFacts"/> therefore folds
/// those three component-derived facts into each entry it yields, resolved through the same
/// <c>componentByPurlKey</c> map <c>BuildVexEntry</c> reads from, rather than treating "no
/// <c>components[]</c> array" as "no component facts asserted".</para>
///
/// <para><c>ecosystem</c>/<c>purl_name</c> are included in a component's fingerprint input only
/// when <c>includePurlIdentity</c> is set (the <c>vdr</c> line) — neither is ever its own field in
/// the rendered <c>components[]</c> object, but on the <c>vdr</c> line they are what
/// <c>SbomPurlKey.ForComponent</c> resolves a vulnerability's analysis binding from, so a backfill
/// that re-parses them can change which analysis attaches to which finding. On the
/// <c>inventory</c> line, where no vulnerability binding exists to disturb, they are pure
/// unasserted database bookkeeping and are left out — an unrelated backfill must not bump an
/// inventory document that renders byte-for-byte the same either way.</para>
///
/// <para><b>Component hashes and identifiers are fingerprinted as the RENDERED (parsed,
/// validated, alias-normalized) fact set in RENDERED ORDER, never the stored column's raw
/// JSON.</b> <c>sbom_components.component_hashes</c>/<c>additional_identifiers</c> are ingested
/// verbatim and can carry entries the export boundary does not (yet) place anywhere in the
/// document — <see cref="ParseAssertedHashes"/> drops a value that fails ASCII-hex validation, and
/// <see cref="ParseAdditionalIdentifiers"/> keeps every kind, including ones neither
/// <see cref="BuildComponentObject"/> nor <see cref="BuildComponentProperties"/> currently
/// recognises, specifically so a future ingest revision that widens
/// <c>SbomIdentifierKinds</c> does not need to re-parse every already-stored row. Fingerprinting
/// the raw column would make THAT widening bump every document's <c>version</c> the next time
/// export runs, with no rendered change at all — <c>version</c> becoming a render counter for a
/// kind the document never asserts, the exact defect D9 exists to prevent. <see
/// cref="FingerprintComponent"/> instead re-derives the same filtered, alias-normalized set
/// <see cref="BuildComponentHashes"/> and <see cref="BuildComponentObject"/>/
/// <see cref="BuildComponentProperties"/> already compute for rendering (an entry that ends up
/// SOMEWHERE in the document — native field or disclosed property — is asserted content; one that
/// does not is not) — in the SAME order the stored array carries it within each RENDERED OUTPUT,
/// never re-sorted: unlike <see cref="FingerprintComponents"/>' cross-ROW sort (a real defence
/// against non-deterministic SQL row order), the WITHIN-one-column array order is itself rendered
/// — the first asserted <c>cpe</c> takes the native field, and the <c>swhid</c>/<c>omniborId</c>
/// arrays each emit in stored order. Hashes are the narrower case: <see cref="BuildComponentHashes"/>
/// renders the asserted set into TWO separate JSON outputs (native <c>hashes[]</c> and the
/// disclosed <c>dependably:asserted-hashes</c> property), so only each OUTPUT's own internal
/// order is rendered — the interleaving BETWEEN the two outputs is not one rendered sequence, and
/// treating it as one (fingerprinting a single combined list) would bump <c>version</c> for a
/// reordering that changes nothing rendered, the SAME defect from the opposite direction; see
/// <see cref="FingerprintAssertedHashes"/>'s own doc comment for the two-partition fix.</para>
///
/// <para>Two narrower gaps in the same family: the D13a <c>dependably:identifier-status</c>
/// absence property fires off the FULL parsed identifier list's count
/// (<c>c.Purl is null &amp;&amp; additionalIdentifiers.Count == 0</c> in
/// <see cref="BuildComponentProperties"/>), not the rendered SUBSET above — an unrecognised-kind
/// entry changes that count, and so the property's presence, on a purl-less component even though
/// it renders nowhere itself, which is why <see cref="FingerprintComponent"/> also fingerprints
/// <c>identifierStatusAbsent</c> computed the identical way. And <c>ownHash</c> (dependably's own
/// digest) is fingerprinted only when it passes <see cref="IsAsciiHex"/>, mirroring
/// <see cref="BuildComponentHashes"/>' own <c>validOwn</c> gate — that method's own doc comment
/// notes a blank non-NULL <c>content_hash</c> legitimately reaches here and is invalid, so two
/// different invalid values (which render nothing, either way) must not be distinguishable to the
/// fingerprint.</para>
///
/// <para><b>Decision — the fingerprint covers the org's signing POSTURE (a boolean), never the
/// rendered <c>dependably:signature-state</c> STRING, and never the <c>signature</c> member
/// itself (ADR-sbom-author-signature).</b> <see cref="ComputeContentFingerprint"/>/
/// <see cref="ComputeVexContentFingerprint"/> fold in <c>orgHasActiveKey</c> — whether the org has
/// an active signing key ANYWHERE in the fleet
/// (<see cref="Sbom.SbomSigningKeyRepository.HasActiveKeyAsync"/>) — on the same footing as
/// <c>metadata.authors</c>/<c>metadata.tools</c> in <see cref="FingerprintProvenance"/> just
/// above: a key genuinely appearing (an operator sets <c>DEPENDABLY_MASTER_KEY</c> for the first
/// time) or disappearing for the org is a real change to what every subsequent render can
/// honestly claim, so it bumps the org's open documents exactly once — the CISA D2/D9 case this
/// decision exists for.
///
/// <para>The rendered STRING is a different, WIDER fact than the boolean: <see cref="Sbom.SbomAuthorSigner.SignedState"/>
/// vs <see cref="Sbom.SbomAuthorSigner.UnsignedKeyUnavailableState"/> depends on which replica of
/// a mixed fleet happened to answer THIS request, not on anything the org's data or configuration
/// changed — see <see cref="Sbom.SbomAuthorSigner.ResolveAsync"/>'s own doc comment. Folding the
/// STRING into the fingerprint (an earlier version of this decision did exactly that) turns a
/// load-balancer's routing choice into a fingerprint input: alternating which replica serves the
/// SAME org's SAME data bumps <c>version</c> on every single request, unbounded, and
/// <see cref="DeriveChangedAt"/> leaves <c>metadata.timestamp</c> frozen throughout (nothing about
/// the underlying DATA changed), so the churn is invisible to a consumer sanity-checking the
/// timestamp against the version — a render counter hiding behind a document-identity field,
/// exactly what D9 exists to prevent. <see cref="Sbom.SbomAuthorSigner.UnsignedKeyUnavailableState"/>
/// is therefore a DEGRADED-RENDER marker, not a claim about the software or the org's posture —
/// the same category as <c>dependably:last-scan-at</c> and every other rendered-but-unfingerprinted
/// freshness value this file's class doc comment already excludes above. Both
/// <see cref="Sbom.SbomAuthorSigner.SignedState"/> and <see cref="Sbom.SbomAuthorSigner.UnsignedKeyUnavailableState"/>
/// map to <c>orgHasActiveKey = true</c>; only <see cref="Sbom.SbomAuthorSigner.UnsignedNoMasterKeyState"/>
/// maps to <c>false</c>.</para>
///
/// <para>The <c>signature</c> member itself — <c>value</c>, <c>keyId</c>, <c>algorithm</c>,
/// <c>publicKey</c> — is excluded from the fingerprint in its entirety, and this is structural,
/// not a preference: JSF's own canonicalization rule excludes only the envelope's <c>value</c>
/// from what gets signed, which means the signature is computed over a document that must
/// already be complete — including its <c>serialNumber</c>/<c>version</c>, which
/// <see cref="ResolveRevisionAsync"/> resolves from THIS fingerprint before <c>Attach</c> ever
/// runs. Feeding any part of the envelope back into the fingerprint that gates whether
/// <c>serialNumber</c>/<c>version</c> change would make the attestation one of the facts it
/// attests to — circular, not merely redundant. This holds for <c>keyId</c> too, even though it
/// is a stable, human-legible fact: it lives inside the signed envelope and describes the
/// attestation, not the component/vulnerability data the revision line otherwise tracks.
/// Concretely, rotating the org's active signing key does NOT move the revision — a rotation
/// re-attests identical facts under a new key (<c>orgHasActiveKey</c> stays <c>true</c>
/// throughout), it does not edit data ABOUT the target component the way CISA's own D9e version
/// trigger is written. A served document's <c>signature.keyId</c> can therefore differ between
/// two documents both reporting the same <c>(serial, version)</c>; that is an accepted
/// consequence of keeping the fingerprint over asserted CONTENT rather than over attestation
/// metadata, not an oversight — see
/// <c>SbomExportRevisionIdentityTests.KeyRotation_DoesNotMoveRevision_SignatureKeyIdChangesAnyway</c>.</para>
///
/// <para>A note for the NEXT time a fingerprint input changes here: every already-persisted
/// document's first export under the new build bumps <c>version</c> by exactly one, with
/// <c>serialNumber</c>/<c>metadata.timestamp</c> unchanged and no document content different —
/// the expected one-time cost of a corrected fingerprint, not a regression. During a blue-green
/// cutover this is not one bump: a replica still on the previous build computes the OLD
/// fingerprint and one on the new build computes the NEW one, so a request alternating between
/// replicas bumps <c>version</c> per request until every replica runs the new code. The general
/// problem — the fingerprint has no notion of ITS OWN formula version, so two concurrently-running
/// builds disagree about what "unchanged" means — is not solved here; see
/// <see cref="DependablyToolIdentity"/>'s own inclusion in <see cref="FingerprintProvenance"/> for
/// the same failure mode on a different axis.</para>
/// </summary>
public sealed partial class SbomExportService
{
    private const string DocKindVdr = "vdr";
    private const string DocKindVex = "vex";

    private readonly record struct RevisionIdentity(string SerialNumber, int Revision, string ChangedAtIso);

    // Internal DTO for raw DB rows. Dapper sets props by reflection.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets these props by reflection; not statically visible as used.")]
    private sealed class RevisionRow
    {
        public string Id { get; set; } = "";
        public string SerialNumber { get; set; } = "";
        public int Revision { get; set; }
        public string ContentFingerprint { get; set; } = "";
        public string ChangedAt { get; set; } = "";
    }

    /// <summary>
    /// Resolves the stable revision identity for one (project version, doc kind, format, scope)
    /// document, minting it on first render and bumping <c>revision</c> only when
    /// <paramref name="contentFingerprint"/> differs from the last stored one.
    /// <paramref name="derivedChangedAtIso"/> is D6a's "last changed" instant — computed by the
    /// caller from the data itself (component/link/analysis timestamps), never from the render
    /// clock; see <see cref="DeriveChangedAt"/>. It is used as-is only when this call is the one
    /// that mints the row or the one that bumps it; an unchanged render always returns the
    /// PREVIOUSLY stored <c>changed_at</c>, never a freshly derived value that happens to differ
    /// only because an unrelated freshness stamp ticked forward (see the class doc comment).
    ///
    /// <para>The insert races a concurrent first render of the identical document shape with
    /// <c>ON CONFLICT … DO NOTHING</c> — standard syntax on both SQLite (3.24+) and Postgres, so
    /// no provider branch is needed here. Either writer's serial is equally valid; the loser
    /// simply reads the winner's row back. This mint half is create-once/never-mutate, the same
    /// shape as <c>HexSigningKeyRepository</c>'s own <c>ON CONFLICT DO NOTHING</c> mint — but that
    /// precedent covers ONLY this half. The bump below has no analogue there, because a signing
    /// key has no counter to race.</para>
    ///
    /// <para>The bump is an atomic, relative <c>SET revision = revision + 1</c> guarded by
    /// <c>content_fingerprint = @observedFingerprint</c> — an optimistic-concurrency token, not a
    /// second read of the same fact the WHERE clause already pins. Two concurrent exporters
    /// reading the same stale fingerprint can each compute a bump, but only the first UPDATE
    /// matches the guard; the second's <c>rowsAffected</c> is 0, and the loop re-reads the row
    /// (now carrying the winner's fingerprint) before deciding whether ITS OWN fingerprint still
    /// represents a change. An absolute <c>SET revision = @nextRevision</c> computed from a value
    /// read outside the transaction cannot make this guarantee: two writers can compute the same
    /// "current + 1" from a stale read and one write can silently overwrite the other's higher
    /// value, moving the counter backward under HA multi-replica Postgres.</para>
    /// </summary>
    /// <summary>
    /// The composite key one revision line is kept under — the same tuple
    /// <c>sbom_export_revisions</c>' own uniqueness is declared on. Threaded as one value so a
    /// call site cannot transpose two of the five same-typed strings unnoticed.
    /// </summary>
    private readonly record struct RevisionKey(
        string OrgId, string ProjectVersionId, string DocKind, string Format, string ScopeFilter);

    private static async Task<RevisionIdentity> ResolveRevisionAsync(
        DbConnection conn, RevisionKey key, string contentFingerprint, string derivedChangedAtIso,
        CancellationToken ct)
    {
        var (orgId, projectVersionId, docKind, format, scopeFilter) = key;

        await conn.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO sbom_export_revisions
                (id, org_id, project_version_id, doc_kind, format, scope_filter,
                 serial_number, revision, content_fingerprint, changed_at)
            VALUES (@id, @orgId, @projectVersionId, @docKind, @format, @scopeFilter,
                    @serialNumber, 1, @contentFingerprint, @derivedChangedAtIso)
            ON CONFLICT (project_version_id, doc_kind, format, scope_filter) DO NOTHING
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId,
                projectVersionId,
                docKind,
                format,
                scopeFilter,
                // RFC 9562: Guid.NewGuid() is a v4 UUID. Minted here only when this INSERT is the
                // one that wins the race; a losing writer's guid is discarded when the SELECT
                // below reads the winner's row back instead.
                serialNumber = $"urn:uuid:{Guid.NewGuid()}",
                contentFingerprint,
                derivedChangedAtIso,
            },
            cancellationToken: ct));

        while (true)
        {
            var row = await conn.QuerySingleAsync<RevisionRow>(new CommandDefinition(
                """
                SELECT id AS Id, serial_number AS SerialNumber, revision AS Revision,
                       content_fingerprint AS ContentFingerprint, changed_at AS ChangedAt
                FROM sbom_export_revisions
                WHERE org_id = @orgId AND project_version_id = @projectVersionId AND doc_kind = @docKind
                  AND format = @format AND scope_filter = @scopeFilter
                """,
                new { orgId, projectVersionId, docKind, format, scopeFilter }, cancellationToken: ct));

            if (string.Equals(row.ContentFingerprint, contentFingerprint, StringComparison.Ordinal))
            {
                // Unchanged since the last render (whether that was this INSERT just now, or an
                // earlier one): same serial, same revision, same changed_at — two exports of
                // unchanged data must be indistinguishable, not merely similar.
                return new RevisionIdentity(row.SerialNumber, row.Revision, row.ChangedAt);
            }

            int rowsAffected = await conn.ExecuteAsync(new CommandDefinition(
                """
                UPDATE sbom_export_revisions
                SET revision = revision + 1, content_fingerprint = @contentFingerprint,
                    changed_at = @derivedChangedAtIso
                WHERE id = @id AND org_id = @orgId AND content_fingerprint = @observedFingerprint
                """,
                new
                {
                    contentFingerprint,
                    derivedChangedAtIso,
                    id = row.Id,
                    orgId,
                    observedFingerprint = row.ContentFingerprint,
                },
                cancellationToken: ct));

            if (rowsAffected == 1)
            {
                return new RevisionIdentity(row.SerialNumber, row.Revision + 1, derivedChangedAtIso);
            }

            // Lost the race: another exporter's UPDATE landed between our SELECT and ours. Loop
            // and re-read — our own contentFingerprint may or may not still represent a change
            // against whatever the winner just stored.
        }
    }

    /// <summary>
    /// D6a (SBOM Timestamp): the instant the underlying DATA last changed, derived from the actual
    /// rows the fingerprint covers rather than stamped from the render clock — a render is not a
    /// change. <paramref name="floor"/> is <c>project_versions.created_at</c>, the earliest a
    /// version's data could have changed (and the only candidate at all for a version with no
    /// components yet); each <paramref name="sources"/> sequence contributes its own real,
    /// already-stored timestamp column (<c>sbom_components.created_at</c>,
    /// <c>sbom_component_vulns.checked_at</c>, <c>project_vuln_analysis.updated_at</c>) and the
    /// MAX across all of them is the answer. A component row updated in place by a re-ingest that
    /// changes a field <c>UpdateComponentAsync</c> writes (without inserting a new row) does not
    /// move <c>created_at</c> — <c>sbom_components</c> has no <c>updated_at</c> column — so this
    /// derivation can under-report a changed_at for that narrow path; <c>content_fingerprint</c>
    /// still bumps <c>revision</c> correctly in that case; only the reported instant can lag. This
    /// is a known, documented limitation of the data this method has to work with, not a silent
    /// approximation.
    /// </summary>
    /// <summary>
    /// D6a for a single project version's document: the MAX of the version's own created_at and
    /// every timestamp column the fingerprint covers, rendered as the stored ISO instant. Wraps
    /// <see cref="DeriveChangedAt"/> so the caller names the rows rather than re-listing which
    /// column of each carries the instant.
    /// </summary>
    private static string DeriveDocumentChangedAt(
        ResolvedVersion resolved, IReadOnlyList<ComponentRow> components,
        IReadOnlyList<ComponentVulnRow> vulnRows, IReadOnlyList<AnalysisRow> analysisRows) =>
        DeriveChangedAt(
            resolved.CreatedAt,
            components.Select(c => (DateTimeOffset?)c.CreatedAt),
            vulnRows.Select(v => (DateTimeOffset?)v.LinkCheckedAt),
            analysisRows.Select(a => (DateTimeOffset?)a.UpdatedAt)).ToUtcIso();

    private static DateTimeOffset DeriveChangedAt(DateTimeOffset floor, params IEnumerable<DateTimeOffset?>[] sources)
    {
        var max = floor;
        foreach (var source in sources)
        {
            foreach (var candidate in source)
            {
                if (candidate is DateTimeOffset value && value > max)
                {
                    max = value;
                }
            }
        }

        return max;
    }

    /// <summary>
    /// The content-fingerprint input for one component — every field <see cref="BuildComponentObject"/>
    /// turns into an assertion, minus <c>sbom_components.id</c> (an internal database key the
    /// document never asserts; identity is the purl/name+version already in the object) and minus
    /// <see cref="ComponentRow.VulnCheckedAt"/> (freshness-only — see this file's class doc
    /// comment). <c>ecosystem</c>/<c>purlName</c> are included only when
    /// <paramref name="includePurlIdentity"/> is set — see the class doc comment for why the
    /// <c>vdr</c> line needs them and the <c>inventory</c> line does not.
    /// </summary>
    private static JsonObject FingerprintComponent(
        ComponentRow c, IReadOnlyDictionary<string, bool> installScriptByComponentId,
        IReadOnlyDictionary<string, string> ownHashByComponentId, bool includePurlIdentity)
    {
        var obj = new JsonObject
        {
            ["ref"] = c.Purl ?? c.Name,
            ["name"] = c.Name,
        };
        AddIfNotNull(obj, "version", c.Version);
        if (includePurlIdentity)
        {
            AddIfNotNull(obj, "ecosystem", c.Ecosystem);
            AddIfNotNull(obj, "purlName", c.PurlName);
        }

        AddIfNotNull(obj, "componentType", c.ComponentType);
        AddIfNotNull(obj, "sbomScope", c.SbomScope);
        AddIfNotNull(obj, "dependencyKind", c.DependencyKind);
        AddIfNotNull(obj, "dependencyScope", c.DependencyScope);
        AddIfNotNull(obj, "dependencyPath", c.DependencyPath);
        AddIfNotNull(obj, "licenseSpdx", c.LicenseSpdx);
        AddIfNotNull(obj, "licenseUrl", c.LicenseUrl);
        if (c.LicenseNamed is bool licenseNamed)
        {
            obj["licenseNamed"] = licenseNamed;
        }

        AddIfNotNull(obj, "versionRange", c.VersionRange);
        if (c.IsExternal is bool isExternal)
        {
            obj["isExternal"] = isExternal;
        }

        AddIfNotNull(obj, "componentProducer", c.ComponentProducer);

        // Mirrors BuildComponentHashes' OWN validOwn condition: a stored digest that fails
        // ASCII-hex validation (BuildComponentHashes' doc comment notes a blank non-NULL
        // content_hash legitimately reaches here) is never emitted anywhere in the rendered
        // document, so two different invalid values must not be distinguishable to the
        // fingerprint either. Resolved BEFORE FingerprintAssertedHashes below because whether an
        // own digest is present changes how BuildComponentHashes partitions the ASSERTED hashes
        // too — see that method's own doc comment.
        string? rawOwnHash = ownHashByComponentId.GetValueOrDefault(c.Id);
        string? ownHash = rawOwnHash is not null && IsAsciiHex(rawOwnHash) ? rawOwnHash : null;
        AddIfNotNull(obj, "ownHash", ownHash);
        AddIfNotNull(obj, "componentHashes", FingerprintAssertedHashes(c.ComponentHashes, hasOwnHash: ownHash is not null));

        var fullIdentifiers = ParseAdditionalIdentifiers(c.AdditionalIdentifiers);
        AddIfNotNull(obj, "additionalIdentifiers", FingerprintAdditionalIdentifiers(fullIdentifiers));
        // D13a: mirrors BuildComponentProperties' OWN identifier-status absence condition exactly
        // (`c.Purl is null && additionalIdentifiers.Count == 0`, read against the FULL parsed
        // list, not the rendered subset above) — an unrecognised-kind entry does not render as a
        // native field or a dependably:identifier:* property, but it DOES flip whether the
        // dependably:identifier-status absence property itself appears on a purl-less component,
        // which is a real rendered change the filtered array above cannot see.
        obj["identifierStatusAbsent"] = c.Purl is null && fullIdentifiers.Count == 0;
        if (installScriptByComponentId.GetValueOrDefault(c.Id))
        {
            obj["installScript"] = true;
        }

        return obj;
    }

    /// <summary>
    /// The kinds <see cref="BuildComponentObject"/>/<see cref="BuildComponentProperties"/>
    /// actually place somewhere in a rendered document — natively (<c>cpe</c>/<c>swhid</c>/
    /// <c>omniborId</c>) or disclosed (<c>dependably:identifier:*</c>). An entry
    /// <see cref="ParseAdditionalIdentifiers"/> keeps but neither method recognises contributes
    /// nothing to the rendered SUBSET below today and must contribute nothing to it either — see
    /// the class doc comment's "rendered, not stored" paragraph. <b>Kept as an explicit hand-list,
    /// deliberately NOT derived from <see cref="Sbom.SbomIdentifierKinds"/> by reflection:</b> that
    /// class is the ingest-write vocabulary (what a parser is ALLOWED to store) — its own doc
    /// comment describes a kind landing there specifically so a later export revision can start
    /// reading it without a backfill. Deriving this render-side set from it would make a kind
    /// "fingerprinted" from the moment ingest starts writing it, before <see cref="BuildComponentObject"/>/
    /// <see cref="BuildComponentProperties"/> render it anywhere — reintroducing the SAME "version
    /// bumps with no rendered change" defect from the opposite direction. This list must be
    /// updated by hand, in the same change, whenever a kind's actual render status changes.
    /// </summary>
    private static readonly IReadOnlySet<string> RenderedIdentifierKinds = new HashSet<string>(StringComparer.Ordinal)
    {
        Sbom.SbomIdentifierKinds.Cpe, Sbom.SbomIdentifierKinds.Swhid, Sbom.SbomIdentifierKinds.Omnibor,
        Sbom.SbomIdentifierKinds.CommitHash, Sbom.SbomIdentifierKinds.Uuid,
    };

    /// <summary>
    /// The fingerprint input for <c>sbom_components.component_hashes</c>: every asserted entry
    /// that <see cref="ParseAssertedHashes"/> accepts (passes ASCII-hex validation), with the
    /// SAME cross-format alias translation <see cref="BuildComponentHashes"/> applies — an entry
    /// that fails validation never reaches any render and must not move the fingerprint either.
    ///
    /// <para><b>Fingerprinted as TWO separately-ordered partitions, mirroring
    /// <see cref="BuildComponentHashes"/>'s OWN partitioning exactly, never as one combined
    /// list.</b> That method renders two SEPARATE JSON outputs — the native <c>hashes[]</c> array
    /// and the disclosed <c>dependably:asserted-hashes</c> property — so each output's OWN
    /// relative order is rendered (a document differing only in which entry comes first WITHIN
    /// one of those two outputs is a real rendered difference), but which entry lands in which
    /// output, relative to the other output's entries, is not one combined rendered sequence — it
    /// is two independent ones. <paramref name="hasOwnHash"/> selects the SAME branch
    /// <see cref="BuildComponentHashes"/> takes: when dependably's own digest occupies the native
    /// slot, EVERY asserted entry — regardless of hash-alg enum membership — is disclosed
    /// together, in stored order (that method's <c>validOwn is not null</c> arm); otherwise the
    /// asserted set itself splits by hash-alg enum membership, native first, disclosed-only
    /// second, each keeping its own relative order. Both arms decide membership against
    /// <see cref="HashAlgEnum17"/> — never the rendering document's own (possibly narrower 1.6)
    /// enum — because <c>specVersion</c> is deliberately out of the revision key (see the class
    /// doc comment): a partition boundary that moved with specVersion would make a 1.6 and a 1.7
    /// render of unchanged data compute different fingerprints and fight over one revision line,
    /// the same alternating-oscillator failure the "signature identity" decision above exists to
    /// avoid on the signing axis.</para>
    /// </summary>
    // Null omits the key entirely via AddIfNotNull; an empty object would enter the fingerprint as a
    // real member and bump the revision on unchanged data.
    [SuppressMessage("Major Code Smell", "S1168:Empty arrays and collections should be returned instead of null",
        Justification = "Null is absence, not emptiness: an empty value here would be emitted as a real entry and change the result.")]
    private static JsonObject? FingerprintAssertedHashes(string? componentHashesJson, bool hasOwnHash)
    {
        var asserted = ParseAssertedHashes(componentHashesJson)
            .Select(h => (Alg: AssertedAlgAliases.GetValueOrDefault(h.Alg, h.Alg), h.Content))
            .ToList();

        return asserted.Count == 0
            ? null
            : hasOwnHash
                ? new JsonObject { ["disclosed"] = HashesToJsonArray(asserted) }
                : new JsonObject
                {
                    ["native"] = HashesToJsonArray(asserted.Where(h => HashAlgEnum17.Contains(h.Alg))),
                    ["disclosed"] = HashesToJsonArray(asserted.Where(h => !HashAlgEnum17.Contains(h.Alg))),
                };
    }

    private static JsonArray HashesToJsonArray(IEnumerable<(string Alg, string Content)> entries)
    {
        var arr = new JsonArray();
        foreach (var (alg, content) in entries)
        {
            arr.Add(new JsonObject { ["alg"] = alg, ["content"] = content });
        }

        return arr;
    }

    /// <summary>
    /// The fingerprint input for <c>sbom_components.additional_identifiers</c>: every entry of
    /// <paramref name="parsed"/> (the FULL parse — see <see cref="FingerprintComponent"/>, which
    /// also needs the full list's COUNT for the D13a identifier-status condition) whose kind
    /// <see cref="RenderedIdentifierKinds"/> names. <b>Preserves the stored array's own order</b>
    /// for the same reason <see cref="FingerprintAssertedHashes"/> does: the FIRST cpe entry takes
    /// the native <c>cpe</c> field (<c>identifiers.FirstOrDefault</c> in
    /// <see cref="BuildComponentObject"/>, mirrored by the <c>firstCpeEmittedNatively</c> loop in
    /// <see cref="BuildComponentProperties"/>), and the <c>swhid</c>/<c>omniborId</c> native
    /// arrays render in stored order too — reordering two stored entries changes WHICH cpe value a
    /// consumer resolves natively, a real rendered change a sorted fingerprint would miss.
    /// </summary>
    // Null omits the key entirely via AddIfNotNull; an empty array would enter the fingerprint as a
    // real member and bump the revision on unchanged data.
    [SuppressMessage("Major Code Smell", "S1168:Empty arrays and collections should be returned instead of null",
        Justification = "Null is absence, not emptiness: an empty value here would be emitted as a real entry and change the result.")]
    private static JsonArray? FingerprintAdditionalIdentifiers(IReadOnlyList<(string Kind, string Value)> parsed)
    {
        var entries = parsed.Where(i => RenderedIdentifierKinds.Contains(i.Kind)).ToList();
        if (entries.Count == 0)
        {
            return null;
        }

        var arr = new JsonArray();
        foreach (var (kind, value) in entries)
        {
            arr.Add(new JsonObject { ["kind"] = kind, ["value"] = value });
        }

        return arr;
    }

    /// <summary>
    /// The content-fingerprint input for one component set, sorted by its own ref rather than
    /// trusting the caller's (SQL-supplied) ordering — a hash must not depend on row order the
    /// database is free to change between two otherwise-identical reads.
    /// </summary>
    /// <summary>
    /// The component-side inputs a content fingerprint hashes, threaded as one value so the
    /// fingerprint and the component array it covers cannot drift apart.
    /// </summary>
    private readonly record struct ComponentFingerprintInputs(
        IReadOnlyList<ComponentRow> Components,
        IReadOnlyDictionary<string, bool> InstallScriptByComponentId,
        IReadOnlyDictionary<string, string> OwnHashByComponentId,
        bool IncludePurlIdentity);

    /// <summary>
    /// Who produced the document: this org, plus the uploaded document's own tool identity when it
    /// declared one.
    /// </summary>
    private readonly record struct ProvenanceIdentity(
        string OrgSlug, string? OriginalToolName, string? OriginalToolVersion);

    private static JsonArray FingerprintComponents(ComponentFingerprintInputs inputs)
    {
        var (components, installScriptByComponentId, ownHashByComponentId, includePurlIdentity) = inputs;
        var arr = new JsonArray();
        foreach (var c in components
                     .OrderBy(c => c.Purl ?? c.Name, StringComparer.Ordinal)
                     .ThenBy(c => c.Version, StringComparer.Ordinal))
        {
            arr.Add(FingerprintComponent(c, installScriptByComponentId, ownHashByComponentId, includePurlIdentity));
        }

        return arr;
    }

    /// <summary>
    /// One vulnerability finding's content-fingerprint input, shared by the <c>vdr</c> and
    /// standalone-<c>vex</c> producers — the same rating/KEV/EPSS/SSVC/analysis fields, keyed by
    /// whichever component reference the calling producer resolves it against (a bare purl for
    /// <c>vdr</c>, a purl_key for a standalone VEX document), PLUS the three component-derived
    /// facts (<see cref="EffectivePriority"/>'s dependency-context inputs) that feed the rendered
    /// entry's own <c>properties[]</c> — see the class doc comment for why a VEX document needs
    /// these despite asserting no <c>components[]</c> array. <c>*CheckedAt</c>/<c>*AssertedAt</c>
    /// freshness stamps and the affected-application count are excluded — see this file's class
    /// doc comment.
    /// </summary>
    private readonly record struct VulnFingerprintFacts(
        string ComponentRef, string OsvId, string? Severity, double? CvssScore, double? NvdScore,
        bool IsKev, bool? IsKevRansomware, string? KevDueDate, string? KevDateAdded,
        string? KevRequiredAction, string? KevCwes, string? KevNotes, double? EpssScore,
        double? EpssPercentile, string? SsvcExploitation, string? SsvcAutomatable,
        string? SsvcTechnicalImpact, bool IsMalicious, string? DependencyKind, string? DependencyScope,
        bool HasInstallScript, string? VexState, string? VexJustification, string? VexResponse,
        string? VexDetail, string? Reachability);

    private static JsonObject FingerprintVuln(VulnFingerprintFacts f)
    {
        var obj = new JsonObject { ["ref"] = f.ComponentRef, ["id"] = f.OsvId };
        AddIfNotNull(obj, "severity", f.Severity);
        AddIfNotNull(obj, "cvssScore", f.CvssScore);
        AddIfNotNull(obj, "nvdScore", f.NvdScore);
        obj["isKev"] = f.IsKev;
        if (f.IsKevRansomware is bool ransomware)
        {
            obj["isKevRansomware"] = ransomware;
        }

        AddIfNotNull(obj, "kevDueDate", f.KevDueDate);
        AddIfNotNull(obj, "kevDateAdded", f.KevDateAdded);
        AddIfNotNull(obj, "kevRequiredAction", f.KevRequiredAction);
        AddIfNotNull(obj, "kevCwes", f.KevCwes);
        AddIfNotNull(obj, "kevNotes", f.KevNotes);
        AddIfNotNull(obj, "epssScore", f.EpssScore);
        AddIfNotNull(obj, "epssPercentile", f.EpssPercentile);
        AddIfNotNull(obj, "ssvcExploitation", f.SsvcExploitation);
        AddIfNotNull(obj, "ssvcAutomatable", f.SsvcAutomatable);
        AddIfNotNull(obj, "ssvcTechnicalImpact", f.SsvcTechnicalImpact);
        obj["isMalicious"] = f.IsMalicious;
        AddIfNotNull(obj, "dependencyKind", f.DependencyKind);
        AddIfNotNull(obj, "dependencyScope", f.DependencyScope);
        obj["hasInstallScript"] = f.HasInstallScript;
        AddIfNotNull(obj, "vexState", f.VexState);
        AddIfNotNull(obj, "vexJustification", f.VexJustification);
        AddIfNotNull(obj, "vexResponse", f.VexResponse);
        AddIfNotNull(obj, "vexDetail", f.VexDetail);
        AddIfNotNull(obj, "reachability", f.Reachability);
        return obj;
    }

    private static JsonArray FingerprintVulns(IEnumerable<VulnFingerprintFacts> facts)
    {
        var arr = new JsonArray();
        foreach (var f in facts.OrderBy(f => f.ComponentRef, StringComparer.Ordinal)
                     .ThenBy(f => f.OsvId, StringComparer.Ordinal))
        {
            arr.Add(FingerprintVuln(f));
        }

        return arr;
    }

    /// <summary>
    /// <c>vdr</c>'s vulnerability fingerprint facts, resolved the identical way
    /// <see cref="BuildVulnerabilitiesArray"/> resolves each row's analysis block (direct
    /// purl_key/osv_id match, falling back through the advisory's own aliases) — the fingerprint
    /// must see the same analysis state the rendered document does, or a VEX-only edit (no
    /// component or finding change) would go undetected. Named arguments throughout: the record
    /// carries many same-typed fields in a row, and a positional call site reorders silently on an
    /// edit.
    /// </summary>
    private static IEnumerable<VulnFingerprintFacts> VdrVulnFingerprintFacts(
        IReadOnlyList<ComponentVulnRow> vulnRows, IReadOnlyList<AnalysisRow> analysisRows,
        IReadOnlyDictionary<string, bool> installScriptByComponentId)
    {
        var analysisByKey = analysisRows.ToDictionary(a => (a.PurlKey, a.VulnKey), SbomVulnKeyComparer.Instance);
        foreach (var v in vulnRows)
        {
            string? purlKey = SbomPurlKey.ForComponent(v.Ecosystem, v.PurlName, v.ComponentPurl);
            var analysis = purlKey is null ? null : FindAnalysis(analysisByKey, purlKey, v.OsvId, v.Aliases);
            yield return new VulnFingerprintFacts(
                ComponentRef: v.ComponentPurl,
                OsvId: v.OsvId,
                Severity: v.Severity,
                CvssScore: v.CvssScore,
                NvdScore: v.NvdScore,
                IsKev: v.IsKev,
                IsKevRansomware: v.IsKevRansomware,
                KevDueDate: v.KevDueDate,
                KevDateAdded: v.KevDateAdded,
                KevRequiredAction: v.KevRequiredAction,
                KevCwes: v.KevCwes,
                KevNotes: v.KevNotes,
                EpssScore: v.EpssScore,
                EpssPercentile: v.EpssPercentile,
                SsvcExploitation: v.SsvcExploitation,
                SsvcAutomatable: v.SsvcAutomatable,
                SsvcTechnicalImpact: v.SsvcTechnicalImpact,
                IsMalicious: v.IsMalicious,
                DependencyKind: v.DependencyKind,
                DependencyScope: v.DependencyScope,
                HasInstallScript: installScriptByComponentId.GetValueOrDefault(v.ComponentId),
                VexState: analysis?.VexState,
                VexJustification: analysis?.VexJustification,
                VexResponse: analysis?.VexResponse,
                VexDetail: analysis?.VexDetail,
                Reachability: analysis?.Reachability);
        }
    }

    /// <summary>
    /// A standalone VEX document's vulnerability fingerprint facts — every <c>withState</c> row,
    /// keyed by its own purl_key rather than a component purl, matching what the document itself
    /// asserts (<c>affects[].ref</c> is the purl_key for this producer). Resolves each row's
    /// component through <paramref name="componentByPurlKey"/> — the SAME map
    /// <c>BuildVexEntry</c> reads from — so <c>DependencyKind</c>/<c>DependencyScope</c>/
    /// <c>HasInstallScript</c> mirror exactly what fed the rendered entry's own priority.
    /// </summary>
    private static IEnumerable<VulnFingerprintFacts> VexVulnFingerprintFacts(
        IReadOnlyList<AnalysisRow> withState, IReadOnlyDictionary<string, VulnLookupRow> known,
        IReadOnlyDictionary<string, ComponentRow> componentByPurlKey,
        IReadOnlyDictionary<string, bool> installScriptFacts)
    {
        foreach (var a in withState)
        {
            known.TryGetValue(a.VulnKey, out var lookup);
            componentByPurlKey.TryGetValue(a.PurlKey, out var component);
            yield return new VulnFingerprintFacts(
                ComponentRef: a.PurlKey,
                OsvId: a.VulnKey,
                Severity: lookup?.Severity,
                CvssScore: lookup?.CvssScore,
                NvdScore: lookup?.NvdScore,
                IsKev: lookup?.IsKev ?? false,
                IsKevRansomware: lookup?.IsKevRansomware,
                KevDueDate: lookup?.KevDueDate,
                KevDateAdded: lookup?.KevDateAdded,
                KevRequiredAction: lookup?.KevRequiredAction,
                KevCwes: lookup?.KevCwes,
                KevNotes: lookup?.KevNotes,
                EpssScore: lookup?.EpssScore,
                EpssPercentile: lookup?.EpssPercentile,
                SsvcExploitation: lookup?.SsvcExploitation,
                SsvcAutomatable: lookup?.SsvcAutomatable,
                SsvcTechnicalImpact: lookup?.SsvcTechnicalImpact,
                IsMalicious: lookup?.IsMalicious ?? false,
                DependencyKind: component?.DependencyKind,
                DependencyScope: component?.DependencyScope,
                HasInstallScript: component is not null && installScriptFacts.GetValueOrDefault(component.Id),
                VexState: a.VexState,
                VexJustification: a.VexJustification,
                VexResponse: a.VexResponse,
                VexDetail: a.VexDetail,
                Reachability: a.Reachability);
        }
    }

    /// <summary>
    /// D1/D7/D8's provenance claims, as fingerprint input: the tenant author string and the tool
    /// chain (the uploaded document's own original tool, when one is named, and dependably's own
    /// running version — see <see cref="DependablyToolIdentity"/>). Both are genuinely ASSERTED
    /// content (<c>metadata.authors</c>/<c>metadata.tools</c>), so a CI generator upgrade that
    /// changes nothing else, or a tenant rename, is a real change to what the document says — see
    /// the class doc comment. Folding in dependably's OWN version means an operator upgrade also
    /// bumps every open document's NEXT render; that follows from the same premise, not a special
    /// case of it.
    /// </summary>
    private static JsonObject FingerprintProvenance(ProvenanceIdentity provenance)
    {
        var (orgSlug, originalToolName, originalToolVersion) = provenance;
        var obj = new JsonObject
        {
            ["author"] = orgSlug,
            ["dependablyToolVersion"] = DependablyToolIdentity.Version,
        };
        AddIfNotNull(obj, "originalToolName", originalToolName);
        AddIfNotNull(obj, "originalToolVersion", originalToolVersion);
        return obj;
    }

    /// <summary>
    /// Hashes exactly the facts a document asserts: provenance (see
    /// <see cref="FingerprintProvenance"/>), the org's signing POSTURE (see
    /// <paramref name="orgHasActiveKey"/> and the class doc comment's "signature identity"
    /// decision — the rendered <c>dependably:signature-state</c> STRING and the <c>signature</c>
    /// member itself are both deliberately NOT hashed here), the component set/graph, plus (when
    /// <paramref name="vulns"/> is non-null) the vulnerability findings and their analysis state.
    /// See this file's class doc comment for what else is deliberately excluded and why.
    /// </summary>
    private static string ComputeContentFingerprint(
        ResolvedVersion resolved, ComponentFingerprintInputs componentInputs,
        ProvenanceIdentity provenance, IEnumerable<VulnFingerprintFacts>? vulns, bool orgHasActiveKey)
    {
        var payload = new JsonObject
        {
            ["target"] = new JsonObject
            {
                ["type"] = resolved.Classifier,
                ["name"] = resolved.ProjectName,
                ["version"] = resolved.VersionLabel,
            },
            ["provenance"] = FingerprintProvenance(provenance),
            ["orgHasActiveKey"] = orgHasActiveKey,
            ["components"] = FingerprintComponents(componentInputs),
        };
        if (vulns is not null)
        {
            payload["vulnerabilities"] = FingerprintVulns(vulns);
        }

        return Sha256Hex(payload.ToJsonString());
    }

    /// <summary>
    /// A standalone VEX document's content fingerprint: provenance, the org's signing POSTURE
    /// (see <see cref="ComputeContentFingerprint"/>'s doc comment) and vulnerability findings — it
    /// asserts no <c>components[]</c> array of its own, but see the class doc comment for why
    /// <paramref name="vulns"/> still carries component-derived facts.
    /// </summary>
    private static string ComputeVexContentFingerprint(
        ProvenanceIdentity provenance, IEnumerable<VulnFingerprintFacts> vulns, bool orgHasActiveKey) =>
        Sha256Hex(new JsonObject
        {
            ["provenance"] = FingerprintProvenance(provenance),
            ["orgHasActiveKey"] = orgHasActiveKey,
            ["vulnerabilities"] = FingerprintVulns(vulns),
        }.ToJsonString());

    private static void AddIfNotNull(JsonObject obj, string key, string? value)
    {
        if (value is not null)
        {
            obj[key] = value;
        }
    }

    private static void AddIfNotNull(JsonObject obj, string key, JsonNode? value)
    {
        if (value is not null)
        {
            obj[key] = value;
        }
    }

    private static void AddIfNotNull(JsonObject obj, string key, double? value)
    {
        if (value is not null)
        {
            obj[key] = value.Value;
        }
    }

    private static string Sha256Hex(string content) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content)));
}
