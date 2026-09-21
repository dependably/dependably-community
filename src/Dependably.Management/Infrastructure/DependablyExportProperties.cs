namespace Dependably.Infrastructure;

/// <summary>
/// The one namespace of <c>dependably:</c> CycloneDX property names emitted anywhere in
/// <see cref="SbomExportService"/> — every producer references these constants rather than
/// spelling a property name inline, so a property's spelling can never drift between the
/// per-project VDR/inventory export, the collection export, and the standalone VEX export.
///
/// <para><b>Case is deliberately inconsistent with the four pre-existing collection properties</b>
/// (<c>dependably:aggregate</c> / <c>dependably:selection</c> / <c>dependably:projectCount</c> /
/// <c>dependably:projectsWithoutSbom</c>, camelCase, emitted only by
/// <see cref="SbomExportService.BuildCollectionSbomDocumentAsync"/>). Every property declared here
/// is kebab-case — a single documented property namespace, defined once and reused verbatim,
/// spelled the way this vocabulary's own examples are. Renaming the four pre-existing properties
/// to match would be a breaking change to whatever already consumes an exported collection
/// document; that is out of scope here and the inconsistency is left as-is rather than silently
/// harmonized.</para>
///
/// <para><b>The two CISA-attributed KEV date properties are deliberately not spelled
/// <c>dependably:kev-due-date</c></b>: both dates are CISA's own BOD 22-01 assertions, not a
/// dependably-computed deadline and not necessarily an obligation of the consuming organization.
/// A property name without the <c>cisa-</c> prefix would read as the opposite.</para>
///
/// <para><b>CISA P4/X4's two-state absence vocabulary.</b> Six elements carry an explicit
/// "indicate unknown" duty — Tool Version (D8b), Component Producer (D10e), Hash Value (D14d),
/// Component Licence (D16e), Component Version (D12a), Component Identifier (D13a) — and P4a
/// requires the SAME document to be
/// able to say whether an absent field is unknown TO THE AUTHOR or WITHHELD BY the author; the two
/// are different claims about the same silence. <see cref="UnknownValue"/> is dependably's
/// existing tri-state "no assertion" spelling, already load-bearing elsewhere in this file
/// (<see cref="KevRansomware"/>, <see cref="SsvcExploitation"/>) — reused here rather than
/// invented a second time. <see cref="WithheldValue"/> is its new sibling. dependably does not
/// implement withholding today (nothing in this data model ever marks a field "redacted" rather
/// than "not captured"), so every current call site resolves to <see cref="UnknownValue"/> via
/// <see cref="AbsenceReason"/> — the vocabulary still defines both states, per P4a, so a future
/// withholding feature is a one-line flip at each call site rather than a second vocabulary (P4c's
/// recipient-inquiry-process duty is therefore not owed today either; it activates the day a call
/// site first passes <c>withheld: true</c>). The static-scan compliance gate over this file's own
/// SBOM-export call sites is what makes "no site invents its own spelling" a checked invariant
/// rather than a convention.</para>
/// </summary>
public static class DependablyExportProperties
{
    /// <summary>
    /// X4/P4a: the one call every "indicate unknown" duty site routes through, so the two-state
    /// absence vocabulary is defined once. See the class doc comment for why <paramref name="withheld"/>
    /// is always <c>false</c> today and why the parameter exists anyway.
    /// </summary>
    public static string AbsenceReason(bool withheld = false) => withheld ? WithheldValue : UnknownValue;

    // ── Per-vulnerability ────────────────────────────────────────────────────

    /// <summary>The <see cref="EffectivePriority"/> bucket, derived fresh at export time. Always present.</summary>
    public const string Priority = "dependably:priority";

    /// <summary>
    /// <c>"true"</c>/<c>"false"</c> — whether no CVSS score exists from either the advisory's own
    /// source or the NVD overlay, independent of which rule decided the bucket. Always present, so
    /// a KEV advisory nobody scored reads as <c>priority=act, unscored=true</c> rather than an
    /// empty ratings array a consumer would otherwise read as "not severe".
    /// </summary>
    public const string Unscored = "dependably:unscored";

    /// <summary><c>"true"</c>/<c>"false"</c> — CISA KEV catalogue membership. Always present.</summary>
    public const string Kev = "dependably:kev";

    /// <summary>
    /// Tri-state — <c>"true"</c>, <c>"false"</c> (CISA explicitly asserts no known ransomware use),
    /// or <c>"unknown"</c> (no assertion at all, including "not a KEV entry"). Always present; the
    /// false/unknown distinction must never collapse — see <see cref="VulnFacts.IsKevRansomware"/>.
    /// </summary>
    public const string KevRansomware = "dependably:kev-ransomware";

    /// <summary>
    /// CISA's BOD 22-01 federal remediation due date for this KEV entry (<c>YYYY-MM-DD</c>).
    /// Omitted when null (not KEV-listed, or CISA recorded no due date).
    /// </summary>
    public const string CisaKevDueDate = "dependably:cisa-kev-due-date";

    /// <summary>The date CISA added this entry to the KEV catalogue. Omitted when null.</summary>
    public const string CisaKevDateAdded = "dependably:cisa-kev-date-added";

    /// <summary>
    /// CISA's prescribed remediation step for this KEV entry, in prose. Same <c>cisa-</c> prefix
    /// discipline as the two date properties above — this is CISA's own assertion, not a
    /// dependably-computed recommendation. Omitted when null (not KEV-listed, or CISA recorded
    /// no required action).
    /// </summary>
    public const string CisaKevRequiredAction = "dependably:cisa-kev-required-action";

    /// <summary>
    /// This KEV entry's CWE classification ids, as the stored JSON array text (e.g.
    /// <c>["CWE-79"]</c>). Omitted when null — distinct from an explicit <c>[]</c>, which is
    /// exported as-is when CISA recorded the field with zero classifications.
    /// </summary>
    public const string CisaKevCwes = "dependably:cisa-kev-cwes";

    /// <summary>
    /// Vendor advisory/patch notes CISA recorded for this KEV entry, free text. Omitted when null.
    /// </summary>
    public const string CisaKevNotes = "dependably:cisa-kev-notes";

    /// <summary>FIRST.org EPSS percentile rank (0.0-1.0), as a decimal string. Omitted when null.</summary>
    public const string EpssPercentile = "dependably:epss-percentile";

    /// <summary>
    /// CISA Vulnrichment SSVC exploitation state — <c>"none"</c>/<c>"poc"</c>/<c>"active"</c>, or
    /// <c>"unknown"</c> when the tracker overlay is unconfigured, unreachable, or has not assessed
    /// this advisory. Always present; the per-vulnerability value never distinguishes those three
    /// causes from each other — <see cref="TrackerConfigured"/> is the document-level fact that
    /// lets a consumer interpret an "unknown" here.
    /// </summary>
    public const string SsvcExploitation = "dependably:ssvc-exploitation";

    /// <summary>SSVC automatable assessment — <c>"yes"</c>/<c>"no"</c>. Omitted when null.</summary>
    public const string SsvcAutomatable = "dependably:ssvc-automatable";

    /// <summary>SSVC technical-impact assessment — <c>"partial"</c>/<c>"total"</c>. Omitted when null.</summary>
    public const string SsvcTechnicalImpact = "dependably:ssvc-technical-impact";

    /// <summary>
    /// CVSS score from the optional NVD enrichment overlay. Exposed as its own property rather than
    /// folded into the CycloneDX <c>ratings</c> block, which stays the advisory's own OSV-sourced
    /// score unchanged — dependably does not silently substitute one source into a field that
    /// already has a defined meaning to CycloneDX consumers. A consumer wanting the same
    /// NVD-fallback score <see cref="EffectivePriority"/> ranked against can compute
    /// <c>ratings[0].score ?? nvd-score</c> itself, the same <see cref="VulnFacts.EffectiveCvss"/>
    /// rule this platform applies. Omitted when null.
    /// </summary>
    public const string NvdScore = "dependably:nvd-score";

    /// <summary>
    /// The effective freshness timestamp for the NVD enrichment signal —
    /// <c>COALESCE(nvd_asserted_at, nvd_checked_at)</c>, ISO-8601 UTC — reported so a consumer can
    /// judge staleness against its own horizon rather than dependably baking a threshold into the
    /// document. A stale reading is exported as-is, not suppressed: "stale input is not absent
    /// input" (<c>ARCH-block-gate</c>) applies to the export boundary the same way it applies to
    /// the gate itself — a tracker that answered enthusiastically a month ago still exports that
    /// month-old timestamp rather than reading identically to a signal checked seconds ago.
    /// Omitted when <c>nvd_checked_at</c> is null (no NVD signal at all — an unambiguous absence,
    /// not a staleness question).
    /// </summary>
    public const string NvdCheckedAt = "dependably:nvd-checked-at";

    /// <summary>
    /// The effective freshness timestamp for the CISA Vulnrichment SSVC signal —
    /// <c>COALESCE(ssvc_asserted_at, ssvc_checked_at)</c>, ISO-8601 UTC. Same reasoning as
    /// <see cref="NvdCheckedAt"/>; omitted when <c>ssvc_checked_at</c> is null.
    /// </summary>
    public const string SsvcCheckedAt = "dependably:ssvc-checked-at";

    /// <summary>
    /// Count of this tenant's applications whose latest version ships this advisory, from the same
    /// query shape as <c>SbomBlastRadiusRepository.CountProjectsByAdvisoryAsync</c>. Always present
    /// — zero is a real, different answer from "not computed".
    /// </summary>
    public const string AffectedApplications = "dependably:affected-applications";

    // ── Per-component ────────────────────────────────────────────────────────

    /// <summary>Dependency-graph position — <c>direct</c>/<c>transitive</c>/<c>root</c>/<c>graph-unknown</c>. Omitted when null.</summary>
    public const string DependencyKind = "dependably:dependency-kind";

    /// <summary>Dependency-graph scope — <c>dev</c>/<c>runtime</c>/<c>unknown</c>. Omitted when null (never actually null: the column defaults to <c>unknown</c>).</summary>
    public const string DependencyScope = "dependably:dependency-scope";

    /// <summary>
    /// The value a component declared as <c>versionRange</c> instead of a fixed version, carried
    /// as a property only under a CycloneDX 1.6 document — <c>versionRange</c> itself is a 1.7
    /// field, and dropping it under 1.6 would leave a component with no version and no
    /// explanation. Omitted under 1.7, where the native <c>versionRange</c> field is emitted
    /// instead, and omitted whenever the component carries a fixed <c>version</c>.
    /// </summary>
    public const string VersionRange = "dependably:version-range";

    /// <summary>
    /// <c>"true"</c>/<c>"false"</c> — carried as a property only under a CycloneDX 1.6 document,
    /// the same relocation <see cref="VersionRange"/> gets and for the identical reason:
    /// <c>isExternal</c> itself is a 1.7 field, and dropping the fact under 1.6 rather than
    /// relocating it would make a 1.6 and a 1.7 render of the SAME data assert different things —
    /// exactly what would force <c>specVersion</c> into the revision-identity key. Omitted under
    /// 1.7, where the native <c>isExternal</c> field is emitted instead, and omitted whenever the
    /// component declares no value at all.
    /// </summary>
    public const string IsExternal = "dependably:is-external";

    /// <summary>
    /// <c>"true"</c> only, emitted solely on a positive registry cross-link match. Never emitted as
    /// <c>"false"</c> and never omitted-as-negative — a miss means "unknown to this registry", and
    /// asserting <c>"false"</c> would overclaim verified-clean knowledge this registry does not
    /// hold for a third-party dependency it never handled (the same posture the registry
    /// cross-link's own precedent documents).
    /// </summary>
    public const string InstallScript = "dependably:install-script";

    /// <summary>
    /// X4/D10e (Component Producer): <see cref="AbsenceReason"/>'s value, emitted ONLY when the
    /// component carries no <c>component_producer</c> at all — CISA's own words are "unknown
    /// provenance". Never emitted alongside a real <c>publisher</c> field; the two are mutually
    /// exclusive, matching every other absence-companion property in this file.
    /// </summary>
    public const string ProducerStatus = "dependably:producer-status";

    /// <summary>
    /// X4/D12a (Component Version): <see cref="AbsenceReason"/>'s value, emitted ONLY when the
    /// component carries neither a fixed <c>version</c> NOR a <c>versionRange</c> explaining its
    /// absence — a component declaring a range already explains itself and does not need this.
    /// </summary>
    public const string VersionStatus = "dependably:version-status";

    /// <summary>
    /// X4/D14d (Component Hash Value): <see cref="AbsenceReason"/>'s value, emitted ONLY when
    /// neither dependably's own ingest-time digest NOR any document-asserted hash could be
    /// resolved for this component at all — CISA's own words are "no access to the artifact".
    /// Never emitted alongside a native <c>hashes[]</c> field or an
    /// <see cref="AssertedHashes"/> disclosure; see <c>BuildComponentHashes</c>.
    /// </summary>
    public const string HashStatus = "dependably:hash-status";

    /// <summary>
    /// X4/D16e (Component Licence): <see cref="AbsenceReason"/>'s value, emitted ONLY when the
    /// component carries no <c>license_spdx</c> at all. This is the same unknown-licence state
    /// that already blocks under <c>license_enforcement_mode=block</c> for the ecosystems whose
    /// manifests declare one (<c>BlockGateService.DeclaredLicenseEcosystems</c>) — exporting it
    /// explicitly keeps the gate's posture and the document's own claim consistent.
    /// </summary>
    public const string LicenseStatus = "dependably:license-status";

    /// <summary>
    /// D16d (Component Licence — proprietary conditions): <c>"true"</c> only, emitted when
    /// <c>license_spdx</c> contains an SPDX <c>LicenseRef-</c> token — SPDX's own defined
    /// mechanism for referencing a licence OUTSIDE the SPDX List.
    ///
    /// <para><b>This states an OBSERVATION, not a conclusion, and the name says so
    /// deliberately.</b> D16d asks that the licence field "convey the existence of proprietary
    /// licence conditions"; a <c>LicenseRef-</c> token cannot license that claim on its own —
    /// scanners emit it just as often for a PERMISSIVE or public-domain licence with no SPDX List
    /// entry (<c>LicenseRef-scancode-public-domain</c> and siblings are common Syft/scancode
    /// output) as for a genuinely proprietary one. Naming this property "proprietary conditions"
    /// would assert a conclusion the signal cannot support; naming it for what is actually
    /// observed — an identifier outside the SPDX List — is the honest, narrower claim, and the
    /// best-effort contribution this registry can make toward D16d without inventing a licence
    /// classifier it has no data to back. Never emitted as <c>"false"</c> and never
    /// omitted-as-negative — the same positive-only posture as <see cref="InstallScript"/>: a
    /// miss means "no known SPDX-List-outside marker", not "confirmed SPDX-listed", because a
    /// genuinely proprietary licence asserted under a real SPDX id (some commercial licences have
    /// one) is invisible to this signal in the other direction.</para>
    /// </summary>
    public const string NonSpdxListedLicense = "dependably:non-spdx-listed-license";

    /// <summary>
    /// X4/D13a (Component Identifier): <see cref="AbsenceReason"/>'s value, emitted ONLY when the
    /// component carries no identifier AT ALL — no <c>purl</c> and no
    /// <c>additional_identifiers</c> entry of any kind (CPE/SWHID/OmniBOR/commit-hash/UUID).
    /// Before this property existed, <c>sbom_components.purl</c> being nullable meant a
    /// purl-less component carried no identifier and no way to say so — this closes that gap
    /// with the SAME two-state vocabulary every other "indicate unknown" duty uses, per the
    /// class doc comment, rather than inventing a second one.
    /// </summary>
    public const string IdentifierStatus = "dependably:identifier-status";

    /// <summary>
    /// D13d overflow: a SECOND (or later) CPE a component asserted, when CycloneDX's native
    /// <c>cpe</c> field — singular, unlike <c>swhid</c>/<c>omniborId</c> — already holds the
    /// first. A document asserting more than one CPE for one component is real SPDX practice (a
    /// <c>cpe22Type</c> and a <c>cpe23Type</c> SECURITY ref side by side is standard): D13d
    /// requires every asserted identifier to survive the render, not just the one that fit the
    /// native field, so the rest are disclosed here rather than silently dropped. Repeatable, same
    /// reason as <see cref="IdentifierCommitHash"/>.
    /// </summary>
    public const string IdentifierCpe = "dependably:identifier:cpe";

    /// <summary>
    /// D13c: a version-control commit hash the component asserted (CycloneDX
    /// <c>pedigree.commits[].uid</c>) — CycloneDX defines no native component field for this kind,
    /// so it is disclosed here instead of natively. Repeatable: D13d requires every asserted
    /// identifier, not just the first, so more than one commit lands as more than one property
    /// entry of this same name.
    /// </summary>
    public const string IdentifierCommitHash = "dependably:identifier:commit-hash";

    /// <summary>
    /// D13c: a UUID identifier the component asserted (a CycloneDX <c>externalReferences</c>
    /// entry whose <c>url</c> is a <c>urn:uuid:</c> URN) — CycloneDX defines no native component
    /// field for a bare UUID the way it does for CPE/SWHID/OmniBOR, so it is disclosed here
    /// instead. Repeatable, same reason as <see cref="IdentifierCommitHash"/>.
    /// </summary>
    public const string IdentifierUuid = "dependably:identifier:uuid";

    // ── Document-level ───────────────────────────────────────────────────────

    /// <summary>Count of this document's components an OSV scan has actually stamped. Always present.</summary>
    public const string ScannedCount = "dependably:scanned-count";

    /// <summary>Count of scannable components with no scan stamp yet — an open question, not a benign absence. Always present.</summary>
    public const string UnscannedCount = "dependably:unscanned-count";

    /// <summary>Count of components no OSV feed could ever answer for — a different statement from deferred. Always present.</summary>
    public const string UnscannableCount = "dependably:unscannable-count";

    /// <summary>The latest <c>vuln_checked_at</c> across this document's components (ISO-8601 UTC). Omitted when nothing has been scanned.</summary>
    public const string LastScanAt = "dependably:last-scan-at";

    /// <summary>
    /// <c>"true"</c>/<c>"false"</c> — whether the operator's optional vulnerability-tracker
    /// connection is enabled and dialable. Every per-vulnerability SSVC/NVD-derived signal in this
    /// document shares this one answer to "is the signal absent because the feature is off, or
    /// because the source itself said nothing". Always present.
    /// </summary>
    public const string TrackerConfigured = "dependably:tracker-configured";

    /// <summary>
    /// <c>"all"</c>, <c>"prod"</c>, or <c>"dev"</c> — the same three-state vocabulary
    /// <c>SbomAnalysisProjection.ScopeFilters</c> (the component table's own <c>scope</c> filter)
    /// reads, not a second one: which <see cref="Dependably.Infrastructure.Sbom.SbomComponentFilter"/>
    /// this document was rendered under. Always present, on every project and collection document,
    /// including an unfiltered one (<c>"all"</c>): a consumer must be able to tell a filtered
    /// document from a complete one without comparing it to anything else. A VDR's
    /// <c>vulnerabilities[]</c> is filtered to the same kept component set — a filtered-out
    /// component's advisories are omitted along with it, never left as a dangling <c>affects[]</c>
    /// ref naming a component the document's own <c>components[]</c> just declared removed. Under
    /// <c>prod</c> or <c>dev</c>, <c>dependency_path</c> is never rewritten, so the
    /// <c>dependencies[]</c> graph — and only the graph — may still name a ref for a filtered-out
    /// component that has no matching <c>components[]</c> entry, the same shape it already
    /// produces for any path ancestor nothing was ever uploaded as its own component.
    /// </summary>
    public const string ComponentFilter = "dependably:component-filter";

    /// <summary>
    /// Count of components the active <see cref="ComponentFilter"/> removed. Always present —
    /// <c>"0"</c> on an unfiltered document, never omitted, so the absence of the property is
    /// never mistaken for "nothing was checked".
    /// </summary>
    public const string FilteredOutCount = "dependably:filtered-out-count";

    /// <summary>
    /// P2/P2f (Coverage): <c>"true"</c> only when THIS EXPORT rendered its own full, un-narrowed,
    /// non-empty component set — <see cref="ComponentFilter"/> is <c>all</c> AND the kept
    /// component count is greater than zero (on a collection, additionally: every subtree project
    /// contributed a document — <c>dependably:projectsWithoutSbom = "0"</c>, P2e). Built ON
    /// <see cref="ComponentFilter"/> rather than a second, independent disclosure channel, and
    /// kept distinct from <see cref="ScannedCount"/>/<see cref="UnscannedCount"/>/
    /// <see cref="UnscannableCount"/> — those describe VULNERABILITY-SCAN coverage, a different
    /// claim CISA's Coverage practice is not. Always present, on every project and collection
    /// document, AND on a standalone VEX document — where it is unconditionally <c>"false"</c>,
    /// never computed from the version's component count: a VEX document asserts no
    /// <c>components[]</c> array of its own at all, structurally, so it can never truthfully make
    /// this claim regardless of how many components the underlying project version has. See
    /// <c>BuildVexDocumentAsync</c>'s call site, which hardcodes the value rather than deriving
    /// it — a parameter with an affirmative default is exactly the silent-hole shape a sibling
    /// property's own doc comment (<see cref="FilteredOutCount"/>) already warns against, so this
    /// one has none: every call site must state its value.
    ///
    /// <para><b>What this deliberately does NOT claim.</b> This is a statement about what THIS
    /// RENDER did to the component set it was given — never an attestation that the underlying,
    /// STORED inventory is itself exhaustive. Three real cases this property cannot see and must
    /// not be read as ruling out: (1) an ingest-side purl collision silently collapsing two
    /// components that differ in <c>bom-ref</c>/hashes/licence/dependency path into one stored
    /// row — P2b requires each be listed separately with its own dependency relationship, and
    /// <c>SbomIngestRepository.MergeKey</c>'s first-wins merge does not do that today (tracked
    /// separately, not fixed by this property); (2) a third-party SBOM that itself only ever
    /// declared direct dependencies, leaving dependably nothing more to render even though it
    /// rendered every row it holds; (3) any other way the stored data undercounts the real
    /// dependency tree. A recipient reading <c>"true"</c> here may conclude only that dependably
    /// did not itself further narrow what it holds — CISA's P2 operative test (component absence
    /// implies non-affectedness) is not something an export boundary can attest to on behalf of
    /// data it received from someone else, which is exactly why this property is named for what
    /// was RENDERED, not for what is COMPLETE.</para>
    /// </summary>
    public const string FullInventoryRendered = "dependably:full-inventory-rendered";

    /// <summary>
    /// The document-asserted <c>hashes[]</c> entries a third-party producer carried for this
    /// component that could not be emitted as CycloneDX's native <c>hashes[]</c> field, as a JSON
    /// array of <c>{"alg","content"}</c> pairs with <c>alg</c> spelled EXACTLY as the document
    /// asserted it — never normalized to any other vocabulary (IANA's Hash Function Textual
    /// Names included; <c>hashes[].alg</c> is CycloneDX's own closed enum, and this property is
    /// a free-string properties value with no such constraint, which is precisely why it is the
    /// right place for an assertion the native field cannot represent). Two disjoint reasons an
    /// entry lands here, per <see cref="SbomExportService"/>'s hash-emission doc comment: (1)
    /// dependably holds its own stronger ingest-time digest for the component, which occupies the
    /// native field instead — every hex-valid asserted entry is disclosed in that case, regardless
    /// of its <c>alg</c>; or (2) dependably holds no digest of its own and the asserted entry's
    /// <c>alg</c> is not a member of the target document's <c>hash-alg</c> enum (CISA's own
    /// suggested lowercase spelling, or a 1.7-only algorithm asserted under a 1.6 render) — only
    /// that entry is disclosed, not the ones that WERE native-eligible. Omitted whenever nothing
    /// falls into either case.
    /// </summary>
    public const string AssertedHashes = "dependably:asserted-hashes";

    /// <summary>
    /// X4/D8b (SBOM Tool Version): <see cref="AbsenceReason"/>'s value, carried on the ORIGINAL
    /// producing tool's own entry in <c>metadata.tools.components[].properties[]</c> — never on
    /// dependably's own entry, whose version is always known (read from the running assembly).
    /// Emitted ONLY when a document named an original tool but no version for it; a document that
    /// named no original tool at all has nothing to qualify.
    /// </summary>
    public const string ToolVersionStatus = "dependably:tool-version-status";

    /// <summary>
    /// CISA D2 (SBOM Author Signature): the property name a consumer reads to tell "signed" from
    /// "unsigned because this org has no signing key" from "unsigned because this replica
    /// couldn't read the org's key just now" — emitted in every case so the signed case is never
    /// ambiguous to a consumer that has only ever seen one of the others. Values are
    /// <see cref="Sbom.SbomAuthorSigner.SignedState"/>, <see cref="Sbom.SbomAuthorSigner.UnsignedNoMasterKeyState"/>,
    /// or <see cref="Sbom.SbomAuthorSigner.UnsignedKeyUnavailableState"/> — the closed three-value
    /// set <c>SignatureStateVocabularyComplianceTests</c> enforces from the rendered document,
    /// the same posture <see cref="UnknownValue"/>/<see cref="WithheldValue"/> gets from
    /// <c>UnknownWithheldVocabularyComplianceTests</c> — a fourth spelling invented at a call site
    /// would not match either gate's <c>-status</c> selector (this property ends in
    /// <c>-state</c>, deliberately: it is a fact about a KEY, not an "indicate unknown" duty
    /// field), which is exactly why it needs its own gate rather than folding into that one.
    /// </summary>
    public const string SignatureState = "dependably:signature-state";

    public const string TrueValue = "true";
    public const string FalseValue = "false";
    public const string UnknownValue = "unknown";

    /// <summary>P4a/X4's other absence state. See the class doc comment; not emitted by any call site today.</summary>
    public const string WithheldValue = "withheld";
}
