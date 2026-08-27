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
/// </summary>
public static class DependablyExportProperties
{
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
    /// <c>"true"</c> only, emitted solely on a positive registry cross-link match. Never emitted as
    /// <c>"false"</c> and never omitted-as-negative — a miss means "unknown to this registry", and
    /// asserting <c>"false"</c> would overclaim verified-clean knowledge this registry does not
    /// hold for a third-party dependency it never handled (the same posture the registry
    /// cross-link's own precedent documents).
    /// </summary>
    public const string InstallScript = "dependably:install-script";

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

    public const string TrueValue = "true";
    public const string FalseValue = "false";
    public const string UnknownValue = "unknown";
}
