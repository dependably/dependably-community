using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

namespace Dependably.Infrastructure;

// Dapper-mapped DTOs. Using classes with public setters (not positional records) so Dapper
// uses its property-setter path, which coerces SQLite's Int64/TEXT to C# bool/int/DateTimeOffset
// via Convert.ChangeType and registered type handlers.

public class Org
{
    public string Id { get; set; } = "";
    public string Slug { get; set; } = "";
    /// <summary>
    /// Set when the tenant is soft-deleted. system_admin can restore within the grace window
    /// (default 30 days); after that, <see cref="Background.TenantHardDeleteService"/> cascades.
    /// </summary>
    public DateTimeOffset? DeletedAt { get; set; }
    /// <summary>
    /// Tenant lifecycle gate. 'active' is the only state that admits a request: a non-active
    /// value is a full lockout — <see cref="TenantStatusEnforcementMiddleware"/> refuses every
    /// tenant-bound request for the org (protocol plane, management API, and login alike) before
    /// it reaches a controller, and <see cref="Storage.ITenantStorageResolver"/> applies the same
    /// check independently as defence in depth (raising <see cref="Storage.TenantNotReadyException"/>).
    /// system_admin can toggle between 'active' and 'suspended' from the Tenants page;
    /// 'archived' and 'deleting' get the identical lockout but are enterprise-only.
    /// </summary>
    public string Status { get; set; } = "active";
    /// <summary>
    /// Aggregate storage quota in bytes across the tenant's hosted artefacts (sum of
    /// <c>package_versions.size_bytes</c>). NULL = unlimited. Enforced in
    /// <see cref="Publish.PackagePublishService"/> ahead of the blob put — exceeding the
    /// cap returns 413. Noisy-neighbour guard for pooled multi-tenant deployments.
    /// </summary>
    public long? StorageQuotaBytes { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>
/// List-projection of <see cref="Org"/> that carries the per-tenant aggregates needed by the
/// system_admin tenants page (member count, storage bytes used). Kept separate from
/// <see cref="Org"/> so single-tenant callers don't pay for the join.
/// Also carries the most recent <c>org_stats_snapshot</c> JSON blob for health derivation.
/// </summary>
public class OrgListItem
{
    public string Id { get; set; } = "";
    public string Slug { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? DeletedAt { get; set; }
    /// <summary>See <see cref="Org.Status"/>.</summary>
    public string Status { get; set; } = "active";
    public long? StorageQuotaBytes { get; set; }
    public int MemberCount { get; set; }
    public long StorageBytes { get; set; }
    /// <summary>
    /// JSON from <c>org_stats_snapshot.stats_json</c> for this org. Null when no
    /// snapshot exists yet. Deserialized in the controller to derive health signals.
    /// </summary>
    public string? StatsJson { get; set; }
    /// <summary>
    /// ISO 8601 UTC string from <c>org_stats_snapshot.computed_at</c>. Null when no
    /// snapshot exists yet.
    /// </summary>
    public string? StatsComputedAt { get; set; }
}

/// <summary>
/// Per-run record for an IHostedService background worker. Persisted by
/// <see cref="Observability.BackgroundJobScope"/> on dispose; listed in the sysadmin
/// Audit page "Background Jobs" tab.
/// </summary>
public class BackgroundJobRun
{
    public string Id { get; set; } = "";
    public string JobName { get; set; } = "";
    public string Operation { get; set; } = "";
    public string RunId { get; set; } = "";
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset FinishedAt { get; set; }
    public long DurationMs { get; set; }
    /// <summary>Same vocabulary as the <c>dependably.background_job.duration</c> histogram outcome label.</summary>
    public string Outcome { get; set; } = "";
    public string? ErrorMessage { get; set; }
}

public class OrgSettings
{
    public string OrgId { get; set; } = "";
    public bool AnonymousPull { get; set; }
    public bool AllowlistMode { get; set; }
    public long? MaxUploadBytes { get; set; }
    public long? MaxUploadBytesPyPi { get; set; }
    public long? MaxUploadBytesNpm { get; set; }
    public long? MaxUploadBytesNuGet { get; set; }
    public long? MaxUploadBytesMaven { get; set; }
    public long? MaxUploadBytesRpm { get; set; }
    public long? MaxUploadBytesOci { get; set; }
    public long? MaxUploadBytesCargo { get; set; }
    public long? MaxUploadBytesHex { get; set; }
    public int? KeepVersions { get; set; }
    public int? KeepDays { get; set; }
    /// <summary>Max project versions retained per project. NULL is unlimited.</summary>
    public int? KeepProjectVersions { get; set; }
    public int? ActivityRetentionDays { get; set; }
    public int? PurgeUnlistedAfterDays { get; set; }
    /// <summary>'off' | 'warn' | 'block'</summary>
    public string LicenseEnforcementMode { get; set; } = "off";
    /// <summary>
    /// 'off' | 'warn' | 'block'. Publish-side licence gate, independent of
    /// <see cref="LicenseEnforcementMode"/> (the serve-path gate): governs whether a hosted
    /// publish carrying no declared licence is accepted (off/warn) or rejected (block) for the
    /// <see cref="Protocol.BlockGateService.DeclaredLicenseEcosystems"/> ecosystems. Defaults to
    /// 'off' so no currently-succeeding publish workflow breaks on upgrade.
    /// </summary>
    public string LicensePublishEnforcementMode { get; set; } = "off";
    public bool ProxyPassthroughEnabled { get; set; } = true;
    public double MaxOsvScoreTolerance { get; set; } = 10.0;
    /// <summary>
    /// Supply-chain hold: a proxy-fetched version is blocked when
    /// (now − upstream published_at) is below this many hours. NULL = policy off.
    /// Evaluated on every serve and index render by <see cref="Protocol.BlockGateService"/>,
    /// so a held version serves again automatically once it ages past the threshold;
    /// fail-open when the upstream publish timestamp is missing.
    /// </summary>
    public int? MinReleaseAgeHours { get; set; }
    /// <summary>BCP-47 short code (e.g. "en", "fr"). New users in this tenant inherit this value.</summary>
    public string DefaultLanguage { get; set; } = "en";
    /// <summary>
    /// IANA zone name (e.g. "America/Toronto"). Renders stored instants for users in this tenant
    /// who have not set their own. Display only — instants are stored in UTC regardless.
    /// </summary>
    public string DefaultTimezone { get; set; } = "UTC";
    /// <summary>
    /// Legacy boolean; kept for blue-green safety. Superseded by <see cref="VersionOverwritePolicy"/>.
    /// </summary>
    public bool AllowVersionOverwrite { get; set; }
    /// <summary>
    /// Tri-state same-version-push org policy: 'block' (default) = always reject duplicate
    /// coordinates; 'exception' = blocked by default but individual packages can grant permission
    /// via <c>packages.same_version_push_override = 'allow'</c>; 'allow' = allowed by default
    /// but individual packages can deny via <c>'block'</c>. When 'block', per-package overrides
    /// are ignored (hard lockdown). Resolution lives in PackagePublishService.ResolveOverwriteAllowed.
    /// </summary>
    public string VersionOverwritePolicy { get; set; } = "block";
    /// <summary>
    /// Per-tenant air-gap posture. When true, this org makes no outbound network requests:
    /// proxy passthrough is forced off (uncached upstream returns 404 via
    /// <see cref="ProxyPassthroughEffective"/>), and the vulnerability and deprecation-metadata
    /// scan passes skip this org. Composes with the instance <c>AIR_GAPPED</c> env var
    /// (<see cref="IAirGapMode"/>): the effective posture is instance OR tenant.
    /// </summary>
    public bool AirGapped { get; set; }
    /// <summary>
    /// Per-tenant MFA enrollment requirement. When true, all authenticated users in this org
    /// must complete MFA enrollment before accessing any API endpoints, enforced by
    /// <see cref="Dependably.Security.MfaEnrollmentGuard"/>. Composes with the instance
    /// <c>REQUIRE_MFA</c> env var (<see cref="IRequireMfaMode"/>): effective requirement =
    /// instance OR tenant.
    /// </summary>
    public bool RequireMfa { get; set; }
    /// <summary>
    /// Computed proxy-passthrough gate used by the protocol controllers: passthrough is allowed
    /// only when it is enabled AND the tenant is not air-gapped. The raw
    /// <see cref="ProxyPassthroughEnabled"/> value is still surfaced verbatim in the settings API.
    /// </summary>
    public bool ProxyPassthroughEffective => ProxyPassthroughEnabled && !AirGapped;
    /// <summary>
    /// Proxy gate for upstream-deprecated packages (keyed on <c>package_versions.deprecated</c>).
    /// 'off' = allow through (default); 'warn' = surface deprecation in UI without blocking;
    /// 'block_new' = refuse a deprecated version on cache miss (never fetch/cache/serve it) while
    /// still serving already-cached versions; 'block_all' = block_new plus deny already-cached
    /// versions. Legacy 'block' rows are migrated to 'block_all'.
    /// </summary>
    public string BlockDeprecated { get; set; } = "off";
    /// <summary>
    /// Proxy gate for versions removed from the upstream registry (keyed on
    /// <c>package_versions.revoked_at</c> / <c>cache_artifact.revoked_at</c>). 'off' = allow
    /// through; 'warn' (default) = surface the revoked badge without blocking; 'block' = deny the
    /// serve/listing path and quarantine for review. Three values (no <c>block_new</c> analog —
    /// revocation is always a full upstream removal). A manual per-version allow override still wins.
    /// </summary>
    public string BlockRevoked { get; set; } = "warn";
    /// <summary>
    /// Proxy gate for versions carrying a malicious-package advisory (OSV <c>MAL-</c> ids from
    /// the OpenSSF malicious-packages feed). Those advisories usually have no CVSS score, so
    /// <see cref="MaxOsvScoreTolerance"/> never sees them — this gate keys on the advisory id
    /// prefix instead. 'block' (default) = deny fetch and serve; 'warn' = surface in UI only;
    /// 'off' = gate disabled. A manual per-version allow override still wins.
    /// </summary>
    public string BlockMalicious { get; set; } = "block";
    /// <summary>
    /// Narrower companion to <see cref="BlockMalicious"/>: fires only when the tracker's
    /// version-precise still-live-malicious signal (<c>package_version_vulns.mal_still_live_for_version</c>)
    /// is true for the version being evaluated — independent of <see cref="BlockMalicious"/> the
    /// same way <see cref="BlockKevRansomware"/> is independent of <see cref="BlockKev"/>. 'off'
    /// (default) / 'warn' / 'block'. Defaults 'off' deliberately, unlike <see cref="BlockMalicious"/>'s
    /// 'block' default: this arm is new behaviour on an existing deployment's serving posture, so
    /// it must be opt-in on upgrade. Inert unless the operator has configured the optional
    /// vulnerability-tracker connection, because nothing else populates the column.
    /// </summary>
    public string BlockMaliciousLive { get; set; } = "off";
    /// <summary>
    /// Proxy gate for versions whose advisories alias a CVE in the CISA Known Exploited
    /// Vulnerabilities catalog — exploited-in-the-wild, independent of CVSS score.
    /// 'off' (default) / 'warn' / 'block'. A manual per-version allow override still wins.
    /// </summary>
    public string BlockKev { get; set; } = "off";
    /// <summary>
    /// EPSS exploitation-probability ceiling (0.0–1.0). A version is blocked when the maximum
    /// <c>vulnerabilities.epss_score</c> across its advisories exceeds this value. NULL = off.
    /// </summary>
    public double? MaxEpssTolerance { get; set; }
    /// <summary>
    /// Narrower companion to <see cref="BlockKev"/>: fires only on advisories CISA marks as used
    /// in ransomware campaigns. Independent of <see cref="BlockKev"/> rather than a mode on it,
    /// so the two compose — the useful policy is often <c>BlockKev = "warn"</c> with this at
    /// <c>"block"</c>. 'off' (default) / 'warn' / 'block'.
    ///
    /// <para>
    /// Fires only on an explicit "known" verdict. A CVE CISA marks <c>Unknown</c>, and one whose
    /// entry carries no such field at all, both leave this arm alone — see the column comment in
    /// <c>Schema.sql</c> for why that is safe rather than a fail-open.
    /// </para>
    /// </summary>
    public string BlockKevRansomware { get; set; } = "off";
    /// <summary>
    /// EPSS percentile ceiling (0.0–1.0), the rank sibling of <see cref="MaxEpssTolerance"/>.
    /// Blocked when the maximum <c>vulnerabilities.epss_percentile</c> across a version's
    /// advisories exceeds this value. NULL = off. Both may be set; either tripping is enough.
    /// </summary>
    public double? MaxEpssPercentileTolerance { get; set; }
    /// <summary>
    /// Enrichment-overlay gate for advisories CISA Vulnrichment marks as actively exploited
    /// (<c>ssvc_exploitation = 'active'</c>). 'off' (default) / 'warn' / 'block'. Inert unless the
    /// operator has configured the optional vulnerability-tracker connection, because nothing
    /// else populates the column.
    /// </summary>
    public string BlockSsvcExploitation { get; set; } = "off";
    /// <summary>
    /// Proxy gate for artefacts that ship an install/lifecycle script
    /// (<c>package_versions.has_install_script</c>). 'off' (default) = allow through; 'warn' =
    /// surface in UI only; 'block' = deny fetch and serve. A manual per-version allow override
    /// still wins.
    /// </summary>
    public string BlockInstallScripts { get; set; } = "off";
    /// <summary>
    /// Proxy gate for npm registry signature verification of proxy-origin versions
    /// (<c>package_versions.provenance_status</c>). 'off' (default) = do not verify; 'warn' =
    /// verify and surface in UI only; 'block' = fail closed (a version that fails verification or
    /// is unsigned is refused, not cached or served). Enabling 'warn'/'block' requires at least
    /// one npm SPKI trust anchor in <c>signature_trust_anchor</c>; without one the verifier
    /// reports not-applicable and nothing blocks. A manual per-version allow override still wins.
    /// </summary>
    public string VerifyNpmSignatures { get; set; } = "off";
    /// <summary>
    /// Proxy gate for NuGet <c>.nupkg</c> signature verification of proxy-origin versions
    /// (<c>package_versions.provenance_status</c>). 'off' (default) = do not verify; 'warn' =
    /// verify and surface in UI only; 'block' = fail closed (a version whose signature fails
    /// verification or is unsigned is refused, not cached or served). Enabling 'warn'/'block'
    /// requires at least one NuGet X.509 trust anchor in <c>signature_trust_anchor</c>; without
    /// one the verifier reports not-applicable and nothing blocks. A manual per-version allow
    /// override still wins.
    /// </summary>
    public string VerifyNuGetSignatures { get; set; } = "off";
    /// <summary>
    /// Proxy gate for PyPI PEP 740 attestation verification of proxy-origin versions
    /// (<c>package_versions.provenance_status</c>). 'off' (default) = do not verify; 'warn' =
    /// verify and surface in UI only; 'block' = fail closed (a version whose attestation fails
    /// verification or that carries none is refused, not cached or served). Enabling 'warn'/'block'
    /// requires at least one per-org <c>sigstore_root</c> trust anchor and at least one
    /// <c>trusted_publisher</c> trust anchor configured via Settings → Trust Anchors; without
    /// them the verifier reports not-applicable and nothing blocks. A manual per-version allow
    /// override still wins.
    /// </summary>
    public string VerifyPyPiAttestations { get; set; } = "off";
    /// <summary>
    /// Proxy gate for RPM per-package GPG header signature verification of proxy-origin versions
    /// (<c>cache_artifact.provenance_status</c>). 'off' (default) = do not verify; 'warn' = verify
    /// and surface in UI only; 'block' = fail closed (a version whose header signature fails
    /// verification or carries none is refused, not cached or served). Enabling 'warn'/'block'
    /// requires at least one RPM PGP trust anchor in <c>signature_trust_anchor</c>; without one
    /// the verifier reports not-applicable and nothing blocks. A manual per-version allow override
    /// still wins.
    /// </summary>
    public string VerifyRpmSignatures { get; set; } = "off";
    /// <summary>
    /// Proxy gate for Maven detached <c>.asc</c> OpenPGP signature verification of proxy-origin
    /// versions (<c>cache_artifact.provenance_status</c>). 'off' (default) = do not verify; 'warn' =
    /// verify and surface in UI only; 'block' = fail closed (a version whose <c>.asc</c> signature
    /// fails verification or is absent is refused, not cached or served). Enabling 'warn'/'block'
    /// requires at least one per-org Maven PGP trust anchor in <c>signature_trust_anchor</c>;
    /// without one the verifier reports not-applicable and nothing blocks. A manual per-version
    /// allow override still wins.
    /// </summary>
    public string VerifyMavenSignatures { get; set; } = "off";
    /// <summary>
    /// Proxy gate for Terraform provider publisher-signed SHASUMS chain verification of
    /// proxy-origin archives (<c>cache_artifact.provenance_status</c>). The download response's
    /// own <c>shasum</c> is self-certified by the same registry that names the archive host; this
    /// gate instead fetches the registry's <c>shasums_url</c>/<c>shasums_signature_url</c>,
    /// GPG-verifies the detached signature against the per-org trust anchor ring, and confirms
    /// the archive's SHA-256 appears in the verified SHASUMS. 'off' (default) = do not verify;
    /// 'warn' = verify and surface in UI only; 'block' = fail closed (an archive whose chain fails
    /// verification or carries none is refused, not cached or served). Enabling 'warn'/'block'
    /// requires at least one per-org Terraform PGP trust anchor in <c>signature_trust_anchor</c>;
    /// without one the verifier reports not-applicable and nothing blocks. A manual per-version
    /// allow override still wins.
    /// </summary>
    public string VerifyTerraformSignatures { get; set; } = "off";
    /// <summary>
    /// Admission gate for an ingested CycloneDX document's enveloped JSF signature
    /// (CISA D2, <c>project_documents.signature_status</c>). 'off' (default) = do not verify;
    /// 'warn' = verify and record the verdict without refusing the upload; 'block' = fail closed
    /// (a document whose signature fails verification, or that carries none, is refused).
    /// Enabling 'warn'/'block' requires at least one <c>('sbom','spki')</c> trust anchor in
    /// <c>signature_trust_anchor</c>; without one the check has nothing to verify against and
    /// denies under 'block' rather than no-opping — see <c>SbomController</c>'s admission check.
    /// This is deliberately NOT dispatched by <see cref="VerifyProvenanceMode"/>: it governs an
    /// upload admission decision, not a <c>BlockGateService</c> artefact-provenance arm — a
    /// document has no coordinate for that gate to key on (ADR-sbom-author-signature).
    /// </summary>
    public string VerifySbomSignatures { get; set; } = "off";

    /// <summary>
    /// Per-tenant RPM hosted-publishing posture override: NULL (unset), 'passthrough', or 'merged'.
    /// NULL inherits the instance <c>Rpm:UpstreamMode</c> env value; an explicit value overrides
    /// the env value in EITHER direction (see <c>RpmController.IsRpmPassthroughEffective</c>).
    /// 'passthrough' refuses hosted RPM publish while an rpm upstream registry is configured;
    /// 'merged' allows hosted publish and serves a combined local ∪ upstream repodata document.
    /// </summary>
    public string? RpmUpstreamMode { get; set; }

    /// <summary>
    /// Resolves the signature-verification mode ('off' | 'warn' | 'block') for an ecosystem so the
    /// block-gate provenance arm reads the right per-ecosystem policy on the serve path. The
    /// stored <c>package_versions.provenance_status</c> column is ecosystem-agnostic, but the
    /// tenant policy that governs it is per-ecosystem (<see cref="VerifyNpmSignatures"/> for npm,
    /// <see cref="VerifyNuGetSignatures"/> for nuget, <see cref="VerifyPyPiAttestations"/> for pypi).
    /// An ecosystem with no signature policy returns 'off', so its versions never block on provenance.
    /// </summary>
    public string VerifyProvenanceMode(string ecosystem) => ecosystem switch
    {
        "npm" => VerifyNpmSignatures,
        "nuget" => VerifyNuGetSignatures,
        "pypi" => VerifyPyPiAttestations,
        "rpm" => VerifyRpmSignatures,
        "maven" => VerifyMavenSignatures,
        "terraform" => VerifyTerraformSignatures,
        _ => "off",
    };
}

public class Package
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    public string Ecosystem { get; set; } = "";
    public string Name { get; set; } = "";
    public string PurlName { get; set; } = "";
    public bool IsProxy { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public int VersionCount { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    // Sum of download_count across every version under this package.
    public long TotalDownloads { get; set; }
    // Upstream's declared latest version, or null when no baseline is known.
    public string? UpstreamLatestVersion { get; set; }
    // Publish timestamp of UpstreamLatestVersion, when the ecosystem's metadata carries one. Null
    // when the baseline itself is unknown or the ecosystem's metadata doesn't expose a timestamp
    // (see UpstreamLatestVersionResolver's per-ecosystem availability notes).
    public DateTimeOffset? UpstreamLatestPublishedAt { get; set; }
    // Packages-list "Latest" indicator, computed in SQL: "current" (upstream latest is cached),
    // "stale" (a newer upstream version exists but is not cached), or "unknown" (no baseline).
    public string LatestState { get; set; } = "unknown";
    // Packages-list "Abandoned" indicator, computed in C# (PackageRepository, against the injected
    // TimeProvider) after the SQL fetch: "abandoned" when UpstreamLatestPublishedAt is >= 365 days
    // old, "active" otherwise, "unknown" when no publish timestamp is known. Never "abandoned" on
    // an unknown timestamp — surfacing uncertainty as staleness would assert a fact the server
    // doesn't have.
    public string AbandonedState { get; set; } = "unknown";
    // True when any version of this package is linked to an OSV MAL- advisory (OpenSSF
    // malicious-packages feed). Drives the packages-list malicious indicator. Computed in SQL.
    public bool HasMaliciousVersion { get; set; }
    // True when any version of this package is linked to a vulnerability CISA has added to the
    // Known Exploited Vulnerabilities Catalog (v.is_kev = 1). Drives the packages-list KEV
    // indicator. Computed in SQL.
    public bool HasKevVersion { get; set; }
    /// <summary>
    /// Per-package same-version-push override. NULL = inherit the org <c>version_overwrite_policy</c>.
    /// 'allow' = grant overwrite permission even when the org policy is 'exception'. 'block' = deny
    /// overwrite even when the org policy is 'allow'. Ignored when the org policy is 'block'.
    /// </summary>
    public string? SameVersionPushOverride { get; set; }
    // Package-level metadata surfaced in the UI, captured from the artifact manifest at hosted
    // publish and proxy first-fetch. Null when the ecosystem's manifest omits the field or the
    // package was last ingested before capture existed (no historical backfill).
    public string? Homepage { get; set; }
    public string? RepositoryUrl { get; set; }
    public string? Description { get; set; }
    // Author/publisher as the artifact manifest names it, captured by the same parse.
    public string? Author { get; set; }
}

public class PackageVersion
{
    public string Id { get; set; } = "";
    public string PackageId { get; set; } = "";
    public string Version { get; set; } = "";
    public string Purl { get; set; } = "";
    public string BlobKey { get; set; } = "";
    public long SizeBytes { get; set; }
    public string? ChecksumSha256 { get; set; }
    public bool Yanked { get; set; }
    public string? YankReason { get; set; }
    public bool FirstFetch { get; set; }
    /// <summary>
    /// Cumulative count of served downloads — every 'download' + 'first_fetch' event (proxy
    /// first-fetch, protocol-client pulls, and UI downloads). Monotonic and durable, so it
    /// survives activity-log pruning and remains an all-time total.
    /// </summary>
    public long DownloadCount { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    /// <summary>
    /// ISO 8601 UTC; stamped when a same-version re-push overwrites this row's bytes. NULL
    /// means never overwritten, so the effective pushed date is <see cref="CreatedAt"/>.
    /// </summary>
    public DateTimeOffset? UpdatedAt { get; set; }
    public DateTimeOffset? VulnCheckedAt { get; set; }
    public string? ManualBlockState { get; set; }
    /// <summary>NULL = not deprecated; otherwise the upstream deprecation message (npm/NuGet).</summary>
    public string? Deprecated { get; set; }
    /// <summary>Provenance: 'proxy' (upstream cache) or 'uploaded' (user-pushed via protocol or /admin/upload).</summary>
    public string Origin { get; set; } = "proxy";
    /// <summary>
    /// Upstream first-publish timestamp captured on proxy first-fetch (PyPI upload_time,
    /// npm time[version], NuGet catalogEntry.published). NULL for uploaded versions and for
    /// legacy rows pre-dating the column.
    /// </summary>
    public DateTimeOffset? PublishedAt { get; set; }
    /// <summary>
    /// Hex SHA-1 of the artefact bytes. Captured at npm publish time and from upstream npm
    /// packuments on proxy first-fetch. NULL for non-npm rows and for legacy rows. Required
    /// so the packument's <c>dist.shasum</c> can carry the correct hash (SHA-1 by spec).
    /// </summary>
    public string? ChecksumSha1 { get; set; }
    /// <summary>
    /// Upstream-published integrity hash captured at proxy first-fetch, stored verbatim in
    /// upstream's native encoding (npm <c>sha512-{b64}</c> SRI, NuGet base64, PyPI hex) so
    /// operators can copy-paste against the public registry's UI without re-encoding.
    /// For hosted npm publishes the same pair carries the artefact's sha512 SRI
    /// (<c>'sha512-sri'</c>) — the publisher's <c>dist.integrity</c> claim when the client
    /// sent one, otherwise computed server-side from the uploaded bytes — so the packument
    /// can emit <c>dist.integrity</c>. Paired with <see cref="UpstreamIntegrityAlgorithm"/>.
    /// NULL for non-npm uploaded versions and legacy rows.
    /// </summary>
    public string? UpstreamIntegrityValue { get; set; }
    /// <summary>
    /// Tag describing how to interpret <see cref="UpstreamIntegrityValue"/>:
    /// <c>'sha256'</c> (hex), <c>'sha512-sri'</c>, or <c>'sha512-b64'</c>.
    /// </summary>
    public string? UpstreamIntegrityAlgorithm { get; set; }
    /// <summary>ISO 8601 UTC; set by <c>DeprecationRefreshService</c> after each upstream metadata check. NULL = never checked.</summary>
    public DateTimeOffset? DeprecationCheckedAt { get; set; }
    /// <summary>
    /// ISO 8601 UTC; first time this version was observed REMOVED from the upstream registry
    /// (npm unpublish, PyPI delete, registry takedown). NULL = still published upstream. Distinct
    /// from <see cref="Deprecated"/> (still published, advised against): revoked = gone entirely.
    /// Set by <c>DeprecationRefreshService</c>; reset to NULL if the version reappears upstream.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; set; }
    /// <summary>
    /// Operational-risk signal: count of upstream STABLE versions strictly newer than this one,
    /// using each ecosystem's native version ordering (NuGet.Versioning, PEP 440, semver, Maven
    /// ComparableVersion) — consistent with the latest=STABLE convention <see
    /// cref="Protocol.IUpstreamLatestVersionResolver"/> already applies. NULL = unknown
    /// (hosted-only package with no upstream counterpart, air-gapped, unsupported ecosystem, or
    /// not yet refreshed) — render UNSCORED, never 0. Set by <c>DeprecationRefreshService</c> and
    /// seeded on proxy first-fetch.
    /// </summary>
    public int? VersionsBehind { get; set; }
    /// <summary>
    /// True when the artefact ships an install/lifecycle script that runs automatically on
    /// install — an npm preinstall/install/postinstall hook, a PyPI sdist <c>setup.py</c>, or a
    /// NuGet <c>tools/install.ps1</c>/<c>init.ps1</c> or <c>build/*.targets</c>/<c>*.props</c>.
    /// Detected at proxy first-fetch and hosted publish by <see cref="Protocol.ScriptDetectionService"/>
    /// and stored in <c>package_versions.has_install_script</c>; drives the install-script block-gate arm.
    /// </summary>
    public bool HasInstallScript { get; set; }
    /// <summary>
    /// Discriminator for the detected script kind, e.g. <c>'npm:postinstall'</c>,
    /// <c>'pypi:setup.py'</c>, <c>'nuget:install.ps1'</c>, <c>'nuget:msbuild'</c>. NULL when
    /// <see cref="HasInstallScript"/> is false.
    /// </summary>
    public string? InstallScriptKind { get; set; }
    /// <summary>
    /// Provenance/signature-verification outcome captured at proxy first-fetch:
    /// <c>'verified'</c> (a pinned trust anchor produced a valid signature over the canonical
    /// signing payload), <c>'failed'</c> (a signature was present but did not verify), or
    /// <c>'unsigned'</c> (upstream published no signature). NULL when verification was not
    /// applicable (policy off, no verifier, hosted origin) or for rows that pre-date the column.
    /// Drives the provenance block-gate arm.
    /// </summary>
    public string? ProvenanceStatus { get; set; }
    /// <summary>
    /// Identity of the verifying signer (the trust-anchor keyid) when
    /// <see cref="ProvenanceStatus"/> is <c>'verified'</c>. NULL otherwise.
    /// </summary>
    public string? ProvenanceSigner { get; set; }
    /// <summary>
    /// Install-relevant manifest subset (bin, dependencies, optionalDependencies,
    /// peerDependencies, peerDependenciesMeta, bundleDependencies, engines, os, cpu, libc,
    /// directories, _hasShrinkwrap) captured from the tarball's package.json and stored as one
    /// JSON object — at hosted npm publish for uploaded rows, or at npm proxy first-fetch
    /// (<c>cache_artifact.manifest_json</c>, projected here by
    /// <see cref="CacheArtifactIndexFacts.ToPackageVersionSynthetic"/>) for proxy rows. Merged
    /// into the packument's per-version objects so npm/npx can resolve bin links and transitive
    /// dependencies. NULL for non-npm rows and for rows cached/published before the column
    /// existed (those render the legacy minimal shape until backfilled).
    /// </summary>
    public string? ManifestJson { get; set; }
    /// <summary>
    /// True when this version is linked to an OSV <c>MAL-</c> advisory (OpenSSF
    /// malicious-packages feed) — i.e. known-malicious. MAL advisories usually carry no CVSS
    /// score, so this is a distinct signal from the vulnerability-severity counts. Derived in
    /// SQL by <see cref="PackageRepository.GetVersionsAsync"/>; not a stored column.
    /// </summary>
    public bool IsMalicious { get; set; }
    /// <summary>
    /// Canonical artifact filename for proxy cache-plane versions (e.g. <c>vite-8.0.16.tgz</c>),
    /// populated by <see cref="CacheArtifactIndexFacts.ToPackageVersionSynthetic"/>. Null for
    /// uploaded versions, which use the blob-key suffix as the filename. Metadata renderers
    /// prefer this value over the blob-key suffix so proxy versions advertise a resolvable
    /// download URL instead of a content-addressed SHA-256 path segment.
    /// </summary>
    public string? Filename { get; set; }
    /// <summary>
    /// True when this version is linked to at least one OSV advisory of any kind (scored,
    /// unscored, or MAL-). Lets the status projection distinguish "scanned, no advisories"
    /// from "scanned, has advisories below the block tolerance" so a vulnerable-but-servable
    /// version is never labelled clean. Derived in SQL; not a stored column.
    /// </summary>
    public bool HasAdvisory { get; set; }
    /// <summary>
    /// Full URL the artifact bytes were fetched from, for proxy cache-plane versions — the
    /// resolved per-org upstream (a private registry when one is configured), projected from
    /// <c>cache_artifact.upstream_url</c> by
    /// <see cref="CacheArtifactIndexFacts.ToPackageVersionSynthetic"/>. NULL for uploaded
    /// versions (no upstream) and for proxy rows cached before the column was populated.
    /// </summary>
    public string? UpstreamUrl { get; set; }
}

public class User
{
    public string Id { get; set; } = "";
    public string TenantId { get; set; } = "";
    public string Email { get; set; } = "";
    /// <summary>'member' | 'admin' | 'owner' — per-tenant role.</summary>
    public string Role { get; set; } = "member";
    /// <summary>'forms' | 'saml' — how the account was provisioned. SAML-linked forms users stay 'forms'.</summary>
    public string AccountType { get; set; } = "forms";
    public bool MustChangePassword { get; set; }
    public DateTimeOffset? LastLoginAt { get; set; }
    /// <summary>'active' | 'locked' | 'disabled'.</summary>
    public string AccountStatus { get; set; } = "active";
    public bool MfaEnabled { get; set; }
    public DateTimeOffset? PasswordResetIssuedAt { get; set; }
    /// <summary>Per-user locale override. Null means inherit org_settings.default_language.</summary>
    public string? Language { get; set; }
    /// <summary>Monotonic session-invalidation counter embedded in tenant JWTs as the <c>tver</c> claim.</summary>
    public long TokenVersion { get; set; } = 1;
    /// <summary>AES-GCM-encrypted TOTP authenticator key. Null until the user enrolls in MFA.</summary>
    public string? MfaAuthenticatorKey { get; set; }
    /// <summary>JSON array of SHA-256 hashes of one-time MFA recovery codes. Null until enrollment.</summary>
    public string? MfaRecoveryCodes { get; set; }
    /// <summary>Random stamp rotated on every credential change so concurrent mutations are detectable.</summary>
    public string? SecurityStamp { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>
/// Operator identity. Distinct from <see cref="User"/>: system_admins live outside the
/// tenant model entirely. Empty table in single-mode installs.
/// </summary>
public class SystemAdmin
{
    public string Id { get; set; } = "";
    public string Email { get; set; } = "";
    public bool MustChangePassword { get; set; }
    public DateTimeOffset? LastLoginAt { get; set; }
    public string AccountStatus { get; set; } = "active";
    public DateTimeOffset? PasswordResetIssuedAt { get; set; }
    public string? Language { get; set; }
    /// <summary>
    /// IANA zone name for rendering timestamps in the apex SPA. NULL falls back to
    /// <see cref="TimeZoneCodes.Default"/> — an operator belongs to no org, so there is no
    /// tenant default in the chain the way there is for <c>users.timezone</c>.
    /// </summary>
    public string? Timezone { get; set; }
    /// <summary>True when the operator has completed MFA enrollment.</summary>
    public bool MfaEnabled { get; set; }
    /// <summary>AES-GCM-encrypted TOTP authenticator key. Null until MFA enrollment.</summary>
    public string? MfaAuthenticatorKey { get; set; }
    /// <summary>JSON array of SHA-256 hashes of one-time MFA recovery codes. Null until enrollment.</summary>
    public string? MfaRecoveryCodes { get; set; }
    /// <summary>Random stamp rotated on every credential change so concurrent mutations are detectable.</summary>
    public string? SecurityStamp { get; set; }
    /// <summary>Monotonic session-invalidation counter. System JWTs embed this as the <c>tver</c> claim.</summary>
    public long TokenVersion { get; set; } = 1;
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>
/// Projection returned by <c>GET /api/v1/system/users</c>. Strictly control-plane: never
/// includes password_hash, tokens, packages, or any data-plane field. Per the locked
/// "control plane vs data plane" decision.
/// </summary>
public class SystemUserLookupView
{
    public string Email { get; set; } = "";
    public string TenantSlug { get; set; } = "";
    public string Role { get; set; } = "";
    public DateTimeOffset? LastLoginAt { get; set; }
    public string AccountStatus { get; set; } = "active";
    public bool MfaEnabled { get; set; }
    public DateTimeOffset? PasswordResetIssuedAt { get; set; }
    public bool MustChangePassword { get; set; }
}

/// <summary>
/// Member listing view — projected from the <c>users</c> table directly (1:1 user:tenant).
/// </summary>
public class OrgMemberView
{
    public string UserId { get; set; } = "";
    public string Email { get; set; } = "";
    public string Role { get; set; } = "";
    public string AccountType { get; set; } = "forms";
    public DateTimeOffset JoinedAt { get; set; }
    /// <summary>True when the member has completed MFA enrollment.</summary>
    public bool MfaEnabled { get; set; }
}

/// <summary>
/// Discriminator for which token table a <see cref="TokenRecord"/> was resolved from.
/// Set by <c>TokenRepository.ResolveAsync</c>; used by <c>TouchLastUsedAsync</c> to
/// dispatch the throttled <c>last_used_at</c> update to the correct table.
/// </summary>
public enum TokenSource { User, Service }

public class TokenRecord
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    public string? UserId { get; set; }
    /// <summary>
    /// Canonical JSON array of capability strings (e.g. <c>["publish:npm","read:metadata"]</c>).
    /// Populated at issuance via <c>Capabilities.TryNormalizeAndAuthorize</c> and read at
    /// auth time by <c>HasCapability</c>. NULL/malformed values deny everything.
    ///
    /// Use <see cref="CapabilitySet"/> in hot paths — it parses the JSON exactly once per
    /// resolved token and reuses the materialized set across capability checks. Mutating
    /// <see cref="Capabilities"/> after construction invalidates the cached parse.
    /// </summary>
    public string? Capabilities
    {
        get;
        set
        {
            field = value;
            CapabilitySet = null;
        }
    }
    /// <summary>
    /// Cached parse of <see cref="Capabilities"/> as an O(1) lookup set. Built on first
    /// access (auth check) and reused for every subsequent <c>HasCapability</c> /
    /// <c>ResolveTokenCapabilities</c> call against the same <see cref="TokenRecord"/>,
    /// so a request that fans out into multiple capability checks pays one Deserialize.
    /// Returns an empty set for NULL/whitespace/malformed JSON — same deny-all semantics
    /// the previous inline parsers used.
    /// </summary>
    [System.Text.Json.Serialization.JsonIgnore]
    [AllowNull]
    public IReadOnlySet<string> CapabilitySet
    {
        get
        {
            if (field is not null)
            {
                return field;
            }

            if (string.IsNullOrWhiteSpace(Capabilities))
            {
                return field = EmptyCapabilitySet;
            }

            try
            {
                string[]? list = System.Text.Json.JsonSerializer.Deserialize<string[]>(Capabilities);
                if (list is null || list.Length == 0)
                {
                    return field = EmptyCapabilitySet;
                }

                var set = new HashSet<string>(StringComparer.Ordinal);
                foreach (string c in list)
                {
                    if (!string.IsNullOrWhiteSpace(c))
                    {
                        set.Add(c);
                    }
                }

                return field = set;
            }
            catch (System.Text.Json.JsonException)
            {
                // Malformed JSON: deny-all (matches the previous inline behaviour).
                return field = EmptyCapabilitySet;
            }
        }

        private set;
    }

    private static readonly IReadOnlySet<string> EmptyCapabilitySet = new HashSet<string>(StringComparer.Ordinal);

    /// <summary>Optional free-text label captured at creation.</summary>
    public string? Description { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    /// <summary>Last successful auth timestamp; updated throttled (~60s) by the auth path.</summary>
    public DateTimeOffset? LastUsedAt { get; set; }
    public TokenSource Source { get; set; }

    /// <summary>
    /// Value to persist in <c>activity.actor_kind</c> / <c>audit_log.actor_kind</c> for events
    /// attributable to this token. <see cref="TokenSource.User"/> → <c>"user"</c> (actor_id is
    /// a users.id, resolved via the users LEFT JOIN); <see cref="TokenSource.Service"/> →
    /// <c>"service"</c> (actor_id is a service_tokens.id, resolved as <c>service:&lt;name&gt;</c>).
    /// Get-only — Dapper's setter-path mapper ignores it on hydration.
    /// </summary>
    public string ActorKind => Source switch
    {
        TokenSource.User => ActorKinds.User,
        TokenSource.Service => ActorKinds.Service,
        _ => ActorKinds.User,
    };

    /// <summary>
    /// Value to persist in <c>activity.actor_id</c> / <c>audit_log.actor_id</c>, and the only
    /// correct partner for <see cref="ActorKind"/>. A service token has no owning user —
    /// <c>TokenRepository.ResolveAsync</c> selects <c>NULL AS user_id</c> for the service
    /// branch — so its own id is the identity, and it is what the audit list queries join
    /// <c>service_tokens</c> on to render <c>service:&lt;name&gt;</c>. Passing
    /// <see cref="UserId"/> alongside <c>ActorKind</c> writes a NULL actor under a
    /// <c>'service'</c> discriminator, which no join resolves and which reads as anonymous —
    /// indistinguishable from a genuinely unauthenticated request. The two properties sit
    /// together so a call site cannot pair one with the wrong other.
    /// Get-only — Dapper's setter-path mapper ignores it on hydration.
    /// </summary>
    public string? AuditActorId => Source switch
    {
        TokenSource.Service => Id,
        _ => UserId,
    };

    /// <summary>
    /// The service token's own name, resolved alongside the token. NULL for a user token, whose
    /// display name is its owner's email and is resolved through the <c>users</c> join instead.
    /// </summary>
    public string? Name { get; set; }

    /// <summary>
    /// Value to persist in <c>activity.actor_label</c> / <c>audit_log.actor_label</c>: the actor's
    /// display name, denormalized so the row survives the disappearance of what it would otherwise
    /// join to. Non-null for a service token only, and that asymmetry is the point rather than an
    /// omission. <c>service_tokens</c> is hard-deleted on revocation, so without the stored name a
    /// revoked token's rows lose their meaning; <c>users</c> has an erasure path that deliberately
    /// keeps only a pseudonymous <c>actor_id</c> skeleton, and denormalizing an email here would
    /// put personal data at rest beyond the fixed column lists that
    /// <c>RetentionService</c> and <c>OrgRepository.RemoveOrgMemberAsync</c> null. Deriving the
    /// value here rather than letting call sites supply one is what makes that guarantee
    /// structural: no caller can put an email in this column.
    /// Get-only — Dapper's setter-path mapper ignores it on hydration.
    /// </summary>
    public string? AuditActorLabel => Source switch
    {
        TokenSource.Service => Name,
        _ => null,
    };
}

/// <summary>
/// String constants for <c>activity.actor_kind</c> / <c>audit_log.actor_kind</c>. NULL is also
/// valid — it means "anonymous" (truly unauthenticated; only reachable on pull paths when
/// <see cref="OrgSettings.AnonymousPull"/> is true) OR a legacy row written before the column
/// existed. <see cref="TokenRecord.ActorKind"/> derives one of these from a resolved token.
/// </summary>
public static class ActorKinds
{
    public const string User = "user";
    public const string Service = "service";
}

public class ServiceTokenRecord
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    public string Name { get; set; } = "";
    /// <summary>See <see cref="TokenRecord.Capabilities"/>.</summary>
    public string? Capabilities { get; set; }
    /// <summary>Optional free-text label captured at creation.</summary>
    public string? Description { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    /// <summary>Last successful auth timestamp; updated throttled (~60s) by the auth path.</summary>
    public DateTimeOffset? LastUsedAt { get; set; }
}

public class InviteRecord
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    public string Email { get; set; } = "";
    /// <summary>'member' | 'admin' | 'owner' — role the invitee receives on accept.</summary>
    public string Role { get; set; } = "member";
    public string CreatedBy { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? AcceptedAt { get; set; }
}

/// <summary>
/// Outcome of a successful invite creation: the raw token (shown to the inviter exactly once,
/// never logged) plus the stored record. A nullable return of this type is how the repository
/// reports "a pending invite for this address already exists" without throwing.
/// </summary>
/// <param name="RawToken">Unhashed invite token; only the SHA-256 of it is persisted.</param>
/// <param name="Record">The row as written.</param>
public sealed record InviteCreation(string RawToken, InviteRecord Record);

public class AllowlistEntry
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    public string PurlPattern { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
}

public class BlocklistEntry
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    public string Pattern { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>
/// A single configured upstream proxy registry for one (org, ecosystem). The org's entries for
/// an ecosystem form a priority-ordered list (ascending <see cref="Position"/>, lowest first).
/// Zero entries for an ecosystem disables proxying for it.
///
/// OCI-specific fields: <see cref="AuthType"/> drives pull authentication;
/// <see cref="TokenEndpoint"/> pins the token-exchange realm; <see cref="Prefixes"/> is the
/// first-match-wins repository-prefix routing list. <see cref="HasSecret"/> indicates whether
/// a credential is stored without exposing the secret itself.
/// </summary>
public class UpstreamRegistryEntry
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    public string Ecosystem { get; set; } = "";
    public string? Name { get; set; }
    public string Url { get; set; } = "";
    public int Position { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    // OCI-only fields (NULL for all other ecosystems).
    /// <summary>Auth mechanism: 'anonymous' | 'basic' | 'dockerhub_token_exchange'. Null for non-OCI rows.</summary>
    public string? AuthType { get; set; }
    /// <summary>Basic/token-exchange username. Null for anonymous or non-OCI rows.</summary>
    public string? Username { get; set; }
    /// <summary>Operator-pinned token-exchange realm URL. Null when not set.</summary>
    public string? TokenEndpoint { get; set; }
    /// <summary>Repository-name prefix routing list. Null for non-OCI rows.</summary>
    public IReadOnlyList<string>? Prefixes { get; set; }
    /// <summary>True when a secret/password is stored for this entry (secret is never projected).</summary>
    public bool HasSecret { get; set; }
    /// <summary>Hex: the upstream repository's signing public key (PEM), or null when it relies on a well-known key.</summary>
    public string? PublicKeyPem { get; set; }

    /// <summary>
    /// NuGet-only: base URL of this upstream's symbol server. A symbol server is a different host
    /// from the v3 index, so it cannot be derived from <see cref="Url"/>. Null disables symbol
    /// proxying for this upstream.
    /// </summary>
    public string? SymbolServerUrl { get; set; }

    /// <summary>
    /// Terraform-only: which server-side protocol this upstream speaks — null for the Provider
    /// Registry Protocol (the default), <c>"mirror"</c> for the Provider Network Mirror Protocol.
    /// No other ecosystem reads this field. See <c>ADR-terraform-provider-network-mirror</c>.
    /// </summary>
    public string? Protocol { get; set; }
}

/// <summary>
/// A per-org signature trust anchor row from <c>signature_trust_anchor</c>. One row per key
/// material block; an org may have multiple anchors for the same ecosystem (e.g. Maven has
/// both a project key and a mirror key). <c>material</c> is PUBLIC key material stored
/// plaintext — never returned by the list API, only on add confirmation.
/// </summary>
public class TrustAnchorEntry
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    public string Ecosystem { get; set; } = "";
    /// <summary>Discriminates the key material format: 'pgp' | 'spki' | 'x509' | 'sigstore_root' | 'trusted_publisher' | 'rekor_key'.</summary>
    public string AnchorKind { get; set; } = "";
    /// <summary>Optional fingerprint or subject for display — never used for trust decisions.</summary>
    public string? KeyId { get; set; }
    /// <summary>Operator-supplied display label (optional).</summary>
    public string? Label { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    /// <summary>User id of the operator who added this anchor.</summary>
    public string? CreatedBy { get; set; }

    /// <summary>
    /// False when this row's <c>(Ecosystem, AnchorKind)</c> pair has no registered material
    /// validator (<see cref="TrustAnchorPairs"/>) — meaning its material was never parsed or
    /// strength-checked and cannot produce a <c>verified</c> verdict. Computed from the shared
    /// pair set rather than stored, so it can never drift from the insert-time gate.
    /// </summary>
    public bool IsRegisteredPair => TrustAnchorPairs.IsRegistered(Ecosystem, AnchorKind);
}

public class AuditEntry
{
    public string Id { get; set; } = "";
    /// <summary>'tenant' | 'system'. system events are operator-only; tenant events are per-tenant.</summary>
    public string Scope { get; set; } = "tenant";
    public string? OrgId { get; set; }
    /// <summary>Tenant slug resolved from orgs for display; NULL for apex/system events or a deleted org.</summary>
    public string? OrgSlug { get; set; }
    public string? ActorId { get; set; }
    public string? ActorEmail { get; set; }
    public string Action { get; set; } = "";
    public string? Ecosystem { get; set; }
    public string? Purl { get; set; }
    public string? Detail { get; set; }
    /// <summary>Canonical remote IP of the actor; NULL for background paths and for rows past the pseudonymization horizon.</summary>
    public string? SourceIp { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public class VulnerabilityRecord
{
    public string Id { get; set; } = "";
    public string OsvId { get; set; } = "";
    public string Ecosystem { get; set; } = "";
    public string PackageName { get; set; } = "";
    public string? Aliases { get; set; }       // JSON array
    public string? Summary { get; set; }
    public string? Severity { get; set; }
    public double? CvssScore { get; set; }
    public string? AffectedVersions { get; set; } // JSON array
    public string? PublishedAt { get; set; }
    public string? ModifiedAt { get; set; }
    public DateTimeOffset FetchedAt { get; set; }
}

public class AffectedVersionRecord
{
    public string PackageName { get; set; } = "";
    public string Version { get; set; } = "";
    public string Purl { get; set; } = "";
    public string? Severity { get; set; }
    public double? CvssScore { get; set; }
    public string OsvId { get; set; } = "";
    public string? Summary { get; set; }
    /// <summary>OSV advisory publication time (vulnerabilities.published_at), not the version scan time.</summary>
    public string? PublishedAt { get; set; }
    public string? VulnCheckedAt { get; set; }
    public string OrgSlug { get; set; } = "";
    public string Ecosystem { get; set; } = "";
    /// <summary>
    /// ISO 8601 UTC; set when the affected version has been observed removed from upstream.
    /// NULL = still published. A distinct lifecycle signal — not a vulnerability/severity.
    /// </summary>
    public string? RevokedAt { get; set; }
    /// <summary>True when any advisory alias is in the CISA Known Exploited Vulnerabilities catalog (vulnerabilities.is_kev, refreshed by ThreatFeedRefreshService).</summary>
    public bool IsKev { get; set; }
    /// <summary>Maximum FIRST.org EPSS exploitation probability (0..1) across the advisory's aliases; NULL = not scored by EPSS or not yet checked.</summary>
    public double? EpssScore { get; set; }
    /// <summary>True when CISA's KEV catalog marks this advisory as known ransomware campaign use (vulnerabilities.kev_known_ransomware); NULL = not a KEV entry or not yet checked.</summary>
    public bool? IsKevRansomware { get; set; }
    /// <summary>
    /// Durable first-observation instant for this (version, advisory) finding
    /// (<c>package_version_vulns.first_seen_at</c>) — set once at link time and never moved by a
    /// later re-scan. Distinct from <see cref="PublishedAt"/> (the advisory's own upstream
    /// publication time) and from <see cref="VulnCheckedAt"/> (the most recent scan).
    /// </summary>
    public string? FirstSeenAt { get; set; }
}

// ── Rich OSV advisory detail (lazy detail endpoint) ───────────────────────────
//
// Projected from the stored osv_json — the full advisory captured at hydration. Records
// (not Dapper classes) because they are deserialized from the OSV JSON via the constructor
// and serialized straight back out as the API response. Field names follow the OSV schema
// (https://ossf.github.io/osv-schema/); free-form objects (database_specific, ecosystem_specific)
// round-trip as raw JsonElement rather than a hand-maintained shape. All members are nullable so
// the same shape serves both the deserialize path and the column-fallback path used when an
// advisory predates osv_json capture.

public sealed record OsvDetail(
    string? Id,
    string? SchemaVersion,
    string? Published,
    string? Modified,
    string? Withdrawn,
    string? Summary,
    string? Details,
    string[]? Aliases,
    string[]? Related,
    OsvReference[]? References,
    OsvSeverityEntry[]? Severity,
    OsvAffectedDetail[]? Affected,
    OsvCredit[]? Credits,
    JsonElement? DatabaseSpecific,
    RemediationGuidance? Remediation = null,
    ThreatIntel? ThreatIntel = null);

/// <summary>
/// Threat-feed enrichment for the advisory (vulnerabilities.is_kev / epss_score, refreshed by
/// ThreatFeedRefreshService) — computed from the stored row after parsing, never present in the
/// stored OSV JSON itself (the OSV schema has no <c>threat_intel</c> key), so round-tripping
/// <c>osv_json</c> through <see cref="OsvDetail"/> can never populate it by accident.
/// </summary>
public sealed record ThreatIntel(bool IsKev, double? EpssScore, bool? IsKevRansomware = null);

/// <summary>
/// CWE→OWASP/skill guidance computed from <see cref="OsvDetail.DatabaseSpecific"/> and
/// <see cref="OsvDetail.Affected"/> after parsing — never present in the stored OSV JSON itself
/// (the OSV schema has no <c>remediation</c> key), so round-tripping <c>osv_json</c> through this
/// record can never populate it by accident. Null when the advisory predates <c>osv_json</c>
/// capture and there's nothing to compute from; non-null (with possibly empty
/// <see cref="Entries"/>) whenever the advisory JSON itself was available to parse.
/// <see cref="FixedVersion"/> is the fix for the affected range containing the caller-supplied
/// installed version, resolved under the ecosystem's native version ordering
/// (<c>FixedVersionResolver</c>); null when no version context was supplied or nothing resolved.
/// </summary>
public sealed record RemediationGuidance(
    string[] CweIds,
    RemediationEntry[] Entries,
    string? UpgradeSkillId,
    string? FixedVersion = null);

/// <summary>One extracted CWE id, resolved against a CWE→OWASP/skill catalog. OWASP/skill fields are null when the CWE is known but unmapped.</summary>
public sealed record RemediationEntry(
    string CweId,
    string CweUrl,
    string? OwaspId,
    string? OwaspTitle,
    string? OwaspUrl,
    string? SkillId);

public sealed record OsvReference(string? Type, string? Url);

public sealed record OsvSeverityEntry(string? Type, string? Score);

public sealed record OsvCredit(string? Name, string[]? Contact, string? Type);

public sealed record OsvAffectedDetail(
    OsvAffectedPackageRef? Package,
    OsvRange[]? Ranges,
    string[]? Versions,
    JsonElement? EcosystemSpecific,
    JsonElement? DatabaseSpecific);

public sealed record OsvAffectedPackageRef(string? Ecosystem, string? Name, string? Purl);

public sealed record OsvRange(string? Type, string? Repo, OsvRangeEvent[]? Events);

public sealed record OsvRangeEvent(string? Introduced, string? Fixed, string? LastAffected, string? Limit);

public class PackageVersionLicense
{
    public string Id { get; set; } = "";
    public string PackageVersionId { get; set; } = "";
    public string LicenseSpdx { get; set; } = "";
    /// <summary>'upstream' | 'sbom' | 'manual'</summary>
    public string Source { get; set; } = "upstream";
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>The two non-denied licence-policy postures. 'allowed' is a blanket yes;
/// 'conditional' means acceptability depends on how the dependency is used, with the condition
/// itself recorded in the entry's note. Both satisfy the block-mode policy check — the
/// difference is that conditional artifacts are surfaced for review rather than refused.</summary>
public static class LicenseDispositions
{
    public const string Allowed = "allowed";
    public const string Conditional = "conditional";

    public static bool IsValid(string? value) => value is Allowed or Conditional;
}

public class LicenseAllowlistEntry
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    public string LicenseSpdx { get; set; } = "";
    /// <summary>'allowed' | 'conditional' — see <see cref="LicenseDispositions"/>.</summary>
    public string Disposition { get; set; } = LicenseDispositions.Allowed;
    /// <summary>Operator-supplied rationale: why this licence is allowed, or what condition makes
    /// it acceptable. NULL when the entry was recorded before notes existed, or nobody wrote one.</summary>
    public string? Note { get; set; }
    public string? CreatedBy { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public class LicenseBlocklistEntry
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    public string LicenseSpdx { get; set; } = "";
    /// <summary>Operator-supplied rationale for the refusal.</summary>
    public string? Note { get; set; }
    public string? CreatedBy { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}


public class SpdxLicense
{
    public string Identifier { get; set; } = "";
    public string Name { get; set; } = "";
    public bool IsOsiApproved { get; set; }
    public bool IsFsfLibre { get; set; }
    public bool IsDeprecated { get; set; }
    public string? ReferenceUrl { get; set; }
    /// <summary>'permissive' | 'weak-copyleft' | 'strong-copyleft' | 'network-copyleft' | 'public-domain' | 'unclassified'</summary>
    public string Copyleft { get; set; } = "unclassified";
}

/// <summary>Full-text projection of a single spdx_license row, served on demand by the
/// license-text endpoint. <see cref="LicenseText"/> is NULL for a known identifier whose
/// text was not bundled (custom or post-bundle SPDX additions).</summary>
public sealed record SpdxLicenseText(string Identifier, string Name, string? LicenseText);

/// <summary>One row in the admin review queue: a single canonical SPDX license leaf seen
/// during ingestion for this tenant that is on neither the allow- nor block-list. Compound
/// expressions are split into their leaves before reaching this projection, so every entry is
/// an individually actionable id.</summary>
public class LicenseReviewEntry
{
    public string LicenseSpdx { get; set; } = "";
    public int PackageCount { get; set; }
    public DateTimeOffset FirstSeen { get; set; }
    /// <summary>True if a matching row in spdx_license is marked deprecated.</summary>
    public bool IsDeprecated { get; set; }
    /// <summary>Human-readable license name from spdx_license; NULL for identifiers absent
    /// from the bundled SPDX list (custom or compound expressions).</summary>
    public string? Name { get; set; }
    /// <summary>Copyleft classification from spdx_license ('permissive' | 'weak-copyleft' |
    /// 'strong-copyleft' | 'network-copyleft' | 'public-domain' | 'unclassified'). Defaults to
    /// 'unclassified' when no matching spdx_license row exists.</summary>
    public string Copyleft { get; set; } = "unclassified";
}

public class ActivityEntry
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    public string Ecosystem { get; set; } = "";
    public string Purl { get; set; } = "";
    public string EventType { get; set; } = "";
    public string? ActorId { get; set; }
    public string? ActorEmail { get; set; }
    public string? Detail { get; set; }
    public string? SourceIp { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>
/// Per-tenant SAML 2.0 SP configuration. <c>FormsLoginEnabled=false</c> requires a recent
/// successful test (<see cref="LastTestAt"/>) so a misconfigured IdP can't lock the tenant out.
/// </summary>
public class TenantSamlConfig
{
    public string OrgId { get; set; } = "";
    public bool Enabled { get; set; }
    public bool FormsLoginEnabled { get; set; } = true;
    public string? IdpEntityId { get; set; }
    public string? IdpSsoUrl { get; set; }
    /// <summary>Base64-encoded X.509 signing certificate parsed from uploaded metadata.</summary>
    public string? IdpSigningCert { get; set; }
    /// <summary>Raw uploaded IdP metadata XML, kept for re-parsing and audit.</summary>
    public string? MetadataXml { get; set; }
    /// <summary>SP entity ID. NULL = derive at request time from <c>https://{host}/saml/metadata</c>.</summary>
    public string? SpEntityId { get; set; }
    public string NameIdFormat { get; set; } = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    /// <summary>Override attribute name for email. NULL = use NameID.</summary>
    public string? EmailAttribute { get; set; }
    public string? ButtonLabel { get; set; }
    public DateTimeOffset? LastTestAt { get; set; }
    public string? LastTestEmail { get; set; }
    /// <summary>JSON array of { type, values[] } from the latest successful test assertion. NULL until a test is run.</summary>
    public string? LastTestClaims { get; set; }
    /// <summary>Admin-pinned X.509 signing cert (base64 DER). When set, this is the sole trust anchor (overrides metadata cert).</summary>
    public string? IdpSigningCertOverride { get; set; }
    /// <summary>Claim type to read role/group values from. NULL = use built-in list (Role, groups, etc.).</summary>
    public string? RoleAttribute { get; set; }
    /// <summary>JSON object mapping IdP role value → Dependably role ("owner"|"admin"|"member"|"auditor").</summary>
    public string? RoleMapping { get; set; }
    /// <summary>Fallback role when no mapping matches. Defaults to "member".</summary>
    public string DefaultRole { get; set; } = "member";
    /// <summary>
    /// Opt-in ceiling raise for IdP-driven role assignment: false (default) caps IdP-assignable
    /// roles at member/auditor; true additionally permits admin. "owner" is never IdP-assignable.
    /// </summary>
    public bool IdpCanAssignAdmin { get; set; }
    /// <summary>
    /// Stage of the last cert-expiry audit event emitted for this tenant's effective IdP signing
    /// cert. One of "30", "14", "7", "1", or "expired". NULL means no alert has been emitted yet
    /// (or the cert was replaced since the last alert). The daily sweep compares this against the
    /// current expiry window to decide whether a new audit event is needed.
    /// </summary>
    public string? CertExpiryAlertStage { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>
/// IdP-issued identity linked to a local <see cref="User"/>. Identity is
/// <c>(IdpEntityId, NameId)</c> — never email — so login keeps working when the IdP changes
/// the user's email and cross-IdP collisions on the same email are impossible.
/// </summary>
public class ExternalIdentity
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    public string UserId { get; set; } = "";
    public string IdpEntityId { get; set; } = "";
    public string NameId { get; set; } = "";
    public string? EmailSnapshot { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? LastLoginAt { get; set; }
}

/// <summary>
/// Admin-authored banner shown to authenticated users. Two scopes:
/// <c>scope='tenant'</c> rows are authored by tenant admins for their own org;
/// <c>scope='system'</c> rows are authored by system_admin operators and shown across
/// all tenants. Dismissed per-user via <see cref="BannerDismissal"/>.
/// </summary>
public class Banner
{
    public string Id { get; set; } = "";
    public string Scope { get; set; } = "tenant";
    public string? OrgId { get; set; }
    public string Severity { get; set; } = "info";
    public string Body { get; set; } = "";
    public string? LinkUrl { get; set; }
    public string? LinkLabel { get; set; }
    public string TargetRole { get; set; } = "all";
    public string StartsAt { get; set; } = "";
    public string EndsAt { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public string? CreatedBy { get; set; }
    public string CreatedAt { get; set; } = "";
}

/// <summary>
/// Records that a specific user dismissed a specific banner. Server-side so dismissal
/// persists across devices. Cascade-deleted when the banner or user is removed.
/// </summary>
public class BannerDismissal
{
    public string BannerId { get; set; } = "";
    public string UserId { get; set; } = "";
    public string DismissedAt { get; set; } = "";
}

// ── Projects plane ──────────────────────────────────────────────────────────────
// Rows describing an application a team builds and the SBOM/VEX/SARIF documents uploaded
// about it. Nothing here is an artefact this registry serves, so no registry policy or
// serve path reads these.

/// <summary>
/// An application or service a team builds, or a collection grouping several of them.
/// <see cref="Kind"/> discriminates the two; a collection holds no versions and accepts no
/// document uploads. <see cref="ParentId"/> is the containing collection, NULL at the root.
/// </summary>
public class Project
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    /// <summary>The containing collection, or null at the root of the tree.</summary>
    public string? ParentId { get; set; }
    /// <summary><c>project</c> or <c>collection</c>.</summary>
    public string Kind { get; set; } = "project";
    public string Name { get; set; } = "";
    /// <summary>CycloneDX component.type vocabulary; seeded from an uploaded SBOM's metadata.</summary>
    public string Classifier { get; set; } = "application";
    public string? Description { get; set; }
    /// <summary>
    /// Whether this application is still in service. A retired project contributes nothing to the
    /// blast radius however many of its releases are active — see
    /// <see cref="ProjectLifecycle"/> for the predicate the two flags combine into.
    /// </summary>
    public bool IsActive { get; set; } = true;
    public string? CreatedBy { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>
/// One release of a <see cref="Project"/>, labelled by an opaque version string.
/// <see cref="IsLatest"/> is the only notion of "latest"; a partial unique index makes two
/// latest rows for one project impossible at commit.
/// </summary>
public class ProjectVersion
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    public string ProjectId { get; set; } = "";
    public string Version { get; set; } = "";
    public bool IsLatest { get; set; }
    /// <summary>
    /// Whether this release is still deployed somewhere. Orthogonal to <see cref="IsLatest"/>:
    /// a release can be latest and retired (nothing runs the newest build yet) or active and
    /// superseded (an older build still serving traffic).
    /// </summary>
    public bool IsActive { get; set; } = true;
    /// <summary>
    /// <c>pass</c>, <c>warn</c> or <c>violation</c> from the last policy evaluation. Null means
    /// the version has never been evaluated, which is not the same as passing.
    /// </summary>
    public string? PolicyStatus { get; set; }
    public string? CreatedBy { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>
/// Metadata for one uploaded SBOM/VEX/SARIF original. The bytes live verbatim in the registry
/// blob tier under <see cref="BlobKey"/>; upload is latest-wins per (version, doc type).
/// </summary>
public class ProjectDocument
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    public string ProjectVersionId { get; set; } = "";
    /// <summary><c>sbom</c>, <c>vex</c> or <c>sarif</c>.</summary>
    public string DocType { get; set; } = "";
    /// <summary><c>cyclonedx-json</c>, <c>spdx-json</c>, <c>openvex-json</c> or <c>sarif-json</c>.</summary>
    public string Format { get; set; } = "";
    /// <summary>The document's own spec version, e.g. <c>1.6</c> or <c>2.1.0</c>.</summary>
    public string? SpecVersion { get; set; }
    public string? ToolName { get; set; }
    public string? ToolVersion { get; set; }
    public string Sha256 { get; set; } = "";
    public long SizeBytes { get; set; }
    /// <summary>Built by <see cref="Storage.BlobKeys.ProjectDocument"/>; registry tier.</summary>
    public string BlobKey { get; set; } = "";
    public string? UploadedBy { get; set; }
    /// <summary>
    /// metadata.lifecycles as a JSON array of <c>{"phase"}</c> or <c>{"name","description"}</c>
    /// entries, or null when the uploaded document declared none.
    /// </summary>
    public string? Lifecycles { get; set; }
    /// <summary>
    /// The ingest projection revision that wrote this document's derived rows. Compared against
    /// <see cref="Sbom.SbomIngestVersion.Current"/> by the dedup arm, so a widened projection
    /// re-merges an unchanged document once instead of short-circuiting on the hash alone.
    /// </summary>
    public int IngestVersion { get; set; }
    /// <summary>
    /// CISA D2's verdict from verifying this document's enveloped JSF signature —
    /// <c>ProvenanceStatuses.Verified</c>/<c>Unsigned</c>, <c>SbomSignatureVerdict.FailedStatus</c>
    /// (cryptographically invalid), <c>SbomSignatureVerdict.UnanchoredStatus</c> (this registry
    /// holds no pinned anchor for the claimed keyId), or null for a doc_type/format this policy
    /// does not cover, or a document uploaded while <c>verify_sbom_signatures</c> was 'off'.
    /// </summary>
    public string? SignatureStatus { get; set; }
    /// <summary>The signing key's fingerprint, set only when <see cref="SignatureStatus"/> is <c>verified</c>.</summary>
    public string? SignatureKeyId { get; set; }
    /// <summary>
    /// X4/D8b (SBOM Tool Version) read back: true only when the original producing tool's own
    /// entry (the one <see cref="ToolName"/>/<see cref="ToolVersion"/> came from) carried
    /// dependably's own <c>dependably:tool-version-status</c> property — a dependably export
    /// re-ingested here. False for every other document, including one that names no tool at all.
    /// </summary>
    public bool ToolVersionExplicitlyUnknown { get; set; }
    public DateTimeOffset UploadedAt { get; set; }
}

/// <summary>
/// One component of one project version's SBOM. The verbatim <see cref="Purl"/> sits beside the
/// parsed <see cref="Ecosystem"/>/<see cref="PurlName"/>/<see cref="Version"/> triple so registry
/// cross-links and scan batching are equality-indexed; the parsed columns are null when the purl
/// is absent or names a type <c>PurlNormalizer</c> does not map.
/// </summary>
public class SbomComponent
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    public string ProjectVersionId { get; set; } = "";
    /// <summary>Verbatim from the SBOM; null when the component declares none.</summary>
    public string? Purl { get; set; }
    public string? Ecosystem { get; set; }
    public string? PurlName { get; set; }
    public string? Version { get; set; }
    public string Name { get; set; } = "";
    /// <summary>CycloneDX components[].type.</summary>
    public string? ComponentType { get; set; }
    /// <summary>
    /// The raw CycloneDX scope (<c>required</c>/<c>optional</c>/<c>excluded</c>). Display only —
    /// unreliable in the wild, which is why it is never the dev/prod signal.
    /// </summary>
    public string? SbomScope { get; set; }
    /// <summary>
    /// The authoritative dev/prod signal (<c>dev</c>/<c>runtime</c>/<c>unknown</c>), owned by the
    /// reachability scanner. Defaults to <c>unknown</c> so an unclassified component reads as
    /// unclassified rather than as production.
    /// </summary>
    public string DependencyScope { get; set; } = "unknown";
    /// <summary><c>direct</c>, <c>transitive</c>, <c>root</c> or <c>graph-unknown</c>.</summary>
    public string? DependencyKind { get; set; }
    /// <summary>JSON array of purls from the dependency root to this component.</summary>
    public string? DependencyPath { get; set; }
    /// <summary>SPDX expression declared by the component's licences.</summary>
    public string? LicenseSpdx { get; set; }
    /// <summary>Scan-pass stamp. Null keeps the row in the unscanned bucket.</summary>
    public DateTimeOffset? VulnCheckedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

/// <summary>
/// Scan-result link from an <see cref="SbomComponent"/> to a row of the global
/// <c>vulnerabilities</c> table. A table of its own rather than a third owner arm on
/// <c>package_version_vulns</c>, so registry policy surfaces never count application inventory.
/// Carries no org id: the row is always reached through its component, which carries one.
/// </summary>
public class SbomComponentVuln
{
    public string Id { get; set; } = "";
    public string ComponentId { get; set; } = "";
    public string VulnId { get; set; } = "";
    public DateTimeOffset CheckedAt { get; set; }
}

/// <summary>
/// The single (product, vulnerability) statement for a project version: the VEX arm and the
/// reachability arm on one row, each written by its own ingester and by manual triage.
/// <see cref="PurlKey"/> is the version-less canonical purl, so triage survives a component
/// bump; <see cref="VulnKey"/> is a plain advisory id with no foreign key, because a VEX or
/// SARIF document legitimately cites advisories the advisory feed has never served.
/// </summary>
public class ProjectVulnAnalysis
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    public string ProjectVersionId { get; set; } = "";
    /// <summary>Version-less canonical purl.</summary>
    public string PurlKey { get; set; } = "";
    /// <summary>Canonical advisory id, CVE preferred. Deliberately not a foreign key.</summary>
    public string VulnKey { get; set; } = "";
    /// <summary>CycloneDX analysis vocabulary; OpenVEX states are normalized into it on import.</summary>
    public string? VexState { get; set; }
    public string? VexJustification { get; set; }
    public string? VexResponse { get; set; }
    public string? VexDetail { get; set; }
    /// <summary><c>upload</c> when a document set it, <c>manual</c> when an operator did.</summary>
    public string? VexSource { get; set; }
    /// <summary><c>reachable</c>, <c>not-observed</c>, <c>unknown</c> or <c>imported-not-called</c>.</summary>
    public string? Reachability { get; set; }
    /// <summary><c>high</c>, <c>medium</c> or <c>low</c>.</summary>
    public string? Confidence { get; set; }
    public bool SarifSuppressed { get; set; }
    /// <summary>The SARIF security-severity property, when the producer carries one.</summary>
    public double? SecuritySeverity { get; set; }
    /// <summary><c>asserted</c> or <c>representative</c>.</summary>
    public string? SeverityOrigin { get; set; }
    /// <summary>The producer partial fingerprint this row was matched on.</summary>
    public string? Fingerprint { get; set; }
    public string? UpdatedBy { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>
/// One materialized policy violation: which evaluator arm fired, on which component, over which
/// advisory or licence. Materialized so an alert fires once and a project list can roll findings
/// up without fanning out per row; restamped at scan completion, on a triage change, and by the
/// nightly pass. Nothing here denies a serve.
/// </summary>
public class SbomPolicyFinding
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    public string ProjectVersionId { get; set; } = "";
    public string ComponentId { get; set; } = "";
    /// <summary><c>malicious</c>, <c>kev</c>, <c>epss</c>, <c>cvss</c> or <c>license</c>.</summary>
    public string Arm { get; set; } = "";
    /// <summary>Advisory id for the four vulnerability arms; null for the licence arm.</summary>
    public string? VulnKey { get; set; }
    /// <summary>Offending SPDX expression for the licence arm; null for the vulnerability arms.</summary>
    public string? LicenseSpdx { get; set; }
    /// <summary>JSON detail naming the threshold that was crossed.</summary>
    public string? Detail { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
