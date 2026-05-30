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
    /// Tenant lifecycle gate. 'active' admits writes; 'suspended'/'archived'/'deleting' cause
    /// <see cref="Storage.ITenantStorageResolver"/> to raise <see cref="Storage.TenantNotReadyException"/>.
    /// system_admin can toggle between 'active' and 'suspended' from the Tenants page;
    /// 'archived' and 'deleting' are enterprise-only.
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
    public int? KeepVersions { get; set; }
    public int? KeepDays { get; set; }
    public int? ActivityRetentionDays { get; set; }
    /// <summary>'off' | 'warn' | 'block'</summary>
    public string LicenseEnforcementMode { get; set; } = "off";
    public bool ProxyPassthroughEnabled { get; set; } = true;
    public double MaxOsvScoreTolerance { get; set; } = 10.0;
    /// <summary>
    /// Supply-chain hold: a proxy-fetched version is blocked at first-fetch when
    /// (now − upstream published_at) is below this many hours. NULL = policy off.
    /// Evaluated in <see cref="Protocol.BlockGateService"/>; fail-open when the upstream
    /// publish timestamp is missing.
    /// </summary>
    public int? MinReleaseAgeHours { get; set; }
    /// <summary>BCP-47 short code (e.g. "en", "fr"). New users in this tenant inherit this value.</summary>
    public string DefaultLanguage { get; set; } = "en";
    /// <summary>
    /// #45 replacement policy. When true, publishing a duplicate (name, version) overwrites
    /// the existing artefact and emits a <c>package.replace</c> audit event recording both
    /// hashes. Default false — the strict immutable-coordinate behaviour.
    /// </summary>
    public bool AllowVersionOverwrite { get; set; }
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
    public DateTimeOffset CreatedAt { get; set; }
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
    /// Paired with <see cref="UpstreamIntegrityAlgorithm"/>. NULL for uploaded versions and
    /// legacy rows.
    /// </summary>
    public string? UpstreamIntegrityValue { get; set; }
    /// <summary>
    /// Tag describing how to interpret <see cref="UpstreamIntegrityValue"/>:
    /// <c>'sha256'</c> (hex), <c>'sha512-sri'</c>, or <c>'sha512-b64'</c>.
    /// </summary>
    public string? UpstreamIntegrityAlgorithm { get; set; }
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
}

/// <summary>
/// Discriminator for which token table a <see cref="TokenRecord"/> was resolved from.
/// Set by <c>TokenRepository.ResolveAsync</c>; used by <c>TouchLastUsedAsync</c> to
/// dispatch the throttled <c>last_used_at</c> update to the correct table.
/// </summary>
public enum TokenSource { User, Service }

public class TokenRecord
{
    private string? _capabilitiesJson;
    private IReadOnlySet<string>? _parsedCapabilities;

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
        get => _capabilitiesJson;
        set
        {
            _capabilitiesJson = value;
            _parsedCapabilities = null;
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
    public IReadOnlySet<string> CapabilitySet
    {
        get
        {
            if (_parsedCapabilities is not null) return _parsedCapabilities;
            if (string.IsNullOrWhiteSpace(_capabilitiesJson))
                return _parsedCapabilities = EmptyCapabilitySet;
            try
            {
                var list = System.Text.Json.JsonSerializer.Deserialize<string[]>(_capabilitiesJson);
                if (list is null || list.Length == 0)
                    return _parsedCapabilities = EmptyCapabilitySet;
                var set = new HashSet<string>(StringComparer.Ordinal);
                foreach (var c in list)
                    if (!string.IsNullOrWhiteSpace(c)) set.Add(c);
                return _parsedCapabilities = set;
            }
            catch (System.Text.Json.JsonException)
            {
                // Malformed JSON: deny-all (matches the previous inline behaviour).
                return _parsedCapabilities = EmptyCapabilitySet;
            }
        }
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

public class AuditEntry
{
    public string Id { get; set; } = "";
    /// <summary>'tenant' | 'system'. system events are operator-only; tenant events are per-tenant.</summary>
    public string Scope { get; set; } = "tenant";
    public string? OrgId { get; set; }
    public string? ActorId { get; set; }
    public string? ActorEmail { get; set; }
    public string Action { get; set; } = "";
    public string? Ecosystem { get; set; }
    public string? Purl { get; set; }
    public string? Detail { get; set; }
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
    public string? VulnCheckedAt { get; set; }
    public string OrgSlug { get; set; } = "";
    public string Ecosystem { get; set; } = "";
}

public class PackageVersionLicense
{
    public string Id { get; set; } = "";
    public string PackageVersionId { get; set; } = "";
    public string LicenseSpdx { get; set; } = "";
    /// <summary>'upstream' | 'sbom' | 'manual'</summary>
    public string Source { get; set; } = "upstream";
    public DateTimeOffset CreatedAt { get; set; }
}

public class LicenseAllowlistEntry
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    public string LicenseSpdx { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
}

public class LicenseBlocklistEntry
{
    public string Id { get; set; } = "";
    public string OrgId { get; set; } = "";
    public string LicenseSpdx { get; set; } = "";
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

/// <summary>One row in the admin review queue: a SPDX identifier seen during ingestion
/// for this tenant that is on neither the allow- nor block-list.</summary>
public class LicenseReviewEntry
{
    public string LicenseSpdx { get; set; } = "";
    public int PackageCount { get; set; }
    public DateTimeOffset FirstSeen { get; set; }
    /// <summary>True if the SPDX string contains a compound operator (OR / AND / WITH).
    /// Compound expressions currently bypass policy lookups; the UI surfaces them but
    /// disables Approve/Block.</summary>
    public bool IsCompound { get; set; }
    /// <summary>True if a matching row in spdx_license is marked deprecated.</summary>
    public bool IsDeprecated { get; set; }
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
