using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Caching;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;

namespace Dependably.Api;

// Shared request DTOs for the org-scoped controllers. One file keeps the
// surface discoverable: an admin looking for "what does the PATCH user role endpoint
// accept" finds PatchRoleRequest here without bouncing through controllers.

public sealed record CreateOrgRequest(string Slug);

// AnonymousPull and AllowlistMode are nullable so a partial PUT can omit them without the
// JSON binder coercing the absent value to false. Both are security gates whose stored value
// may already be the enforcing one: a settings tab that no longer renders the allowlist toggle,
// or a scripted body carrying only one field, must not silently disable allowlist enforcement
// (or flip anonymous pull) as a side effect of writing something else. Null flows through to
// OrgSettingsRepository, which COALESCEs it against the stored column (falling back to the
// schema default, 0, on first insert). Same leave-unchanged-on-absent contract as
// AirGapped / RequireMfa / VersionOverwritePolicy below and as the proxy-settings gates.
public sealed record UpdateOrgSettingsRequest(
    bool? AnonymousPull = null,
    bool? AllowlistMode = null,
    long? MaxUploadBytes = null,
    long? MaxUploadBytesPyPi = null,
    long? MaxUploadBytesNpm = null,
    long? MaxUploadBytesNuGet = null,
    long? MaxUploadBytesMaven = null,
    long? MaxUploadBytesRpm = null,
    long? MaxUploadBytesOci = null,
    long? MaxUploadBytesCargo = null,
    string? DefaultLanguage = null,
    // IANA zone name for rendering stored instants. null = leave unchanged.
    string? DefaultTimezone = null,
    bool? AllowVersionOverwrite = null,
    bool? AirGapped = null,
    // Tri-state same-version-push org policy. null = leave unchanged.
    // 'block' | 'exception' | 'allow'. Validated by OrgSettingsController.
    string? VersionOverwritePolicy = null,
    // Per-tenant MFA enrollment requirement. null = leave unchanged.
    bool? RequireMfa = null);

// Per-tenant RPM hosted-publishing posture override. null (inherit instance env) | 'passthrough' |
// 'merged'. Validated by OrgSettingsController.UpdateRpmUpstreamMode.
public sealed record UpdateRpmUpstreamModeRequest(string? Mode);

public sealed record UpdateRetentionRequest(
    int? KeepVersions,
    int? KeepDays,
    int? ActivityRetentionDays,
    int? PurgeUnlistedAfterDays = null);

// ProxyPassthroughEnabled and MaxOsvScoreTolerance are nullable so a partial PUT can omit them
// without the JSON binder silently coercing the absent value to false / 0.0 — see
// ProxyPolicySettings for the leave-unchanged-on-absent contract this DTO feeds.
//
// MinReleaseAgeHours and MaxEpssTolerance are Optional<T> rather than a plain nullable: both
// columns' own "gate disabled" domain value IS null, so a plain nullable can only tell "absent"
// and "explicitly cleared" apart by picking one meaning and losing the other. Optional<T> keeps
// all three states distinguishable end to end — see Optional<T> and ProxyPolicySettings.
//
// Those same two fields are declared as init-only properties below the primary constructor
// rather than as constructor parameters: the OpenAPI schema exporter reads a constructor
// parameter's default value via reflection (ParameterInfo.DefaultValue) to embed a JSON Schema
// "default", and a custom-struct parameter whose default is `default(Optional<T>)` reflects back
// as a bare CLR null (a custom struct's `default` literal doesn't round-trip through parameter
// metadata the way a primitive's does) — the exporter then tries to unbox that null into the
// non-nullable Optional<T> struct and throws, 500ing /openapi/management.json. A property not
// tied to a constructor parameter carries no reflected default, so the exporter never hits that
// path. System.Text.Json still binds them correctly from JSON either way: any body property not
// consumed by the primary constructor is set via its property setter after construction.
public sealed record UpdateProxySettingsRequest(
    bool? ProxyPassthroughEnabled = null,
    double? MaxOsvScoreTolerance = null,
    string? BlockDeprecated = null,
    string? BlockMalicious = null,
    string? BlockKev = null,
    string? BlockInstallScripts = null,
    string? VerifyNpmSignatures = null,
    string? VerifyNuGetSignatures = null,
    string? VerifyPyPiAttestations = null,
    string? VerifyRpmSignatures = null,
    string? VerifyMavenSignatures = null,
    string? BlockRevoked = null,
    string? VerifyTerraformSignatures = null)
{
    public Optional<int?> MinReleaseAgeHours { get; init; }
    public Optional<double?> MaxEpssTolerance { get; init; }
}

// Scope is retained as a nullable field purely so the controller can detect callers still
// sending the retired field and return a clear 400. The repository never sees it.
public sealed record CreateTokenRequest(
    DateTimeOffset? ExpiresAt,
    IReadOnlyList<string>? Capabilities = null,
    string? Scope = null,
    string? Description = null);

public sealed record CreateServiceTokenRequest(
    string Name,
    DateTimeOffset? ExpiresAt,
    IReadOnlyList<string>? Capabilities = null,
    string? Scope = null,
    string? Description = null);

public sealed record CreateInviteRequest(string Email, string? Role = "member");

public sealed record AllowlistRequest(string PurlPattern);

public sealed record BlocklistRequest(string Pattern);

public sealed record ReservedNamespaceRequest(string Ecosystem, string Pattern);

public sealed record InstallScriptAllowlistRequest(
    string Ecosystem,
    string Name,
    string? VersionPattern = null);

public sealed record AddUpstreamRegistryRequest(
    string Ecosystem,
    string? Url = null,
    string? Name = null,
    // OCI-only fields — ignored for non-OCI ecosystems.
    string? AuthType = null,
    string? Username = null,
    string? Secret = null,
    string? TokenEndpoint = null,
    IReadOnlyList<string>? Prefixes = null,
    // Non-OCI field — the registry URL for non-OCI ecosystems.
    string? Host = null,
    // Terraform-only field — which server-side protocol this upstream speaks. Null (the Provider
    // Registry Protocol) or "mirror" (the Provider Network Mirror Protocol); rejected for every
    // other ecosystem.
    string? Protocol = null);

public sealed record ReorderUpstreamRegistryRequest(IReadOnlyList<string> Ids);

/// <summary>
/// Sets or clears a NuGet upstream's symbol-server base URL. Null or empty CLEARS it, which turns
/// symbol proxying off for that upstream.
/// </summary>
public sealed record SetSymbolServerRequest(string? SymbolServerUrl);

// Body for PATCH /api/v1/packages/{eco}/{name}/version-overwrite.
// null Override clears the per-package setting (inherit org policy).
public sealed record SetPackageVersionOverwriteRequest(string? Override = null);

public sealed record PatchRoleRequest(string Role);

// DI-injected dependency aggregate retained for OrgController's remaining (packages + stats +
// setup) surface. Most controllers split out take their own focused dependency lists.
public sealed record OrgControllerServices(
    OrgRepository Orgs,
    PackageRepository Packages,
    ArtifactInventoryRepository Inventory,
    PackageVersionFilesRepository VersionFiles,
    NuGetSymbolIndexRepository SymbolIndex,
    PackageAnalyticsRepository PackageAnalytics,
    StatsSnapshotRepository StatsSnapshots,
    TokenRepository Tokens,
    InviteRepository Invites,
    AllowlistRepository Allowlist,
    BlocklistRepository Blocklist,
    AuditRepository Audit,
    OrgAccessGuard Guard,
    IBlobStore Blobs,
    TieredBlobStorage BlobStorage,
    OciOrphanBlobDeleter OrphanBlobs,
    IConfiguration Config,
    ILogger<OrgController> Logger,
    ProblemResults Problems,
    LicenseRepository Licenses,
    VulnerabilityRepository Vulns,
    IPublicUrlBuilder Urls,
    IAuditEmitter AuditEmitter,
    MetadataInvalidationCoordinator Invalidation,
    CacheArtifactRepository CacheArtifacts,
    TenantArtifactAccessRepository TenantAccess,
    TimeProvider Time);
