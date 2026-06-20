using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Caching;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Api;

// Shared request DTOs for the org-scoped controllers. One file keeps the
// surface discoverable: an admin looking for "what does the PATCH user role endpoint
// accept" finds PatchRoleRequest here without bouncing through controllers.

public sealed record CreateOrgRequest(string Slug);

public sealed record UpdateOrgSettingsRequest(
    bool AnonymousPull,
    bool AllowlistMode,
    long? MaxUploadBytes,
    long? MaxUploadBytesPyPi,
    long? MaxUploadBytesNpm,
    long? MaxUploadBytesNuGet,
    long? MaxUploadBytesMaven = null,
    long? MaxUploadBytesRpm = null,
    long? MaxUploadBytesOci = null,
    long? MaxUploadBytesCargo = null,
    string? DefaultLanguage = null,
    bool? AllowVersionOverwrite = null,
    bool? AirGapped = null);

public sealed record UpdateRetentionRequest(
    int? KeepVersions,
    int? KeepDays,
    int? ActivityRetentionDays);

public sealed record UpdateProxySettingsRequest(
    bool ProxyPassthroughEnabled,
    double MaxOsvScoreTolerance,
    int? MinReleaseAgeHours = null,
    string? BlockDeprecated = null,
    string? BlockMalicious = null,
    string? BlockKev = null,
    double? MaxEpssTolerance = null,
    string? BlockInstallScripts = null,
    string? VerifyNpmSignatures = null,
    string? VerifyNuGetSignatures = null,
    string? VerifyPyPiAttestations = null,
    string? VerifyRpmSignatures = null,
    string? VerifyMavenSignatures = null);

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
    string? Host = null);

public sealed record ReorderUpstreamRegistryRequest(IReadOnlyList<string> Ids);

public sealed record PatchRoleRequest(string Role);

// DI-injected dependency aggregate retained for OrgController's remaining (packages + stats +
// setup) surface. Most controllers split out take their own focused dependency lists.
public sealed record OrgControllerServices(
    OrgRepository Orgs,
    PackageRepository Packages,
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
    IConfiguration Config,
    ILogger<OrgController> Logger,
    ProblemResults Problems,
    LicenseRepository Licenses,
    VulnerabilityRepository Vulns,
    IPublicUrlBuilder Urls,
    IAuditEmitter AuditEmitter,
    IMemoryCache Cache,
    MetadataResponseCache<RpmMergedRepodataKey, MergedRepodataCache> RpmMergedCache,
    RenderedResponseCache<RpmLocalRepodataKey> RpmLocalCache,
    CacheArtifactRepository CacheArtifacts,
    TenantArtifactAccessRepository TenantAccess,
    TimeProvider Time);
