using Dependably.Infrastructure.Audit;
using Dependably.Protocol;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Dependably.Infrastructure;

/// <summary>
/// IServiceCollection extension methods that group Core DI registrations by subsystem.
/// Used from <c>Program.ConfigureBuilder</c> so the bootstrap reads as a discoverable
/// list of subsystem wires (AddRepositories → AddVulnerabilityScanning → AddThreatFeeds)
/// rather than a wall of AddSingleton calls. Management-plane wiring (SIEM, webhook dispatch,
/// invite mail, management repositories) lives in the Dependably.Management assembly.
/// </summary>
public static partial class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Core <c>*Repository</c> set + the async batched writers + per-tier storage
    /// repositories. Singleton because repositories hold no per-request state — they take
    /// <see cref="IMetadataStore"/> and open a fresh connection per call. Management-only
    /// repositories (org settings, SAML config, invites, banners, webhook subscriptions, …) are
    /// registered by the management wiring in Dependably.Management.
    /// </summary>
    public static IServiceCollection AddDependablyRepositories(
        this IServiceCollection services, IConfiguration config)
    {
        // Core repositories
        // The session-validity cache is dropped on a deployment with peer replicas so a
        // revocation performed on one replica binds on every other one's next request
        // instead of after its TTL — see SessionRevocationCachePolicy.
        services.AddSingleton(sp => new UserTokenVersionStore(
            sp.GetRequiredService<IMetadataStore>(),
            SessionRevocationCachePolicy.SessionCacheOrNull(sp)));
        services.AddSingleton<OrgRepository>();
        services.AddSingleton<ArtifactInventoryRepository>();
        services.AddSingleton<PackageRepository>();
        services.AddSingleton<PackageVersionFilesRepository>();
        services.AddSingleton<NuGetSymbolIndexRepository>();
        // Scoped, not singleton: it resolves IBlobStore, which is request-scoped for the
        // tier-resolving decorator.
        services.AddScoped<NuGetSymbolIndexer>();
        services.AddSingleton<StatsSnapshotRepository>();
        services.AddSingleton<OrgStatsHistoryRepository>();
        services.AddSingleton<TokenRepository>();
        // Async batched activity writer. The hosted service drains the channel into
        // batched INSERTs so the download/push hot paths no longer block on a SQLite
        // writer-lock acquisition per row. Capacity is operator-configurable via
        // ACTIVITY_WRITER_QUEUE_CAPACITY; defaults to ActivityWriter.DefaultChannelCapacity.
        int activityCapacity = int.TryParse(config["ACTIVITY_WRITER_QUEUE_CAPACITY"], out int ac) && ac > 0
            ? ac : ActivityWriter.DefaultChannelCapacity;
        services.AddSingleton(new ActivityWriter(activityCapacity));
        services.AddSingleton<ActivityWriterHostedService>();
        services.AddHostedService(sp => sp.GetRequiredService<ActivityWriterHostedService>());
        // Async batched download-count writer. The hosted service aggregates increments
        // per versionId/purl within each drain batch and issues one UPDATE per unique key,
        // removing synchronous DB writes from every download-serve path. Capacity is
        // configurable via DOWNLOAD_COUNT_WRITER_QUEUE_CAPACITY.
        int downloadCapacity = int.TryParse(config["DOWNLOAD_COUNT_WRITER_QUEUE_CAPACITY"], out int dc) && dc > 0
            ? dc : DownloadCountWriter.DefaultChannelCapacity;
        services.AddSingleton(new DownloadCountWriter(downloadCapacity));
        services.AddSingleton<DownloadCountWriterHostedService>();
        services.AddHostedService(sp => sp.GetRequiredService<DownloadCountWriterHostedService>());
        services.AddSingleton<AuditRepository>();
        services.AddSingleton<AuditEventRepository>();
        services.AddSingleton<Privacy.PersonalDataExportRepository>();
        services.AddSingleton<BackgroundJobRunRepository>();
        services.AddSingleton<AllowlistRepository>();
        services.AddSingleton<BlocklistRepository>();
        services.AddSingleton<Dependably.Protocol.ReservedNamespaceService>();
        services.AddSingleton<Dependably.Protocol.InstallScriptAllowlistService>();
        services.AddSingleton<QuarantineRepository>();
        services.AddSingleton<Alerts.AlertRepository>();
        services.AddSingleton<Alerts.AlertService>();
        services.AddSingleton<UpstreamRegistryRepository>();
        services.AddSingleton<TrustAnchorRepository>();
        services.AddSingleton<IPerOrgTrustAnchorStore, PerOrgTrustAnchorStore>();
        services.AddSingleton<LicenseRepository>();
        services.AddSingleton<SpdxLicenseSeeder>();
        services.AddSingleton<ProxyVersionRecorder>();
        services.AddSingleton<SourcePinRepository>();
        // Operator opt-ins for weak-digest acceptance (npm SHA-1 shasum, apk SHA-1 index
        // signatures). Singleton so the once-per-process acceptance/refusal warnings latch once.
        services.AddSingleton<Dependably.Security.WeakAlgorithmAcceptance>();
        services.AddSingleton<Dependably.Storage.ProxyFetchService>();

        // Two-tier storage formalisation
        services.AddSingleton<CacheArtifactRepository>();
        services.AddSingleton<TenantArtifactAccessRepository>();
        services.AddSingleton<CacheAccessRecorder>();
        // Serialises the shared-key refcount check + physical delete of a content-addressed
        // proxy-cache blob key; shared by the LRU eviction pass and the local_only claim purge so
        // both agree on one physical blob before either deletes it.
        services.AddSingleton<CacheBlobKeyLock>();
        // The only physical proxy-cache blob delete — both cache-tier eviction paths route
        // through it for the locked refcount guard.
        services.AddSingleton<CacheOrphanBlobDeleter>();

        // Name-claim mechanism
        services.AddSingleton<ClaimRepository>();
        // Name-ownership binding store. Registered here (alongside ClaimRepository) rather than in
        // the publish pipeline because ClaimResolver depends on it for the resurrection tombstone,
        // and ClaimResolver is composed in every deployment mode.
        services.AddSingleton<NameBindingRepository>();
        // Version-granular delete tombstones, read by the publish dedup/overwrite gate.
        services.AddSingleton<VersionTombstoneRepository>();
        services.AddSingleton<ClaimResolver>();
        services.AddSingleton<NpmDistTagRepository>();
        services.AddSingleton<CargoMetadataRepository>();
        services.AddSingleton<Hex.HexSigningKeyRepository>();
        services.AddSingleton<Protocol.Hex.HexMasterKeyResolver>();
        services.AddSingleton<Hex.HexReleaseRepository>();
        services.AddSingleton<Hex.HexAdvisoryRepository>();
        services.AddSingleton<Hex.HexIdentityLookup>();

        // Projects plane — the application/collection tree the SBOM/VEX/SARIF documents hang off,
        // and the policy evaluation that stamps their component findings.
        services.AddSingleton<ProjectRepository>();
        services.AddSingleton<SbomPolicyRepository>();
        services.AddSingleton<Dependably.Protocol.SbomPolicyEvaluationService>();

        return services;
    }
}
