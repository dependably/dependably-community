using Dependably.Storage;

namespace Dependably.Infrastructure.Startup;

/// <summary>
/// Registers the metadata store (<see cref="IMetadataStore"/>) and the two-tier blob
/// store (<see cref="TieredBlobStorage"/> / <see cref="IBlobStore"/>).
/// </summary>
internal static class StorageStartupExtensions
{
    internal static void AddDependablyMetadataStore(this WebApplicationBuilder builder)
    {
        string dbProvider = (builder.Configuration["DB_PROVIDER"] ?? "sqlite").ToLowerInvariant();
        string? dbConnStr = builder.Configuration["DB_CONNECTION_STRING"];
        string dbPath = builder.Configuration["DB_PATH"] ?? "/data/dependably.db";

        IMetadataStore metadataStore = dbProvider switch
        {
            "postgres" => new NpgsqlMetadataStore(
                dbConnStr ?? throw new InvalidOperationException("DB_CONNECTION_STRING required for DB_PROVIDER=postgres")),
            // Cache=Shared is the legacy SQLite shared-cache mode that introduces
            // table-level locking and reduces WAL read concurrency. WAL with private
            // per-connection caches is the recommended configuration.
            _ => new SqliteMetadataStore($"Data Source={dbPath};Mode=ReadWriteCreate")
        };
        builder.Services.AddSingleton<IMetadataStore>(metadataStore);
        builder.Services.AddSingleton<SchemaInitializer>();
        builder.Services.AddSingleton<FirstBootService>();
    }

    /// <summary>
    /// Registers <see cref="TieredBlobStorage"/> and the default <see cref="IBlobStore"/>
    /// (Registry tier). Per-tier overrides use the <c>_CACHE</c> / <c>_REGISTRY</c> env-var
    /// suffix convention; unsuffixed values apply to both tiers.
    /// </summary>
    // Blob storage. STORAGE_BACKEND selects the default backend for both tiers; per-tier
    // overrides (STORAGE_BACKEND_CACHE / STORAGE_BACKEND_REGISTRY plus the corresponding
    // backend-specific vars suffixed _CACHE / _REGISTRY) opt one or both tiers into a
    // different backing store for split-tier deployments.
    //
    // The default IBlobStore registration resolves to the REGISTRY tier so legacy callers
    // that don't know about the split land on durable storage (the safer default — losing
    // a registry write loses a published artefact, while losing a cache write just causes
    // a re-fetch from upstream).
    internal static void AddDependablyBlobStore(this WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<TieredBlobStorage>(_ =>
        {
            var cfg = builder.Configuration;
            var defaultStore = BlobStoreFactory.Create(cfg);
            // A per-tier override (any *_CACHE / *_REGISTRY env var) tells the factory
            // to build that tier its own store. Without an override the tier shares the
            // default instance, preserving the current single-IBlobStore behaviour for
            // legacy deployments.
            var cache = HasTierOverride(cfg, "CACHE")
                ? BlobStoreFactory.CreateForTier(cfg, "CACHE")
                : defaultStore;
            var registry = HasTierOverride(cfg, "REGISTRY")
                ? BlobStoreFactory.CreateForTier(cfg, "REGISTRY")
                : defaultStore;
            return new TieredBlobStorage(cache, registry);
        });
        builder.Services.AddSingleton<IBlobStore>(sp =>
            sp.GetRequiredService<TieredBlobStorage>().Registry);
        // Tenant-aware registry resolver. Singleton lifetime is non-negotiable: the
        // enterprise impl memoizes per-tenant S3BlobStore instances and per-request
        // scoping would defeat the cache and leak S3 clients. Community impl returns
        // the singleton registry regardless of tenant, but still applies status +
        // provisioning-state gates defensively.
        builder.Services.AddSingleton<ITenantStorageResolver, GlobalTenantStorageResolver>();
    }

    /// <summary>
    /// True if any tier-specific storage env var is set for the given suffix. We don't try
    /// to be clever about which combinations are valid; a single override is enough to
    /// signal "this tier wants its own backend" and the factory throws if required vars
    /// are missing.
    /// </summary>
    private static bool HasTierOverride(ConfigurationManager cfg, string tier) =>
        !string.IsNullOrWhiteSpace(cfg[$"STORAGE_BACKEND_{tier}"])
        || !string.IsNullOrWhiteSpace(cfg[$"LOCAL_STORAGE_PATH_{tier}"])
        || !string.IsNullOrWhiteSpace(cfg[$"S3_BUCKET_{tier}"])
        || !string.IsNullOrWhiteSpace(cfg[$"AZURE_CONNECTION_STRING_{tier}"]);
}
