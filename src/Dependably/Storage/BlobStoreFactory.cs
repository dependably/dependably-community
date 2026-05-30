namespace Dependably.Storage;

public static class BlobStoreFactory
{
    /// <summary>
    /// Single-tier shape for callers that don't care about the cache/registry split.
    /// Reads the unsuffixed env vars (<c>STORAGE_BACKEND</c>, <c>LOCAL_STORAGE_PATH</c>,
    /// <c>S3_BUCKET</c>, etc.) and returns one store. Equivalent to <c>CreateForTier(...)</c>
    /// with no tier override.
    /// </summary>
    public static IBlobStore Create(IConfiguration config) => CreateForTier(config, tier: null);

    /// <summary>
    /// Two-tier factory (#48 follow-up). When <paramref name="tier"/> is non-null, every
    /// env-var lookup falls back to a tier-specific override first
    /// (<c>STORAGE_BACKEND_CACHE</c>, <c>LOCAL_STORAGE_PATH_REGISTRY</c>, etc.) and only
    /// uses the unsuffixed value when no override is set. This is what makes
    /// <c>STORAGE_BACKEND=local STORAGE_BACKEND_REGISTRY=s3</c> route the cache to disk
    /// and the registry to S3 without operators having to learn a brand-new env-var schema.
    /// </summary>
    public static IBlobStore CreateForTier(IConfiguration config, string? tier)
    {
        var backend = TieredValue(config, "STORAGE_BACKEND", tier)?.ToLowerInvariant() ?? "local";

        return backend switch
        {
            "local" => new LocalBlobStore(
                TieredValue(config, "LOCAL_STORAGE_PATH", tier) ?? "/data/blobs"),

            "s3" => new S3BlobStore(
                TieredValue(config, "S3_BUCKET", tier)
                    ?? throw new InvalidOperationException("S3_BUCKET is required"),
                TieredValue(config, "S3_REGION", tier)
                    ?? throw new InvalidOperationException("S3_REGION is required"),
                // Optional: when S3_ENDPOINT is set, S3BlobStore points at an S3-compatible
                // service (R2, MinIO, B2, Wasabi). S3_FORCE_PATH_STYLE=true is required by
                // R2 and MinIO. Both honour the same tiered fallback as the other S3_* vars.
                TieredValue(config, "S3_ENDPOINT", tier),
                bool.TryParse(TieredValue(config, "S3_FORCE_PATH_STYLE", tier), out var fps) && fps),

            "azure" => new AzureBlobStore(
                TieredValue(config, "AZURE_CONNECTION_STRING", tier)
                    ?? throw new InvalidOperationException("AZURE_CONNECTION_STRING is required"),
                TieredValue(config, "AZURE_CONTAINER", tier)
                    ?? throw new InvalidOperationException("AZURE_CONTAINER is required")),

            _ => throw new InvalidOperationException(
                $"Unknown storage backend '{backend}' (tier: {tier ?? "default"}). Valid values: local, s3, azure")
        };
    }

    /// <summary>
    /// Reads <paramref name="key"/>_<paramref name="tier"/> first (uppercased), falling
    /// back to <paramref name="key"/>. Returns null if neither is set.
    /// </summary>
    // deepcode ignore NoHardcodedCredentials: IConfiguration accessor returning a string config
    // value (bucket name, region, path). Callers may pass storage credentials through this
    // helper, but the helper itself contains no hardcoded secret.
    private static string? TieredValue(IConfiguration config, string key, string? tier)
    {
        if (tier is not null)
        {
            var tieredKey = $"{key}_{tier.ToUpperInvariant()}";
            var tieredValue = config[tieredKey];
            if (!string.IsNullOrWhiteSpace(tieredValue)) return tieredValue;
        }
        return config[key];
    }
}
