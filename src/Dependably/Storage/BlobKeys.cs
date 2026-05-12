namespace Dependably.Storage;

/// <summary>
/// Single source of truth for blob key construction.
/// Blob storage never makes keying decisions — keys are always built here.
/// </summary>
public static class BlobKeys
{
    /// <summary>Content-addressed key for proxy (upstream-cached) blobs.</summary>
    public static string Proxy(string sha256) => $"proxy/{sha256}";

    /// <summary>Org-scoped key for hosted (privately published) blobs.</summary>
    public static string Hosted(string orgId, string ecosystem, string purlName, string version, string filename)
        => $"hosted/{orgId}/{ecosystem}/{purlName}/{version}/{filename}";

    /// <summary>
    /// Converts a DB blob key to the actual blob store key.
    /// Proxy DB keys include a filename suffix (proxy/{sha256}/{file}) but blobs are stored at proxy/{sha256}.
    /// Hosted keys are returned unchanged.
    /// </summary>
    public static string StoreKey(string dbKey)
    {
        var parts = dbKey.Split('/');
        return parts.Length == 3 && parts[0] == "proxy" ? $"{parts[0]}/{parts[1]}" : dbKey;
    }
}
