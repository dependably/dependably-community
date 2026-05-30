using System.Text.RegularExpressions;

namespace Dependably.Storage;

/// <summary>
/// Single source of truth for blob key construction.
/// Blob storage never makes keying decisions — keys are always built here.
/// </summary>
public static partial class BlobKeys
{
    [GeneratedRegex("^[0-9a-f]{64}$")]
    private static partial Regex Sha256HexRegex();

    /// <summary>Content-addressed key for proxy (upstream-cached) blobs.</summary>
    /// <remarks>
    /// Defends against path-traversal at the BlobKeys boundary: the input must be a
    /// 64-char lowercase hex SHA-256. Callers always pass <c>ChecksumVerifier.ComputeSha256Hex</c>
    /// output, which satisfies this; the check is defence-in-depth and a sanitizer marker
    /// for SAST tools that don't model the verifier.
    /// </remarks>
    public static string Proxy(string sha256)
    {
        if (!Sha256HexRegex().IsMatch(sha256))
            throw new ArgumentException("sha256 must be 64 lowercase hex characters", nameof(sha256));
        return $"proxy/{sha256}";
    }

    /// <summary>Org-scoped key for hosted (privately published) blobs.</summary>
    public static string Hosted(string orgId, string ecosystem, string purlName, string version, string filename)
        => $"hosted/{orgId}/{ecosystem}/{purlName}/{version}/{filename}";

    /// <summary>
    /// Org-scoped key for generated RPM repodata files (#100). repomd.xml and the
    /// compressed primary/filelists/other XML documents live under a per-arch path so
    /// <c>dnf</c> clients reading <c>/o/{org}/rpm/repodata/{arch}/{file}</c> resolve
    /// directly.
    /// </summary>
    public static string Repodata(string orgId, string arch, string filename)
        => $"hosted/{orgId}/rpm/repodata/{arch}/{filename}";

    /// <summary>
    /// Content-addressed key for RPM repodata proxy files (#102). Hash-prefixed metadata
    /// files (e.g. <c>{sha256}-primary.xml.gz</c>) are cached forever keyed by their
    /// SHA-256 prefix, which is the content-address. Lives on the Cache tier.
    /// </summary>
    public static string RpmRepodataProxy(string sha256) => $"proxy/rpm-repodata/{sha256}";

    /// <summary>
    /// Content-addressed key for OCI manifests and blobs (#98). The Distribution Spec
    /// stores both manifests and layers under their digest <c>{algo}:{hex}</c>; we collapse
    /// to a single namespace because dedup-by-digest is the whole point of OCI storage.
    /// Manifests live under the same prefix as layer blobs — they're just JSON blobs with
    /// a content-type tag in the metadata DB.
    /// </summary>
    public static string OciBlob(string digestAlgorithm, string digestHex)
        => $"oci/{digestAlgorithm}/{digestHex}";

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
