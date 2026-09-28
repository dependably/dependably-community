using System.Security.Cryptography;

namespace Dependably.Storage;

/// <summary>Which signer mints presigned read URLs.</summary>
public enum PresignedReadSigner
{
    /// <summary>The object store's own signer (<see cref="IPresignedReadBlobStore"/> on S3 or Azure).</summary>
    Store,

    /// <summary>CloudFront signed URLs for public proxied objects, and for private ones only when an uncached prefix is set.</summary>
    CloudFront,
}

/// <summary>
/// Configuration for CloudFront signed URLs, bound only when
/// <c>STORAGE_PRESIGNED_READ_SIGNER=cloudfront</c>.
///
/// <para>
/// The two path prefixes are the residency control. Only <see cref="BlobVisibility.Public"/>
/// objects — proxied from upstreams the org has configured entirely without credentials — are
/// signed under <see cref="CachedPathPrefix"/>, which the distribution may cache at the edge.
/// Every other object is the customer's own or cannot be shown not to be: uploaded objects, and
/// proxied objects from an org with any credentialed or unknown upstream for the ecosystem. Those
/// are signed under <see cref="UncachedPathPrefix"/>, which the distribution maps to a
/// caching-disabled behaviour, and only when that prefix is set. While it is unset — the default —
/// they are signed by the object store instead and never routed through CloudFront at all, so
/// sending private bytes through the CDN is a setting someone had to choose.
/// </para>
///
/// <para>
/// The private key is a secret. It is parsed once at startup into an <see cref="RSA"/> instance
/// and the PEM text is not retained; <see cref="ToString"/> names the key pair and never the key.
/// </para>
/// </summary>
public sealed class CloudFrontSignerOptions
{
    public const string SignerKey = "STORAGE_PRESIGNED_READ_SIGNER";
    public const string UrlBaseKey = "CLOUDFRONT_URL_BASE";
    public const string KeyPairIdKey = "CLOUDFRONT_KEY_PAIR_ID";
    public const string PrivateKeyKey = "CLOUDFRONT_PRIVATE_KEY";
    public const string CachedPathPrefixKey = "CLOUDFRONT_CACHED_PATH_PREFIX";
    public const string UncachedPathPrefixKey = "CLOUDFRONT_UNCACHED_PATH_PREFIX";

    /// <summary>The distribution's base URL, with no trailing slash (for example <c>https://d111111abcdef8.cloudfront.net</c>).</summary>
    public required Uri UrlBase { get; init; }

    /// <summary>The CloudFront public key ID the signature is verified against.</summary>
    public required string KeyPairId { get; init; }

    /// <summary>The signing key. Owned by this instance for the life of the process.</summary>
    public required RSA PrivateKey { get; init; }

    /// <summary>Path prefix, without surrounding slashes, for public proxied objects. Empty means the distribution root.</summary>
    public string CachedPathPrefix { get; init; } = "";

    /// <summary>
    /// Path prefix, without surrounding slashes, for private objects; null when unset, in which
    /// case private objects use the store signer.
    /// </summary>
    public string? UncachedPathPrefix { get; init; }

    public override string ToString()
        => $"CloudFront signer (key pair {KeyPairId}, base {UrlBase}, private key [redacted])";

    /// <summary>
    /// Reads the signer choice. An unset or empty value is the store signer; anything other than
    /// <c>store</c> or <c>cloudfront</c> fails startup.
    /// </summary>
    public static PresignedReadSigner ParseSigner(string? raw) =>
        string.IsNullOrWhiteSpace(raw) || string.Equals(raw.Trim(), "store", StringComparison.OrdinalIgnoreCase)
            ? PresignedReadSigner.Store
            : string.Equals(raw.Trim(), "cloudfront", StringComparison.OrdinalIgnoreCase)
                ? PresignedReadSigner.CloudFront
                : throw new InvalidOperationException(
                    $"{SignerKey} must be 'store' or 'cloudfront'; '{raw.Trim()}' is not a signer.");

    /// <summary>
    /// Binds and validates the CloudFront settings. Every missing or malformed value fails startup
    /// with a message that names the setting and never echoes the private key.
    /// </summary>
    public static CloudFrontSignerOptions FromConfiguration(IConfiguration config)
    {
        var missing = new[] { UrlBaseKey, KeyPairIdKey, PrivateKeyKey }
            .Where(k => string.IsNullOrWhiteSpace(config[k]))
            .ToList();
        if (missing.Count > 0)
        {
            throw new InvalidOperationException(
                $"{SignerKey}=cloudfront requires {string.Join(", ", missing)}.");
        }

        string rawBase = config[UrlBaseKey]!.Trim().TrimEnd('/');
        bool validBase = Uri.TryCreate(rawBase, UriKind.Absolute, out var urlBase)
            && urlBase.Scheme == Uri.UriSchemeHttps
            && string.IsNullOrEmpty(urlBase.Query)
            && string.IsNullOrEmpty(urlBase.Fragment);

        return !validBase
            ? throw new InvalidOperationException($"{UrlBaseKey} must be an absolute https URL with no query or fragment.")
            : new CloudFrontSignerOptions
            {
                UrlBase = urlBase!,
                KeyPairId = config[KeyPairIdKey]!.Trim(),
                PrivateKey = ParsePrivateKey(config[PrivateKeyKey]!),
                CachedPathPrefix = NormalizePrefix(config[CachedPathPrefixKey]) ?? "",
                UncachedPathPrefix = NormalizePrefix(config[UncachedPathPrefixKey]),
            };
    }

    /// <summary>
    /// Refuses a storage layout the CloudFront signer cannot serve. A signed URL names one
    /// distribution, whose origin is one S3 bucket, while the existence check runs against
    /// whichever tier the serve path reads. With split tiers the two can be different buckets, and
    /// with a <c>local</c> or <c>azure</c> backend there is no S3 object behind the URL at all —
    /// either way the redirect would point at an object CloudFront cannot fetch. So the CloudFront
    /// signer requires both tiers to share one <c>s3</c> store.
    /// </summary>
    public static void EnsureStorageSupported(bool tiersSplit, string? backend)
    {
        if (tiersSplit)
        {
            throw new InvalidOperationException(
                $"{SignerKey}=cloudfront requires the cache and registry tiers to share one store; "
                + "remove the _CACHE / _REGISTRY storage overrides or use the store signer.");
        }

        if (!string.Equals(backend?.Trim(), "s3", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"{SignerKey}=cloudfront requires STORAGE_BACKEND=s3; the distribution cannot serve objects from a "
                + $"'{(string.IsNullOrWhiteSpace(backend) ? "local" : backend.Trim())}' backend.");
        }
    }

    /// <summary>
    /// Parses a PEM RSA private key (PKCS#1 or PKCS#8). A PEM carried in a single-line environment
    /// variable with literal <c>\n</c> escapes is accepted too. The failure message names the
    /// setting and says nothing about the value.
    /// </summary>
    internal static RSA ParsePrivateKey(string pem)
    {
        string text = pem.Contains('\n') ? pem : pem.Replace("\\n", "\n", StringComparison.Ordinal);
        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(text);
            // A public-key PEM imports cleanly and then cannot sign; a probe signature turns that
            // into a startup failure instead of a signer that falls back on every request.
            _ = CloudFrontUrlSigner.Sign(rsa, [0]);
            return rsa;
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            rsa.Dispose();
            throw new InvalidOperationException(
                $"{PrivateKeyKey} is not a PEM-encoded RSA private key.", ex);
        }
    }

    private static string? NormalizePrefix(string? raw)
    {
        string? trimmed = raw?.Trim().Trim('/');
        return string.IsNullOrEmpty(trimmed) ? null : trimmed;
    }
}
