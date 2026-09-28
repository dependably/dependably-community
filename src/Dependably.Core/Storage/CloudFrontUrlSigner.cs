using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Dependably.Storage;

/// <summary>
/// Mints CloudFront signed URLs with a canned policy, by hand: the policy is a fixed JSON shape,
/// the signature is RSA with SHA-1 and PKCS#1 v1.5 padding (the scheme CloudFront verifies), and
/// the encoding is CloudFront's URL-safe base64 — so no AWS SDK package is needed for it.
///
/// <para>
/// A signed URL is <c>{base}/{prefix}/{key}?Expires={epoch}&amp;Signature={sig}&amp;Key-Pair-Id={id}</c>,
/// where the signature covers
/// <c>{"Statement":[{"Resource":"{url}","Condition":{"DateLessThan":{"AWS:EpochTime":{epoch}}}}]}</c>
/// with no whitespace. The distribution maps each prefix to a behaviour whose origin serves the
/// object at <c>{key}</c>.
/// </para>
///
/// <para>
/// Which prefix is chosen by the object's <see cref="BlobVisibility"/>, which
/// <see cref="BlobPresignService"/> derives: only <see cref="BlobVisibility.Public"/> objects —
/// proxied through upstreams that are all credential-free — go under the cached prefix. Private
/// objects (uploaded, or proxied through any credentialed or unknown upstream) go under the
/// uncached prefix, and only when one is configured — otherwise this signer declines them
/// (<see cref="Handles"/>) and the object store signs instead. This signer only mints: <see cref="BlobPresignService"/> checks that the object
/// exists before asking, so an evicted object keeps the streaming path's fall-through rather than
/// yielding a URL that 404s at the edge, and the check is made once rather than again here.
/// </para>
/// </summary>
public sealed class CloudFrontUrlSigner
{
    private readonly CloudFrontSignerOptions _options;

    public CloudFrontUrlSigner(CloudFrontSignerOptions options) => _options = options;

    /// <summary>
    /// True when this signer signs objects of <paramref name="visibility"/>. Private objects are
    /// signed here only once an uncached prefix is configured; until then they are the store
    /// signer's, which keeps the customer's own bytes off the CDN by default.
    /// </summary>
    public bool Handles(BlobVisibility visibility)
        => visibility == BlobVisibility.Public || _options.UncachedPathPrefix is not null;

    /// <summary>
    /// Signs <paramref name="key"/> for a read until <paramref name="expiresAt"/>, or returns
    /// <c>null</c> when this signer does not handle <paramref name="visibility"/>. It does not
    /// check that the object exists; the caller has.
    /// </summary>
    public Uri? Sign(string key, BlobVisibility visibility, DateTimeOffset expiresAt)
    {
        if (!Handles(visibility))
        {
            return null;
        }

        string prefix = visibility == BlobVisibility.Public ? _options.CachedPathPrefix : _options.UncachedPathPrefix!;
        return SignUrl(ResourceUrl(prefix, key), expiresAt.ToUnixTimeSeconds());
    }

    /// <summary>The unsigned resource URL for <paramref name="key"/> under <paramref name="prefix"/>; each key segment is percent-encoded.</summary>
    internal string ResourceUrl(string prefix, string key)
    {
        var path = new StringBuilder(_options.UrlBase.GetLeftPart(UriPartial.Path).TrimEnd('/'));
        if (prefix.Length > 0)
        {
            path.Append('/').Append(prefix);
        }

        foreach (string segment in key.Split('/'))
        {
            path.Append('/').Append(Uri.EscapeDataString(segment));
        }

        return path.ToString();
    }

    /// <summary>Appends the canned-policy query string to <paramref name="resourceUrl"/>.</summary>
    internal Uri SignUrl(string resourceUrl, long expiresEpoch)
    {
        string policy = CannedPolicy(resourceUrl, expiresEpoch);
        string signature = UrlSafeBase64(Sign(_options.PrivateKey, Encoding.UTF8.GetBytes(policy)));
        string expires = expiresEpoch.ToString(CultureInfo.InvariantCulture);
        return new Uri($"{resourceUrl}?Expires={expires}&Signature={signature}&Key-Pair-Id={Uri.EscapeDataString(_options.KeyPairId)}");
    }

    /// <summary>The canned policy CloudFront reconstructs from the URL and verifies the signature over.</summary>
    internal static string CannedPolicy(string resourceUrl, long expiresEpoch)
        => "{\"Statement\":[{\"Resource\":\"" + resourceUrl
            + "\",\"Condition\":{\"DateLessThan\":{\"AWS:EpochTime\":"
            + expiresEpoch.ToString(CultureInfo.InvariantCulture) + "}}}]}";

    /// <summary>
    /// RSA-SHA1 with PKCS#1 v1.5 padding. SHA-1 is not a choice made here: it is the only digest
    /// CloudFront verifies signed-URL signatures with.
    /// </summary>
    internal static byte[] Sign(RSA key, byte[] data)
        => key.SignData(data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

    /// <summary>CloudFront's URL-safe base64: standard base64 with <c>+</c>→<c>-</c>, <c>=</c>→<c>_</c>, <c>/</c>→<c>~</c>.</summary>
    internal static string UrlSafeBase64(byte[] bytes)
        => Convert.ToBase64String(bytes).Replace('+', '-').Replace('=', '_').Replace('/', '~');
}
