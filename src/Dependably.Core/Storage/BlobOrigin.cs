namespace Dependably.Storage;

/// <summary>
/// Whether a blob's bytes were published to this registry or fetched from an upstream on a
/// client's behalf. It is the input to <see cref="BlobVisibility"/>: uploaded bytes are always the
/// customer's own and may carry a residency commitment, while proxied bytes are public only when
/// every upstream that could have supplied them serves them without credentials — a private image
/// pulled through a credentialed upstream is proxied and still the customer's own.
///
/// <para>
/// It always comes from the metadata row the serve path already holds —
/// <c>package_versions.origin</c>, <c>oci_blobs.origin</c>, <c>maven_version_files.origin</c>, or
/// the fact that the row is a <c>cache_artifact</c> — and never from the storage tier or the key
/// prefix. Content addressing puts an uploaded OCI layer under the same key as a proxied layer
/// with the same digest, and several ecosystems read proxied bytes from the registry tier, so
/// neither the key nor the tier says who the bytes belong to.
/// </para>
/// </summary>
public enum BlobOrigin
{
    /// <summary>Fetched from an upstream registry and cached.</summary>
    Proxied,

    /// <summary>Published to this registry by a tenant.</summary>
    Uploaded,
}

/// <summary>
/// Whether a blob's bytes may be cached by a CDN outside the deployment's region. This, not
/// <see cref="BlobOrigin"/>, is what a presigned-read signer routes on, and
/// <see cref="BlobPresignService"/> is the one place that derives it.
///
/// <para>
/// <see cref="Public"/> is earned, never assumed: a proxied blob is public only when the org's
/// upstreams for its ecosystem are all configured without credentials
/// (<see cref="IProxiedContentVisibility"/>). An uploaded blob, a proxied blob from an org with any
/// credentialed, unknown, or missing upstream for the ecosystem, and a blob whose classification
/// could not be read are all <see cref="Private"/>.
/// </para>
/// </summary>
public enum BlobVisibility
{
    /// <summary>
    /// The customer's own bytes, or bytes whose provenance cannot be shown to be public. Never
    /// edge-cacheable.
    /// </summary>
    Private,

    /// <summary>
    /// Proxied bytes that the org's upstreams for this ecosystem serve to anyone without
    /// credentials. The only class a signer may place on an edge-cacheable path.
    /// </summary>
    Public,
}

public static class BlobOrigins
{
    /// <summary>
    /// Maps an <c>origin</c> column value to a <see cref="BlobOrigin"/>. Only the literal
    /// <c>proxy</c> reads as proxied; every other value, including a null or an unrecognised one,
    /// reads as uploaded, because treating unknown bytes as the customer's own is the direction
    /// that can never route them somewhere a residency commitment forbids.
    /// </summary>
    public static BlobOrigin FromColumn(string? origin) =>
        string.Equals(origin, "proxy", StringComparison.Ordinal) ? BlobOrigin.Proxied : BlobOrigin.Uploaded;
}
