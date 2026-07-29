namespace Dependably.Storage;

/// <summary>
/// Optional <see cref="IBlobStore"/> capability: minting a short-lived, signed URL that lets a
/// client read one blob directly from the backing object store, so the artefact bytes never
/// transit the application tier.
///
/// <para>
/// It is deliberately a separate interface rather than a member on <see cref="IBlobStore"/>.
/// A filesystem-backed store has no URL to sign, and an object store configured without a
/// signing credential cannot sign either — forcing every implementation to grow the member
/// would mean the serve path could only discover "unsupported" by catching an exception.
/// Instead, a store advertises the capability by implementing this interface, and a store that
/// implements it but is not currently able to sign reports that through
/// <see cref="SupportsPresignedReads"/>. A serve path that finds neither streams the bytes as
/// it always has.
/// </para>
///
/// <para>
/// The expiry is passed in as an absolute instant rather than a duration so implementations
/// hold no clock of their own: the caller reads the injected <see cref="TimeProvider"/> once and
/// every backend signs against the same instant.
/// </para>
/// </summary>
public interface IPresignedReadBlobStore
{
    /// <summary>
    /// True when this store can mint a presigned read URL right now. An object-store
    /// implementation returns false when it holds no credential capable of signing (for example
    /// an Azure container client built from a SAS URL or a token credential rather than a shared
    /// key), so the caller falls back to streaming instead of failing the read.
    /// </summary>
    bool SupportsPresignedReads { get; }

    /// <summary>
    /// Mints a GET-only URL for <paramref name="key"/> valid until <paramref name="expiresAt"/>.
    /// Returns <c>null</c> when the blob does not exist or when this store cannot sign — both
    /// mean "fall back to streaming", never "fail the request". Implementations verify existence
    /// before signing so an evicted blob keeps the streaming path's fall-through behaviour
    /// instead of handing the client a URL that 404s at the object store.
    /// </summary>
    Task<Uri?> TryCreatePresignedReadUrlAsync(string key, DateTimeOffset expiresAt, CancellationToken ct = default);
}

/// <summary>
/// A minted presigned read URL and the instant it stops being valid. The expiry travels with the
/// URL so a caller can log or assert on the grant window without re-deriving it from the clock.
/// </summary>
public readonly record struct PresignedReadUrl(Uri Url, DateTimeOffset ExpiresAt);
