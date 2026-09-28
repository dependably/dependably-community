using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;

namespace Dependably.Storage;

/// <summary>
/// The single place a serve path asks "may I answer this read with a redirect, and if so what
/// URL?". It owns every condition that must hold — the feature is enabled for this ecosystem, the
/// request is a full artefact GET, the tier backing this blob advertises
/// <see cref="IPresignedReadBlobStore"/> and can sign right now, and the blob is actually there —
/// and the one clock read that fixes the expiry. The existence check is made here, once per
/// redirect, and never again by the signers, which only mint.
///
/// <para>
/// Every failure mode falls back to streaming rather than failing the request. A presigned
/// redirect is a throughput optimisation layered on top of a read the caller has already
/// authorized; a store that cannot sign, or throws while signing, must not turn an authorized
/// pull into an error. The inverse — falling back to a redirect when something is wrong — is
/// what this type never does.
/// </para>
///
/// <para>
/// This service makes no authorization, tenancy, or policy decision of its own and deliberately
/// cannot: it is handed a blob key that a caller has already resolved and gated. Callers invoke
/// a <c>TryRedirectAsync</c> overload at the point they would otherwise open the blob stream,
/// after every capability, tenancy, block-gate, and claim check, so the redirect is the same
/// authorization decision delivered as a URL. <c>ProbeAsync</c> may run earlier, since it
/// only asks what opening the stream would have asked — whether the blob is there — and signs
/// nothing.
/// </para>
/// </summary>
public sealed class BlobPresignService
{
    private readonly PresignedReadOptions _options;
    private readonly CloudFrontUrlSigner? _cloudFront;
    private readonly IProxiedContentVisibility? _visibility;
    private readonly TimeProvider _time;
    private readonly ILogger<BlobPresignService> _logger;

    /// <param name="visibility">
    /// Decides whether a proxied blob is public. Without one, no proxied blob is: every object is
    /// <see cref="BlobVisibility.Private"/> and nothing is signed under an edge-cacheable prefix.
    /// </param>
    public BlobPresignService(
        PresignedReadOptions options, TimeProvider time, ILogger<BlobPresignService> logger,
        IProxiedContentVisibility? visibility = null)
    {
        _options = options;
        _cloudFront = options.Signer switch
        {
            PresignedReadSigner.CloudFront => new CloudFrontUrlSigner(
                options.CloudFront ?? throw new InvalidOperationException("The CloudFront signer is selected but not configured.")),
            _ => null,
        };
        _visibility = visibility;
        _time = time;
        _logger = logger;
    }

    /// <summary>True when the operator has opted this instance into presigned reads.</summary>
    public bool Enabled => _options.Enabled;

    /// <summary>The lifetime minted URLs carry.</summary>
    public TimeSpan Ttl => _options.Ttl;

    /// <summary>
    /// The request-shape half of the redirect decision, with no I/O: presigned reads are on for
    /// <paramref name="ecosystem"/>, the request is not a HEAD and carries no <c>Range</c>, and
    /// the response is metered as an artefact. Both <c>ProbeAsync</c> and
    /// <see cref="TryRedirectAsync(HttpContext, IBlobStore, string, long, BlobOrigin, string, CancellationToken)"/>
    /// run it themselves, so a caller never needs to.
    ///
    /// <para>
    /// The metering check is what keeps metadata off the redirect path at runtime. A response
    /// classified <see cref="EgressKind.Metadata"/> is mutable or rendered, and one still
    /// <see cref="EgressKind.PerResponse"/> is one whose handler never said what it serves — both
    /// refuse. A request with no metering feature at all (an edge build, or an unmetered route)
    /// passes this check; the artefact actions are all metered, so on the main image that case
    /// only arises for the unmetered HEAD twins, which the method check already refuses.
    /// </para>
    /// </summary>
    public bool IsRedirectCandidate(HttpContext http, string ecosystem)
    {
        var request = http.Request;
        return _options.Enabled
            && _options.RedirectsEcosystem(ecosystem)
            && !HttpMethods.IsHead(request.Method)
            && !request.Headers.ContainsKey(HeaderNames.Range)
            && (http.Features.Get<EgressMeteringFeature>() is not { } metering || metering.Kind == EgressKind.Artifact);
    }

    /// <summary>
    /// The existence half of the redirect decision, for a serve path whose cache hit is decided
    /// by whether the blob is there and whose redirect must wait for a gate in between. Returns
    /// <c>null</c> when this read can never be redirected — the request is not a redirect
    /// candidate, or nothing can sign an object of <paramref name="origin"/> in
    /// <paramref name="store"/> — and the caller opens the stream as it would without presigning.
    /// Otherwise it asks the store once whether the blob exists and returns that answer as a
    /// <see cref="RedirectProbe"/>: absent is a cache miss; present is a hit the caller gates and
    /// then hands to <see cref="TryRedirectAsync(HttpContext, RedirectProbe, long, CancellationToken)"/>,
    /// which signs without asking the store again.
    ///
    /// <para>
    /// This is what makes a redirected hit cost one existence round-trip rather than two: the
    /// probe is the check the signer would otherwise repeat. Nothing is signed here, so a hit the
    /// gate then refuses never has a URL minted for it.
    /// </para>
    /// </summary>
    public async Task<RedirectProbe?> ProbeAsync(
        HttpContext http, IBlobStore store, string storeKey, BlobOrigin origin, string ecosystem,
        CancellationToken ct = default)
    {
        if (!IsRedirectCandidate(http, ecosystem) || !CanSign(store, origin))
        {
            return null;
        }

        bool exists = await store.ExistsAsync(storeKey, ct);
        return new RedirectProbe(store, storeKey, origin, ecosystem, exists);
    }

    /// <summary>
    /// <see cref="ProbeAsync(HttpContext, IBlobStore, string, BlobOrigin, string, CancellationToken)"/>
    /// for a serve path that only learns the blob's origin after the gate — a store key shared
    /// by hosted and proxied rows. It returns a probe whenever some signer could handle the blob,
    /// and the origin is supplied to
    /// <see cref="TryRedirectAsync(HttpContext, RedirectProbe, long, BlobOrigin, CancellationToken)"/>;
    /// if that origin then turns out to be unsignable, the redirect returns <c>null</c> and the
    /// caller streams.
    /// </summary>
    public async Task<RedirectProbe?> ProbeAsync(
        HttpContext http, IBlobStore store, string storeKey, string ecosystem, CancellationToken ct = default)
    {
        bool anySigner = _cloudFront is not null || store is IPresignedReadBlobStore { SupportsPresignedReads: true };
        if (!_options.Enabled || !anySigner || !IsRedirectCandidate(http, ecosystem))
        {
            return null;
        }

        bool exists = await store.ExistsAsync(storeKey, ct);
        return new RedirectProbe(store, storeKey, origin: null, ecosystem, exists);
    }

    /// <summary>
    /// Answers the current request with a <c>307</c> (a <c>302</c> for the ecosystems in
    /// <see cref="FoundRedirectEcosystems"/>) to a short-lived presigned URL for
    /// <paramref name="storeKey"/>, or returns <c>null</c> when the caller should stream the blob
    /// instead: the request is not a redirect candidate (see <see cref="IsRedirectCandidate"/>),
    /// the recorded size is unknown, the store cannot sign, or the blob is not in the store.
    ///
    /// <para>
    /// <c>307</c> rather than <c>302</c> keeps the method and headers intact. The redirect itself
    /// carries <c>private, no-store</c>: its body is a bearer credential with a minutes-or-less
    /// lifetime and must not be cached by a proxy or a CDN, even though the blob it points at is
    /// immutable. Any <c>Content-Length</c> a caller pre-set for the streamed answer is cleared,
    /// since a 307 carries no body.
    /// </para>
    ///
    /// <para>
    /// A blob whose size the row does not record is streamed, not redirected. The redirect is
    /// metered by the size handed in here, because the bytes never pass through this process; an
    /// unknown size would redirect the transfer and bill nothing for it.
    /// </para>
    ///
    /// <para>
    /// <paramref name="origin"/> is what the serve path's row records; the visibility the signer
    /// routes on is derived from it in the seam (<see cref="ClassifyAsync"/>), on this overload and
    /// the probed ones alike, so no serve site can hand the signer a public classification of its
    /// own.
    /// </para>
    ///
    /// <para>
    /// The egress is recorded here, once the URL is signed — the seam is the only caller of
    /// <see cref="EgressMeteringHttpContextExtensions.RecordRedirectedEgress"/>. The caller's own
    /// download tracking (activity row, download counter, cache access tick) is the caller's to
    /// run, on this branch and the streaming one alike. What a redirect cannot observe is whether
    /// the client then completed the transfer, or replayed the URL inside its TTL; the short TTL
    /// bounds that, and it is why the feature is opt-in.
    /// </para>
    /// </summary>
    public async Task<IActionResult?> TryRedirectAsync(
        HttpContext http, IBlobStore store, string storeKey, long sizeBytes, BlobOrigin origin, string ecosystem,
        CancellationToken ct = default)
    {
        if (sizeBytes <= 0 || !IsRedirectCandidate(http, ecosystem))
        {
            return null;
        }

        var visibility = await ClassifyAsync(http, origin, ecosystem, ct);
        var url = await TryCreateAsync(store, storeKey, visibility, ct);
        return url is null ? null : Redirect(http, url.Value.Url, sizeBytes, storeKey, ecosystem);
    }

    /// <summary>
    /// The redirect for a blob <c>ProbeAsync</c> has already found present: the same
    /// answer and refusals as the one-shot overload, except that the store is not asked again
    /// whether the blob exists — the probe was that question. An absent probe returns <c>null</c>.
    /// </summary>
    public Task<IActionResult?> TryRedirectAsync(
        HttpContext http, RedirectProbe probe, long sizeBytes, CancellationToken ct = default)
        => probe.Origin is { } origin
            ? TryRedirectAsync(http, probe, sizeBytes, origin, ct)
            : Task.FromResult<IActionResult?>(null);

    /// <summary>
    /// The probed redirect for a blob whose origin is known only now. A probe made for a
    /// specific origin refuses any other, so a probe cannot be re-aimed at a different signer
    /// than the one its can-sign check covered.
    /// </summary>
    public async Task<IActionResult?> TryRedirectAsync(
        HttpContext http, RedirectProbe probe, long sizeBytes, BlobOrigin origin, CancellationToken ct = default)
    {
        if (!probe.Exists || sizeBytes <= 0 || !IsRedirectCandidate(http, probe.Ecosystem)
            || (probe.Origin is { } bound && bound != origin))
        {
            return null;
        }

        var visibility = await ClassifyAsync(http, origin, probe.Ecosystem, ct);
        var url = await TrySignAsync(probe.Store, probe.StoreKey, visibility, ct);
        return url is null ? null : Redirect(http, url.Value.Url, sizeBytes, probe.StoreKey, probe.Ecosystem);
    }

    private static RedirectResult Redirect(HttpContext http, Uri url, long sizeBytes, string storeKey, string ecosystem)
    {
        var response = http.Response;
        response.Headers.Remove(HeaderNames.ContentLength);
        response.ContentLength = null;
        response.ContentType = null;
        response.Headers.CacheControl = "private, no-store";

        http.RecordRedirectedEgress(sizeBytes, storeKey);
        // AbsoluteUri, not ToString(): ToString() unescapes the path, and a signature covers the
        // escaped form, so an unescaped Location would name a different resource.
        return new RedirectResult(
            url.AbsoluteUri, permanent: false, preserveMethod: !FoundRedirectEcosystems.Contains(ecosystem));
    }

    /// <summary>
    /// Ecosystems answered with <c>302</c> instead of <c>307</c>. apk-tools (2.14 and 3.0) follows
    /// a 302 but fails on a 307, even to the same host. Only artefact GETs reach this path, and a
    /// GET stays a GET under either status, so the two redirect the same request.
    /// </summary>
    internal static readonly IReadOnlySet<string> FoundRedirectEcosystems =
        new HashSet<string>(["apk"], StringComparer.Ordinal);

    /// <summary>
    /// Mints a presigned read URL for <paramref name="key"/> in <paramref name="store"/>, or
    /// returns <c>null</c> when the caller should stream the blob instead.
    ///
    /// <para>
    /// This is the one place a sign is preceded by an existence check: the signers themselves
    /// only mint, so a missing object is refused here, before a URL that would 404 at the object
    /// store or the edge is ever produced. With the CloudFront signer selected, a
    /// <see cref="BlobVisibility.Public"/> object is signed by CloudFront under the cached prefix,
    /// and a private one is signed by CloudFront only when an uncached path prefix is configured;
    /// any object CloudFront does not handle falls to the object store's own signer, as with the
    /// default store signer.
    /// </para>
    ///
    /// <para>
    /// Internal so that a visibility reaches it only through a <c>TryRedirectAsync</c> overload,
    /// which derives it; a caller elsewhere cannot declare its own blob public.
    /// </para>
    /// </summary>
    internal async Task<PresignedReadUrl?> TryCreateAsync(
        IBlobStore store, string key, BlobVisibility visibility, CancellationToken ct = default)
    {
        if (!CanSign(store, visibility))
        {
            return null;
        }

        try
        {
            if (!await store.ExistsAsync(key, ct))
            {
                return null;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogSigningFailure(ex);
            return null;
        }

        return await TrySignAsync(store, key, visibility, ct);
    }

    /// <summary>
    /// True when some URL for an object of <paramref name="origin"/> in <paramref name="store"/>
    /// could be minted: the probe-time question, asked before the visibility is known. A proxied
    /// object is taken at its best case — public — so a probe is not refused for want of a lookup
    /// it has not made; if the redirect then finds it private and nothing signs private objects,
    /// the redirect returns <c>null</c> and the caller streams.
    /// </summary>
    private bool CanSign(IBlobStore store, BlobOrigin origin)
        => CanSign(store, origin == BlobOrigin.Proxied ? BlobVisibility.Public : BlobVisibility.Private);

    /// <summary>
    /// True when a URL for an object of <paramref name="visibility"/> in <paramref name="store"/>
    /// can be minted right now: the feature is on and either CloudFront handles the visibility or
    /// the store advertises a signing credential.
    /// </summary>
    private bool CanSign(IBlobStore store, BlobVisibility visibility)
        => _options.Enabled
            && (_cloudFront?.Handles(visibility) == true
                || store is IPresignedReadBlobStore { SupportsPresignedReads: true });

    /// <summary>
    /// Derives the <see cref="BlobVisibility"/> of a blob about to be redirected. An uploaded blob
    /// is private. A proxied blob is public only when the request carries a resolved tenant and
    /// <see cref="IProxiedContentVisibility"/> answers that the tenant's upstreams for
    /// <paramref name="ecosystem"/> are all credential-free; no tenant, no visibility service, a
    /// false answer, or a lookup that throws all leave it private.
    ///
    /// <para>
    /// The lookup runs only under the CloudFront signer. The store signer does not edge-cache, so
    /// the classification cannot change where its URL points and is not worth a read.
    /// </para>
    /// </summary>
    internal async Task<BlobVisibility> ClassifyAsync(
        HttpContext http, BlobOrigin origin, string ecosystem, CancellationToken ct)
    {
        if (origin != BlobOrigin.Proxied
            || _cloudFront is null
            || _visibility is null
            || http.Items[TenantContext.HttpItemsKey] is not TenantContext { IsTenant: true, TenantId: { Length: > 0 } orgId })
        {
            return BlobVisibility.Private;
        }

        try
        {
            return await _visibility.IsPublicAsync(orgId, ecosystem, ct) ? BlobVisibility.Public : BlobVisibility.Private;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(
                "{ExceptionType} deciding whether a proxied {Ecosystem} blob is public; it is signed as private. TraceId={TraceId}",
                ex.GetType().Name, ecosystem, System.Diagnostics.Activity.Current?.TraceId.ToString());
            return BlobVisibility.Private;
        }
    }

    /// <summary>
    /// Mints the URL with no existence check; every caller has just established that the object
    /// is present. A signer that throws falls back to streaming.
    /// </summary>
    private async Task<PresignedReadUrl?> TrySignAsync(
        IBlobStore store, string key, BlobVisibility visibility, CancellationToken ct)
    {
        bool viaCloudFront = _cloudFront?.Handles(visibility) == true;
        if (!viaCloudFront && store is not IPresignedReadBlobStore { SupportsPresignedReads: true })
        {
            return null;
        }

        var expiresAt = _time.GetUtcNow().Add(_options.Ttl);
        try
        {
            var url = viaCloudFront
                ? _cloudFront!.Sign(key, visibility, expiresAt)
                : await ((IPresignedReadBlobStore)store).TryCreatePresignedReadUrlAsync(key, expiresAt, ct);
            return url is null ? null : new PresignedReadUrl(url, expiresAt);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogSigningFailure(ex);
            return null;
        }
    }

    private void LogSigningFailure(Exception ex)
        => _logger.LogWarning(
            "{ExceptionType} minting a presigned read URL for a blob; the read falls back to streaming through this instance. TraceId={TraceId}",
            ex.GetType().Name, System.Diagnostics.Activity.Current?.TraceId.ToString());
}

/// <summary>
/// The answer <c>BlobPresignService.ProbeAsync</c> got from the store about one blob,
/// carried to the redirect so the store is asked once. It binds the key, origin, and ecosystem
/// the probe was made for, so the redirect cannot be pointed at a different object than the one
/// found present (an origin-less probe takes its origin at redirect time). Only the seam
/// constructs one.
/// </summary>
public sealed class RedirectProbe
{
    // blobtier-ok: a value carrying the tier its caller probed, not a service choosing one.
    internal RedirectProbe(IBlobStore store, string storeKey, BlobOrigin? origin, string ecosystem, bool exists)
    {
        Store = store;
        StoreKey = storeKey;
        Origin = origin;
        Ecosystem = ecosystem;
        Exists = exists;
    }

    /// <summary>True when the blob was in the store at probe time; false is a cache miss.</summary>
    public bool Exists { get; }

    internal IBlobStore Store { get; }
    internal string StoreKey { get; }
    /// <summary>The origin the probe was made for, or null when the caller supplies it at redirect time.</summary>
    internal BlobOrigin? Origin { get; }
    internal string Ecosystem { get; }
}
