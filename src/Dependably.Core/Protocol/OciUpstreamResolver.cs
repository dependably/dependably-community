using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text.Json;
using Dapper;
using Dependably.Configuration;
using Dependably.Infrastructure;
using Dependably.Storage;
using Microsoft.Extensions.Options;

namespace Dependably.Protocol;

/// <summary>
/// Fetches OCI manifests, blobs, and tag lists from configured upstream registries.
///
/// Prefix routing: the first <see cref="OciUpstreamRegistryOptions"/> whose
/// <c>Prefixes</c> list contains a prefix of the repository name wins.
/// Auth is delegated to <see cref="OciUpstreamAuthService"/>; a 401 from upstream triggers
/// one token eviction + retry.
///
/// Manifest TTL: tag → digest mappings are re-validated against upstream when
/// <c>oci_tags.last_revalidated</c> is older than <c>ManifestTagTtl</c>.
/// Digest references are immutable per the Distribution Spec — served from cache without
/// an upstream round-trip.
///
/// Moving-tag policy is three orthogonal knobs: the TTL answers "when do we ask upstream
/// again"; the org's <c>min_release_age_hours</c> answers "may a newly observed digest be
/// PROMOTED onto the tag" (a too-young digest is held pending on <c>oci_tags</c> while the
/// previously accepted digest keeps serving — promotion is gated, availability never is);
/// and <c>ManifestTagStaleGrace</c> (enforced in the controller) answers "how long may the
/// last accepted digest keep serving while upstream is unavailable". The upstream
/// tag → digest observation itself is coalesced instance-wide per credential identity — see
/// <c>_tagObservations</c> — while everything a tenant accepts stays strictly per-org.
///
/// Blob fetching: the digest is known from the request, so the blob store key
/// (<see cref="BlobKeys.OciBlob"/>) is computed before downloading. The upstream response
/// is streamed through an <see cref="OciDigestVerifyStream"/> for live SHA-256 verification;
/// the verified bytes are written to <see cref="TieredBlobStorage.Cache"/>, then read back
/// for streaming to the caller.
/// </summary>
public sealed class OciUpstreamResolver
{
    // Split limit for OCI digest strings: algorithm and hex are exactly two parts ({algo}:{hex}).
    private const int DigestSplitParts = 2;

    // Auth retry pattern: one initial attempt and one retry after token invalidation.
    private const int UpstreamMaxAttempts = 2;
    private const int UpstreamFirstAttempt = 0;

    // First HTTP status code in the server-error class (5xx) — with 429, the statuses that
    // classify an upstream answer as "unavailable" rather than "not found".
    private const int ServerErrorStatusFloor = 500;

    // All four manifest media types accepted by current Docker and OCI clients.
    private static readonly string[] ManifestAcceptTypes =
    [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ];

    // Constant filename recorded on an OCI manifest's cache_artifact row. version is the
    // content-addressed digest, so a fixed filename is safe and collision-free within the
    // (ecosystem, name, version, filename) UNIQUE coordinate — this row always represents the
    // pullable manifest, never a layer or config blob (those stay in oci_blobs only, with no
    // cache_artifact row). Internal so SchemaInitializer's backfill migration can reuse it.
    internal const string ManifestCacheFilename = "manifest";

    private readonly IHttpClientFactory _http;
    private readonly OciUpstreamAuthService _auth;
    private readonly IOptions<OciOptions> _options;
    private readonly TieredBlobStorage _blobs;
    private readonly IMetadataStore _db;
    private readonly PackageRepository _packages;
    private readonly UpstreamRegistryRepository _upstreamRepo;
    private readonly IAirGapMode _airGap;
    private readonly OciImageLicenseRecorder _licenseRecorder;
    private readonly OciReferenceGraph _referenceGraph;
    private readonly CacheAccessRecorder _cacheRecorder;
    private readonly CacheArtifactRepository _cacheArtifacts;
    private readonly ILogger<OciUpstreamResolver> _logger;
    private readonly TimeProvider _time;

    // Single-flight dedup for concurrent OCI blob fetches: keyed by (org id, content-addressed
    // blob key) so concurrent cache-misses for the same digest WITHIN ONE ORG collapse to one
    // upstream pull. The org is part of the key because the shared work item captures the
    // winner's org, upstream, and credentials: a key of bytes alone would hand a caller from
    // another tenant a payload pulled with credentials it never holds, from a registry it
    // cannot reach. The shared work item writes the verified blob to the cache store and
    // returns only metadata (key + media type) — NOT an open stream. Each waiter independently
    // calls _blobs.Cache.GetAsync after the Lazy resolves to open its OWN stream, avoiding
    // use-after-dispose when N callers race on the same digest. CancellationToken.None prevents
    // a single caller disconnect from faulting the shared Lazy and cancelling all other
    // waiters — the blob write is idempotent.
    private readonly ConcurrentDictionary<OciBlobInflightKey, Lazy<Task<OciBlobFetchMetadata?>>> _blobInflight = new();

    // Test-only observation seam (InternalsVisibleTo Dependably.Tests): counts callers that have
    // reached the _blobInflight registration point for a given (org, blob key), so a concurrency
    // test can deterministically wait for "all N callers have registered as winner/joiner"
    // instead of guessing at that moment with a timeout. Never read on any production path.
    private readonly ConcurrentDictionary<OciBlobInflightKey, int> _blobInflightArrivals = new();

    // Instance-wide moving-tag observation cache + single-flight. The upstream question "what
    // digest does {host}/{repository}:{tag} point at right now" has one answer per CREDENTIAL
    // IDENTITY, not per tenant — in multi-tenant mode every tenant otherwise independently polls
    // the public upstream for the same moving tag, multiplying Docker Hub requests (and 429
    // exposure) by the tenant count for one identical answer. What is shared here is ONLY that
    // observation (digest + header metadata); everything a tenant ACCEPTS stays strictly
    // per-org — the oci_tags mapping, promotion timing (pending_first_seen_at), licence gate,
    // audit rows — and manifest/blob BYTES are always fetched with the org's own credentials.
    //
    // The key includes a fingerprint of the upstream's credential material
    // (CredentialFingerprint), never just (host, repository, tag): a tenant on private
    // credentials sees a different registry view than one on anonymous, and coalescing across
    // that boundary would hand one tenant a digest resolved with credentials it does not hold —
    // the cross-org proxy class CanServeSharedBlobAsync closes for blob bytes. Two orgs with
    // byte-identical credentials (the anonymous/public case this exists for) share by
    // construction; any credential difference means no sharing at all.
    //
    // State is process-local and in-memory, deliberately not persisted — the same posture as
    // the SMTP transport breaker: a file-backed SQLite deployment runs exactly one live process
    // (InstanceLock refuses a second writer), so process-local IS instance-wide there; a
    // Postgres deployment may run several replicas, each holding its own view, bounding the
    // upstream fan-out to (replicas) rather than (tenants) — a real and self-correcting
    // reduction with no cross-replica coordination cost.
    //
    // A completed Found entry is reused until ManifestTagTtl old (any answer younger than the
    // TTL is acceptable staleness by definition); NotFound/NoDigest/faulted results are evicted
    // on completion and never reused — a failure observed by one tenant must not become another
    // tenant's cached answer. Bounded at MaxTagObservations with expiry-ordered pruning, since
    // repository/tag are client-controlled strings.
    private readonly ConcurrentDictionary<OciTagObservationKey, Lazy<Task<TagObservation>>> _tagObservations = new();
    private const int MaxTagObservations = 1024;

    /// <summary>
    /// Number of <see cref="FetchBlobAsync"/> callers from <paramref name="orgId"/> that have
    /// registered against the shared in-flight entry for <paramref name="blobKey"/> (winner +
    /// joiners), for deterministic concurrency-test synchronization only.
    /// </summary>
    internal int BlobInflightArrivalCount(string orgId, string blobKey) =>
        _blobInflightArrivals.TryGetValue(new OciBlobInflightKey(orgId, blobKey), out int count) ? count : 0;

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification =
            "Resolver aggregates 12 independent DI-resolved services (HTTP client factory, auth service, " +
            "options, tiered blob storage, metadata store, air-gap mode, license recorder, cache-plane " +
            "recorder + repository, logger, clock, secret protector). Bundling into a wrapper record " +
            "would obscure the DI graph.")]
    public OciUpstreamResolver(
        IHttpClientFactory http,
        OciUpstreamAuthService auth,
        IOptions<OciOptions> options,
        TieredBlobStorage blobs,
        IMetadataStore db,
        IAirGapMode airGap,
        OciImageLicenseRecorder licenseRecorder,
        CacheAccessRecorder cacheRecorder,
        CacheArtifactRepository cacheArtifacts,
        ILogger<OciUpstreamResolver> logger,
        TimeProvider time,
        Dependably.Infrastructure.Identity.EnvelopeProtector envelope)
    {
        _http = http;
        _auth = auth;
        _options = options;
        _blobs = blobs;
        _db = db;
        // Repository wrappers are stateless Dapper helpers over the shared IMetadataStore.
        // Built here rather than injected to avoid capturing Scoped services in this Singleton.
        _packages = new PackageRepository(db, time: time);
        _upstreamRepo = new UpstreamRegistryRepository(db, time, envelope);
        _referenceGraph = new OciReferenceGraph(db);
        _airGap = airGap;
        _licenseRecorder = licenseRecorder;
        // CacheAccessRecorder and CacheArtifactRepository are registered as singletons (stateless
        // Dapper helpers over the shared IMetadataStore), so — unlike the scoped services this
        // resolver avoids capturing — they are safe to inject directly here.
        _cacheRecorder = cacheRecorder;
        _cacheArtifacts = cacheArtifacts;
        _logger = logger;
        _time = time;
    }

    /// <summary>
    /// Finds the first upstream registry for <paramref name="orgId"/> whose prefix list matches
    /// <paramref name="repository"/>. An empty string prefix is the catch-all fallback. Returns
    /// null when no upstreams are configured for the org or none matches.
    /// </summary>
    public async Task<OciUpstreamRegistryOptions?> MatchUpstreamAsync(
        string orgId, string repository, CancellationToken ct)
    {
        var upstreams = await _upstreamRepo.BuildOciUpstreamsForOrgAsync(orgId, ct);
        foreach (var u in upstreams)
        {
            foreach (string prefix in u.Prefixes)
            {
                if (string.IsNullOrEmpty(prefix) ||
                    repository.StartsWith(prefix, StringComparison.Ordinal))
                {
                    return u;
                }
            }
        }
        return null;
    }

    /// <summary>
    /// Fetches only the header metadata (digest, size, media type) for a manifest from the
    /// upstream registry using a HEAD request — no body is downloaded. Used by the manifest
    /// HEAD handler on a cache-miss to avoid downloading the full manifest body only to
    /// discard it.
    ///
    /// Checks the local cache first (same TTL logic as <see cref="FetchManifestAsync"/>).
    /// Falls back to an upstream HEAD on a cache-miss. Returns <c>null</c> when no upstream
    /// matches, the upstream returns 404, or the upstream does not supply the required headers.
    /// Throws <see cref="AirGappedException"/> in air-gap mode.
    /// </summary>
    public async Task<OciManifestMetadata?> FetchManifestMetadataAsync(
        string orgId,
        string repository,
        string reference,
        bool isDigest,
        CancellationToken ct)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException($"oci-manifest::{repository}/{reference}");
        }

        // Check the local cache before hitting upstream — a cached manifest already has
        // all the metadata we need without any network round-trip.
        var fromCache = isDigest
            ? await TryGetCachedManifestMetadataByDigestAsync(orgId, reference, ct)
            : await TryGetCachedTagManifestMetadataAsync(orgId, repository, reference, ct);

        if (fromCache is not null)
        {
            return fromCache;
        }

        var upstream = await MatchUpstreamAsync(orgId, repository, ct);
        return upstream is null
            ? null
            : await RouteMetadataUpstreamAsync(upstream, orgId, repository, reference, isDigest, ct);
    }

    // A digest reference is content-addressed (plain upstream HEAD); a tag is a mutable
    // mapping and goes through the persisting revalidation path.
    private async Task<OciManifestMetadata?> RouteMetadataUpstreamAsync(
        OciUpstreamRegistryOptions upstream, string orgId, string repository, string reference,
        bool isDigest, CancellationToken ct)
        => isDigest
            ? await FetchManifestMetadataFromUpstreamAsync(orgId, upstream, repository, reference, ct)
            : await RevalidateTagMetadataAsync(upstream, orgId, repository, reference, ct);

    /// <summary>
    /// HEAD-side revalidation of a tag. A HEAD must persist its outcome durably — an accepted
    /// tag mapping cannot depend on whether the client happens to pull with HEAD-then-GET-by-
    /// digest (containerd-snapshotter docker, BuildKit) or GET-by-tag — but a HEAD carries no
    /// manifest body, so what it may write differs by case:
    /// <list type="bullet">
    ///   <item>Digest UNCHANGED — a pure freshness confirmation with no dangling risk: refresh
    ///   <c>last_revalidated</c> (restoring the fresh window, the main harm of a non-persisting
    ///   HEAD) and clear any pending observation.</item>
    ///   <item>Digest CHANGED — never repoint from a HEAD (the tag would dangle at a digest
    ///   whose body is absent). Record the observation as pending for the promotion gate and
    ///   let the next GET-by-tag fetch the body and repoint.</item>
    /// </list>
    /// </summary>
    private async Task<OciManifestMetadata?> RevalidateTagMetadataAsync(
        OciUpstreamRegistryOptions upstream, string orgId, string repository, string tag, CancellationToken ct)
    {
        var row = await ReadTagRowAsync(orgId, repository, tag, ct);
        var obs = await ObserveUpstreamTagAsync(orgId, upstream, repository, tag, ct);
        if (obs.Kind is TagObservationKind.NotFound or TagObservationKind.NoDigest)
        {
            // NotFound: genuine upstream miss → MANIFEST_UNKNOWN. NoDigest: nothing durable can
            // be recorded from a digest-less HEAD; the warning was already logged.
            return null;
        }

        string observedDigest = obs.Digest!;
        if (row.Digest is null)
        {
            // First sighting via HEAD: answer from the observation, but mint no tag row — a
            // row written here would dangle at a digest whose body has never been fetched.
            return new OciManifestMetadata(observedDigest, obs.MediaType, obs.SizeBytes);
        }

        if (string.Equals(observedDigest, row.Digest, StringComparison.OrdinalIgnoreCase))
        {
            await ConfirmTagUnchangedAsync(orgId, repository, tag, ct);
            return await TryGetCachedManifestMetadataByDigestAsync(orgId, row.Digest, ct)
                ?? new OciManifestMetadata(observedDigest, obs.MediaType, obs.SizeBytes);
        }

        int? minAgeHours = await GetMinReleaseAgeHoursAsync(orgId, ct);
        if (IsPromotionAllowed(row, observedDigest, minAgeHours))
        {
            // Promotable, but a HEAD cannot repoint. Record the pending observation WITHOUT
            // refreshing the stamp, so the next GET-by-tag revalidates, fetches the body, and
            // repoints promptly; meanwhile answer with the upstream's new digest — the client's
            // follow-up GET-by-digest is content-addressed and serves correctly either way.
            await HoldPendingDigestAsync(orgId, repository, tag, observedDigest, refreshStamp: false, ct);
            return new OciManifestMetadata(observedDigest, obs.MediaType, obs.SizeBytes);
        }

        // Held by the promotion gate: the tag still resolves to the accepted digest, on HEAD
        // exactly as it would on GET — a probing client must not be told the tag moved.
        await HoldPendingDigestAsync(orgId, repository, tag, observedDigest, refreshStamp: true, ct);
        return await TryGetCachedManifestMetadataByDigestAsync(orgId, row.Digest, ct)
            ?? await FetchManifestMetadataFromUpstreamAsync(orgId, upstream, repository, row.Digest, ct);
    }

    private async Task<OciManifestMetadata?> TryGetCachedManifestMetadataByDigestAsync(
        string orgId, string digest, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (digest, org_id) PK is tenant-scoped.
        var (MediaType, SizeBytes, BlobKey) = await conn.QuerySingleOrDefaultAsync<(string? MediaType, long SizeBytes, string? BlobKey)>(
            "SELECT media_type AS MediaType, size_bytes AS SizeBytes, blob_key AS BlobKey " +
            "FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });

        if (BlobKey is null)
        {
            return null;
        }

        // Confirm the blob is still present in the store without opening a stream.
        bool exists = await _blobs.Cache.ExistsAsync(BlobKey, ct)
            || await _blobs.Registry.ExistsAsync(BlobKey, ct);
        return exists ? new OciManifestMetadata(digest, MediaType ?? "application/octet-stream", SizeBytes) : null;
    }

    private async Task<OciManifestMetadata?> TryGetCachedTagManifestMetadataAsync(
        string orgId, string repository, string tag, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (org_id, repository, tag) PK.
        var (Digest, LastRevalidated) = await conn.QuerySingleOrDefaultAsync<(string? Digest, string? LastRevalidated)>(
            "SELECT digest AS Digest, last_revalidated AS LastRevalidated " +
            "FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND tag = @tag",
            new { orgId, repo = repository, tag });

        return Digest is not null && IsTagEntryFresh(LastRevalidated)
            ? await TryGetCachedManifestMetadataByDigestAsync(orgId, Digest, ct)
            : null;
    }

    private async Task<OciManifestMetadata?> FetchManifestMetadataFromUpstreamAsync(
        string orgId, OciUpstreamRegistryOptions upstream, string repository, string reference, CancellationToken ct)
    {
        string url = $"https://{upstream.Host}/v2/{repository}/manifests/{reference}";
        var client = _http.CreateClient("OciUpstream");
        string logContext = $"OCI manifest HEAD {repository}:{reference} upstream {upstream.Host}";

        using var resp = await SendUpstreamWithAuthRetryAsync(
            orgId, client, HttpMethod.Head, url, ManifestAcceptTypes, upstream, repository, "pull", logContext, ct);
        return resp is null ? null : ExtractManifestMetadataFromHeadResponse(resp, repository, reference, upstream.Host);
    }

    // Extracts OciManifestMetadata from a successful HEAD response.
    // Returns null when no usable digest can be determined from the response headers.
    private OciManifestMetadata? ExtractManifestMetadataFromHeadResponse(
        HttpResponseMessage resp, string repository, string reference, string upstreamHost)
    {
        // Prefer the upstream's Docker-Content-Digest header as the digest; fall back
        // to the reference itself when the reference is already a digest.
        string? upstreamDigest = resp.Headers.TryGetValues("Docker-Content-Digest", out var dcdVals)
            ? dcdVals.FirstOrDefault()
            : null;

        string digest = !string.IsNullOrEmpty(upstreamDigest)
            ? upstreamDigest
            : OciCoordinatesParser.IsValidDigest(reference) ? reference : string.Empty;

        if (string.IsNullOrEmpty(digest))
        {
            _logger.LogWarning(
                "OCI manifest HEAD {Repository}:{Reference} from {Host}: no Docker-Content-Digest header and reference is not a digest; cannot satisfy HEAD without body download.",
                repository, reference, upstreamHost);
            return null;
        }

        string mediaType = resp.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";
        long sizeBytes = resp.Content.Headers.ContentLength ?? 0;
        return new OciManifestMetadata(digest, mediaType, sizeBytes);
    }

    /// <summary>
    /// Returns the OCI manifest for <paramref name="repository"/>/<paramref name="reference"/>
    /// from cache (if fresh) or from the upstream registry.
    ///
    /// For digest references the cache is checked first (content-addressed → immutable).
    /// For tag references the cache is used only when <c>last_revalidated</c> is within
    /// <c>ManifestTagTtl</c>; otherwise the upstream is consulted and the local tag entry
    /// is refreshed.
    ///
    /// Returns null when no upstream matches or the upstream returns 404.
    /// Throws <see cref="AirGappedException"/> in air-gap mode.
    /// </summary>
    public async Task<OciManifestResult?> FetchManifestAsync(
        string orgId,
        string repository,
        string reference,
        bool isDigest,
        CancellationToken ct)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException($"oci-manifest::{repository}/{reference}");
        }

        // For digest references, the cache is authoritative (content-addressed).
        if (isDigest)
        {
            var cached = await TryGetCachedManifestByDigestAsync(orgId, reference, ct);
            if (cached is not null)
            {
                return cached;
            }
        }
        else
        {
            // Tag reference: use cache only when within TTL.
            var cached = await TryGetCachedTagManifestAsync(orgId, repository, reference, ct);
            if (cached is not null)
            {
                return cached;
            }
        }

        var upstream = await MatchUpstreamAsync(orgId, repository, ct);
        return upstream is null
            ? null
            : await RouteManifestUpstreamAsync(upstream, orgId, repository, reference, isDigest, ct);
    }

    // A digest reference is content-addressed (plain fetch-and-cache); a tag is a mutable
    // mapping and goes through the revalidation + promotion-gate path.
    private async Task<OciManifestResult?> RouteManifestUpstreamAsync(
        OciUpstreamRegistryOptions upstream, string orgId, string repository, string reference,
        bool isDigest, CancellationToken ct)
        => isDigest
            ? await FetchAndCacheManifestAsync(upstream, orgId, repository, reference, ct)
            : await RevalidateOrFetchTagAsync(upstream, orgId, repository, reference, ct);

    /// <summary>
    /// Fetches only the header metadata for an OCI blob from upstream using a HEAD request —
    /// no body is downloaded. Returns a <see cref="OciBlobMetadata"/> record with the media
    /// type from the upstream response headers when the blob exists, or <c>null</c> when
    /// no upstream matches or the upstream returns 404.
    /// Used by the blob HEAD handler on a cache-miss to avoid downloading the full layer blob.
    /// Throws <see cref="AirGappedException"/> in air-gap mode.
    /// </summary>
    public async Task<OciBlobMetadata?> FetchBlobMetadataAsync(
        string orgId,
        string repository,
        string digest,
        CancellationToken ct)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException($"oci-blob::{repository}/{digest}");
        }

        string[] parts = digest.Split(':', DigestSplitParts);
        if (parts.Length != 2)
        {
            return null;
        }

        // Answer a cache-hit HEAD only from an oci_blobs row scoped to THIS org. A bare
        // content-key existence probe against the shared, content-addressed cache store would
        // report 200/404 based on whether the digest exists for ANY tenant — a cross-tenant
        // existence oracle over org-agnostic storage. Scoping to (digest, org_id) confines the
        // answer to blobs the caller's own org has actually fetched; anything else falls through
        // to a real, org-scoped upstream HEAD.
        var cached = await TryGetCachedBlobMetadataByDigestAsync(orgId, digest, ct);
        if (cached is not null)
        {
            return cached;
        }

        var upstream = await MatchUpstreamAsync(orgId, repository, ct);
        if (upstream is null)
        {
            return null;
        }

        var client = _http.CreateClient("OciUpstream");
        string url = $"https://{upstream.Host}/v2/{repository}/blobs/{digest}";
        string logContext = $"OCI blob HEAD {digest} upstream {upstream.Host}";

        using var resp = await SendUpstreamWithAuthRetryAsync(
            orgId, client, HttpMethod.Head, url, ["application/octet-stream"], upstream, repository, "pull", logContext, ct);
        if (resp is null)
        {
            return null;
        }

        string mediaType = resp.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";
        return new OciBlobMetadata(mediaType);
    }

    // Returns blob HEAD metadata only when the org owns an oci_blobs row for the digest AND the
    // backing bytes are still present in the store. A dangling row (blob evicted) returns null so
    // the caller falls through to upstream rather than reporting a false 200. The (digest, org_id)
    // scope is what keeps a blob HEAD from becoming a cross-tenant existence oracle over the shared
    // content-addressed cache store.
    private async Task<OciBlobMetadata?> TryGetCachedBlobMetadataByDigestAsync(
        string orgId, string digest, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (digest, org_id) PK is tenant-scoped.
        var (MediaType, BlobKey) = await conn.QuerySingleOrDefaultAsync<(string? MediaType, string? BlobKey)>(
            "SELECT media_type AS MediaType, blob_key AS BlobKey " +
            "FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });

        if (BlobKey is null)
        {
            return null;
        }

        bool exists = await _blobs.Cache.ExistsAsync(BlobKey, ct)
            || await _blobs.Registry.ExistsAsync(BlobKey, ct);
        return exists ? new OciBlobMetadata(MediaType ?? "application/octet-stream") : null;
    }

    /// <summary>
    /// Returns the OCI blob for <paramref name="digest"/> from cache or from upstream.
    /// The digest is verified against the downloaded bytes; a mismatch evicts the
    /// partially-written cache entry and returns null.
    ///
    /// A hit on the shared content-addressed store is served only to an org that already
    /// holds its own <c>oci_blobs</c> row for the digest; any other caller falls through to
    /// its own org-scoped upstream fetch, which re-authenticates and re-verifies the digest.
    ///
    /// Concurrent cache-misses are collapsed by a single-flight coordinator keyed on
    /// (org id, content-addressed blob key), so one upstream pull runs per digest per org
    /// per process and a caller may only await a fetch made with its own org's credentials.
    /// Each waiter re-opens the cached blob independently after the shared fetch completes.
    ///
    /// Returns null when no upstream matches or the upstream returns 404.
    /// Throws <see cref="AirGappedException"/> in air-gap mode.
    /// </summary>
    public async Task<OciBlobResult?> FetchBlobAsync(
        string orgId,
        string repository,
        string digest,
        CancellationToken ct)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException($"oci-blob::{repository}/{digest}");
        }

        string[] parts = digest.Split(':', DigestSplitParts);
        if (parts.Length != 2)
        {
            return null;
        }

        string algo = parts[0];
        string hex = parts[1];
        string blobKey = BlobKeys.OciBlob(algo, hex);

        // Blob may already be in the shared content-addressed store from a prior org or request.
        // A bare store hit is NOT authorization: the key (oci/{algo}/{hex}) has no org segment, so
        // in the default single-store deployment (cache == registry) another tenant's PRIVATE
        // uploaded or proxy-cached bytes live under the identical key. Serve the hit only when the
        // caller's own org already holds an oci_blobs row for this digest (its own prior upload or
        // proxy fetch); otherwise dispose the unused stream and fall through to a real upstream
        // fetch scoped to this org (which re-authenticates and re-verifies the digest before
        // caching, rather than trusting that any configured upstream proves entitlement). That
        // fallthrough is a real fetch even under concurrency: the single-flight entry below is
        // keyed per org, so it can never be satisfied by another org's in-flight pull.
        var existing = await _blobs.Cache.GetAsync(blobKey, ct);
        if (existing is not null)
        {
            if (await CanServeSharedBlobAsync(orgId, digest, ct))
            {
                return new OciBlobResult(existing, "application/octet-stream");
            }

            await existing.DisposeAsync();
        }

        var upstream = await MatchUpstreamAsync(orgId, repository, ct);
        if (upstream is null)
        {
            return null;
        }

        // Single-flight: collapse concurrent misses for the same blob into one fetch, keyed on
        // (orgId, blobKey) — never on the content-addressed key alone. The work item captures
        // the org, upstream, and credentials of whichever caller creates the entry, so a key of
        // bytes alone lets a caller from another org await that fetch and receive a private
        // layer pulled with credentials it does not hold, from a registry it cannot reach: the
        // digest-guessing read the entitlement check above refuses, granted through the
        // in-flight window instead. With the org in the key, every caller sharing an entry is
        // from the org whose credentials the entry uses. Concurrent misses in different orgs
        // each pay their own upstream pull and prove their own entitlement; the bytes still
        // dedup in the store, because the write targets the content-addressed key and is
        // idempotent.
        //
        // The shared work item (FetchAndCacheBlobAsync) writes the verified blob to the cache
        // store, persists this org's oci_blobs row, and returns only metadata (blobKey +
        // mediaType). Each waiter below opens its OWN stream via _blobs.Cache.GetAsync so no
        // stream is shared across callers. CancellationToken.None: a caller disconnect must not
        // fault the shared Lazy and cancel all other waiters. Blob writes are idempotent
        // (content-addressed key).
        var inflightKey = new OciBlobInflightKey(orgId, blobKey);
        var lazy = _blobInflight.GetOrAdd(inflightKey, _ => new Lazy<Task<OciBlobFetchMetadata?>>(
            () => FetchAndCacheBlobAsync(orgId, upstream, repository, digest, blobKey, CancellationToken.None),
            LazyThreadSafetyMode.ExecutionAndPublication));
        _blobInflightArrivals.AddOrUpdate(inflightKey, 1, (_, count) => count + 1);

        // Removes exactly this (inflightKey, lazy) pair once the shared fetch genuinely
        // completes — success or failure — never when an individual caller's WaitAsync(ct) below
        // merely detaches early. A caller cancelling mid-fetch must not evict a live in-flight
        // entry while the shared upstream pull is still running for the remaining waiters, and
        // the pair-targeted removal never touches a newer generation that replaced this entry.
        // Every concurrent caller attaches its own continuation to the same Task; TryRemove is
        // idempotent — only the first continuation to run has any effect.
        _ = lazy.Value.ContinueWith(
            completedTask =>
            {
                _blobInflight.TryRemove(
                    new KeyValuePair<OciBlobInflightKey, Lazy<Task<OciBlobFetchMetadata?>>>(inflightKey, lazy));
                // Bounds _blobInflightArrivals to the same lifecycle as _blobInflight — otherwise
                // every distinct digest ever fetched would leak an entry for the life of the process.
                _blobInflightArrivals.TryRemove(inflightKey, out int _);
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);

        // WaitAsync(ct) lets the caller's request token abort the wait without
        // cancelling the shared upstream fetch that other waiters depend on.
        var meta = await lazy.Value.WaitAsync(ct);
        if (meta is null)
        {
            return null;
        }

        // No per-caller oci_blobs row is written here: the in-flight entry is org-keyed, so the
        // work item that resolved it ran for THIS org and already persisted that org's row (with
        // the real media type and size) plus, on first insert, the config-blob arrival hook.
        // A row minted here for a caller the work item did not fetch for would be a grant of
        // another org's bytes on the strength of nothing but a digest.
        //
        // Each waiter opens an INDEPENDENT stream from the cache store — never shared.
        var stream = await _blobs.Cache.GetAsync(meta.BlobKey, ct);
        return stream is null ? null : new OciBlobResult(stream, meta.MediaType);
    }

    /// <summary>
    /// Returns the list of tags for <paramref name="repository"/> from upstream.
    /// Returns null when no upstream matches, the upstream returns 404, or the response is
    /// malformed.
    /// Throws <see cref="AirGappedException"/> in air-gap mode.
    /// </summary>
    public async Task<List<string>?> FetchTagsAsync(string orgId, string repository, CancellationToken ct)
    {
        if (_airGap.IsEnabled)
        {
            throw new AirGappedException($"oci-tags::{repository}");
        }

        var upstream = await MatchUpstreamAsync(orgId, repository, ct);
        if (upstream is null)
        {
            return null;
        }

        var client = _http.CreateClient("OciUpstream");
        string url = $"https://{upstream.Host}/v2/{repository}/tags/list";
        string logContext = $"OCI tags/{repository} upstream {upstream.Host}";

        using var resp = await SendUpstreamWithAuthRetryAsync(
            orgId, client, HttpMethod.Get, url, [], upstream, repository, "pull", logContext, ct);
        return resp is null ? null : await ReadTagListFromResponseAsync(resp, repository, upstream.Host, url, ct);
    }

    // How an upstream answer classifies for the caller. Success carries the response;
    // NotFound is a definitive "the upstream does not have (or will not show us) this";
    // Error is the upstream failing to answer at all (rate limit, server fault) — the two
    // must never be conflated, because NotFound becomes MANIFEST_UNKNOWN/BLOB_UNKNOWN 404
    // (docker treats the image as nonexistent) while Error becomes 502 / stale-if-error.
    private enum UpstreamSendStatus { Success, NotFound, Error }

    private readonly record struct UpstreamSendResult(
        UpstreamSendStatus Status, HttpResponseMessage? Response, System.Net.HttpStatusCode? ErrorStatus);

    // Sends an authenticated HTTP request with a single 401-triggered token eviction and retry,
    // classifying the outcome (see UpstreamSendStatus). The 401 on the first attempt evicts the
    // cached token and retries once. On the retry (or immediately for other statuses):
    //   404              → NotFound.
    //   401 / 403        → NotFound. Docker Hub answers 401 — not 404 — for a nonexistent or
    //                      unauthorized repository even after the token retry; the data plane's
    //                      auth denial is a definitive per-repository answer, distinct from the
    //                      token-exchange endpoint failing (OciUnauthorizedException → 502).
    //   429 / 5xx        → Error carrying the status: the upstream failed to answer, and a
    //                      rate limit must never masquerade as "image does not exist".
    //   other non-2xx    → NotFound (logged) — a definitive if unexpected refusal.
    // Pass HttpCompletionOption.ResponseHeadersRead for streaming body callers.
    // All 11 parameters are distinct protocol-layer inputs (orgId, HTTP client, method, URL,
    // accept types, upstream config, repository, auth scope, log context, cancellation,
    // completion option); grouping them into a request record would scatter the construction
    // across 5+ callers without reducing the conceptual surface.
#pragma warning disable S107 // Each parameter is a distinct protocol-layer input with no natural grouping
    private async Task<UpstreamSendResult> SendUpstreamCoreAsync(
        string orgId,
        HttpClient client,
        HttpMethod method,
        string url,
        IEnumerable<string> acceptTypes,
        OciUpstreamRegistryOptions upstream,
        string repository,
        string scope,
        string logContext,
        CancellationToken ct,
        HttpCompletionOption completionOption = HttpCompletionOption.ResponseContentRead)
#pragma warning restore S107
    {
        for (int attempt = 0; attempt < UpstreamMaxAttempts; attempt++)
        {
            string? authHeader = await _auth.GetAuthorizationAsync(orgId, upstream, repository, scope, ct);
            var req = new HttpRequestMessage(method, url);
            foreach (string mt in acceptTypes)
            {
                req.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue(mt));
            }

            if (authHeader is not null)
            {
                req.Headers.TryAddWithoutValidation("Authorization", authHeader);
            }

            var resp = await client.SendAsync(req, completionOption, ct);

            if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized && attempt == UpstreamFirstAttempt)
            {
                resp.Dispose();
                _auth.InvalidateToken(orgId, upstream, repository, scope);
                continue;
            }

            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                resp.Dispose();
                return new UpstreamSendResult(UpstreamSendStatus.NotFound, null, null);
            }

            if (resp.StatusCode == System.Net.HttpStatusCode.TooManyRequests
                || (int)resp.StatusCode >= ServerErrorStatusFloor)
            {
                var status = resp.StatusCode;
                _logger.LogWarning("{LogContext} returned {Status} — upstream unavailable, not a miss", logContext, status);
                resp.Dispose();
                return new UpstreamSendResult(UpstreamSendStatus.Error, null, status);
            }

            if (!resp.IsSuccessStatusCode)
            {
                _logger.LogWarning("{LogContext} returned {Status}", logContext, resp.StatusCode);
                resp.Dispose();
                return new UpstreamSendResult(UpstreamSendStatus.NotFound, null, null);
            }

            return new UpstreamSendResult(UpstreamSendStatus.Success, resp, null);
        }

        return new UpstreamSendResult(UpstreamSendStatus.NotFound, null, null);
    }

    // Boundary wrapper over SendUpstreamCoreAsync: Success returns the response (caller owns
    // disposal), NotFound returns null, and Error is raised as OciUpstreamUnavailableException so
    // the controller's upstream-failure handling (502 / stale-if-error) sees it on the same
    // terms as a transport exception.
#pragma warning disable S107 // Mirrors SendUpstreamCoreAsync — see the rationale there
    private async Task<HttpResponseMessage?> SendUpstreamWithAuthRetryAsync(
        string orgId,
        HttpClient client,
        HttpMethod method,
        string url,
        IEnumerable<string> acceptTypes,
        OciUpstreamRegistryOptions upstream,
        string repository,
        string scope,
        string logContext,
        CancellationToken ct,
        HttpCompletionOption completionOption = HttpCompletionOption.ResponseContentRead)
#pragma warning restore S107
    {
        var result = await SendUpstreamCoreAsync(
            orgId, client, method, url, acceptTypes, upstream, repository, scope, logContext, ct, completionOption);
        return result.Status == UpstreamSendStatus.Error
            ? throw new OciUpstreamUnavailableException(result.ErrorStatus, logContext)
            : result.Response;
    }

    // Reads the tags/list JSON response body and extracts the tags array as a string list.
    // Returns null when the body exceeds the metadata cap or the tags property is absent.
    private async Task<List<string>?> ReadTagListFromResponseAsync(
        HttpResponseMessage resp, string repository, string host, string url, CancellationToken ct)
    {
        byte[] body;
        try
        {
            // Tag lists are small JSON documents; cap the buffered read like manifests.
            body = await UpstreamClient.ReadBodyCappedAsync(
                resp, UpstreamClient.MaxMetadataResponseBytes, url, ct);
        }
        catch (UpstreamResponseTooLargeException ex)
        {
            _logger.LogWarning(ex,
                "OCI tags/{Repository} from {Host} exceeded the metadata cap; refusing.",
                repository, host);
            return null;
        }

        using var doc = JsonDocument.Parse(body);
        return !doc.RootElement.TryGetProperty("tags", out var tagsEl)
            ? null
            : tagsEl.EnumerateArray()
            .Where(t => t.ValueKind == JsonValueKind.String)
            .Select(t => t.GetString()!)
            .ToList();
    }

    /// <summary>
    /// True when a locally-held tag entry must be re-checked against its upstream before it may
    /// be served.
    ///
    /// <para>
    /// Only a *proxy* tag is subject to the TTL, and the stamp is what identifies one. A push
    /// writes <c>last_revalidated = NULL</c> (<c>OciUploadService</c> sets it explicitly on the
    /// conflict branch and omits it on insert) because a hosted tag has no upstream that could
    /// disagree with it; every proxy fetch writes a timestamp. So a NULL stamp means "pushed
    /// here", never "stale".
    /// </para>
    ///
    /// <para>
    /// The blob row's <c>origin</c> cannot answer this. <c>oci_blobs</c> is content-addressed and
    /// shared, so a manifest pushed here keeps <c>origin = 'proxy'</c> when the same bytes were
    /// proxied first — the dedup state <c>OciPushTests.DeleteManifest_ByDigest_WhenOriginIsProxy_StillDeletes</c>
    /// pins. Origin describes the bytes; the stamp describes the tag, and it is the tag that is
    /// mutable.
    /// </para>
    /// </summary>
    public bool IsTagDueForUpstreamRevalidation(string? lastRevalidated) =>
        lastRevalidated is not null && !IsTagEntryFresh(lastRevalidated);

    /// <summary>
    /// True when an <c>oci_tags</c> entry stamped <paramref name="lastRevalidated"/> is still
    /// within <c>Oci:ManifestTagTtl</c> and may be served without consulting the upstream.
    ///
    /// <para>
    /// The single authority for tag freshness. A tag is a mutable reference by the Distribution
    /// Spec, so "the cached digest is still what the upstream means by this tag" has an expiry;
    /// a digest reference is content-addressed and never consults this. Both the manifest and
    /// the metadata (HEAD) cache lookups read it, and so does the controller's local serve path —
    /// which resolves the tag itself and would otherwise pin a cached digest forever, since it
    /// runs before any code in this class.
    /// </para>
    ///
    /// <para>
    /// A NULL or unparseable timestamp is stale, not fresh: the column exists to record that a
    /// revalidation happened, so its absence is the absence of that evidence. Failing the other
    /// way would let a row written without the stamp — a bad migration, a hand-edited database —
    /// serve unrevalidated forever, which is the failure this method exists to prevent.
    /// </para>
    /// </summary>
    public bool IsTagEntryFresh(string? lastRevalidated) =>
        lastRevalidated is not null
        && DateTimeOffset.TryParse(
            lastRevalidated, null, System.Globalization.DateTimeStyles.RoundtripKind, out var revalidated)
        && _time.GetUtcNow() - revalidated < _options.Value.ManifestTagTtl;

    /// <summary>
    /// True when a tag whose <c>last_revalidated</c> stamp is <paramref name="lastRevalidated"/>
    /// may still serve its last accepted digest through an upstream failure.
    ///
    /// <para>
    /// The grace window is measured from the moment the entry became stale —
    /// <c>last_revalidated + ManifestTagTtl</c> — never from the most recent failed attempt.
    /// A failed revalidation does not refresh <c>last_revalidated</c> (only a successful one
    /// does), so repeated failures cannot slide the deadline: however many times the upstream
    /// errors during an outage, the tag stops serving at exactly
    /// <c>last_revalidated + ManifestTagTtl + ManifestTagStaleGrace</c>. Without that anchoring,
    /// a weeks-long outage would silently become serve-stale-forever.
    /// </para>
    /// </summary>
    public bool IsWithinStaleGrace(string? lastRevalidated) =>
        lastRevalidated is not null
        && DateTimeOffset.TryParse(
            lastRevalidated, null, System.Globalization.DateTimeStyles.RoundtripKind, out var revalidated)
        && _time.GetUtcNow() - revalidated
            < _options.Value.ManifestTagTtl + _options.Value.ManifestTagStaleGrace;

    // ── Shared tag observation (instance-wide, credential-scoped) ─────────────

    // In-cache identity of one upstream tag observation. CredentialFingerprint is what keeps
    // the sharing inside a single credential identity — see the _tagObservations field comment.
    private readonly record struct OciTagObservationKey(
        string Host, string Repository, string Tag, string CredentialFingerprint);

    private enum TagObservationKind { Found, NotFound, NoDigest }

    // One upstream answer to "what does this tag point at": the digest plus the HEAD header
    // metadata, stamped with when it was observed. Never carries manifest bytes — bodies are
    // always fetched per-org with that org's own credentials.
    private sealed record TagObservation(
        TagObservationKind Kind, string? Digest, string MediaType, long SizeBytes, DateTimeOffset ObservedAt);

    // Collapses the upstream credential material to an opaque identity. SHA-256 rather than the
    // raw values so secrets are not retained as dictionary keys; any difference in auth type,
    // username, password, or pinned token endpoint yields a different fingerprint and therefore
    // no sharing.
    private static string CredentialFingerprint(OciUpstreamRegistryOptions upstream)
    {
        string material = string.Join(
            '\n', (int)upstream.AuthType, upstream.Username, upstream.Password, upstream.TokenEndpoint);
        return Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(material)));
    }

    private bool IsObservationFresh(TagObservation obs) =>
        _time.GetUtcNow() - obs.ObservedAt < _options.Value.ManifestTagTtl;

    /// <summary>
    /// Answers "what digest does this tag point at upstream" through the shared observation
    /// cache: a fresh cached answer is reused without any network traffic; concurrent callers
    /// (across tenants sharing a credential identity) collapse into one upstream HEAD; and a
    /// miss issues the HEAD with the calling org's own credentials. Throws
    /// <see cref="OciUpstreamUnavailableException"/> (or a transport exception) when the
    /// upstream fails to answer.
    /// </summary>
    private async Task<TagObservation> ObserveUpstreamTagAsync(
        string orgId, OciUpstreamRegistryOptions upstream, string repository, string tag, CancellationToken ct)
    {
        var key = new OciTagObservationKey(upstream.Host, repository, tag, CredentialFingerprint(upstream));
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            if (_tagObservations.Count >= MaxTagObservations)
            {
                PruneTagObservations();
            }

            var lazy = _tagObservations.GetOrAdd(key, _ => new Lazy<Task<TagObservation>>(
                // CancellationToken.None inside the shared fetch: the answer is shared by every
                // caller with the same credential identity, so one caller's disconnect must not
                // fault the Lazy for the rest — same posture as the blob single-flight.
                () => FetchTagObservationAsync(orgId, upstream, repository, tag),
                LazyThreadSafetyMode.ExecutionAndPublication));
            var pair = new KeyValuePair<OciTagObservationKey, Lazy<Task<TagObservation>>>(key, lazy);
            var task = lazy.Value;

            if (task.IsCompletedSuccessfully)
            {
                var done = task.Result;
                if (done.Kind == TagObservationKind.Found && IsObservationFresh(done))
                {
                    return done;
                }

                if (done.Kind == TagObservationKind.Found)
                {
                    // A stale Found answer is the one completed state worth retrying: evict
                    // exactly this pair and loop into a fresh fetch.
                    _tagObservations.TryRemove(pair);
                    continue;
                }

                // NotFound/NoDigest: a definitive current answer for THIS caller — return it,
                // but evict so it is never served to a later caller from cache. Looping here
                // instead would refetch the same answer forever when the fetch completes
                // synchronously (a stubbed or very fast upstream).
                _tagObservations.TryRemove(pair);
                return done;
            }

            // In flight or faulted (this caller may be the creator or a joiner). Non-Found and
            // faulted results are evicted on completion so a failure is never served from
            // cache; a Found result stays until ManifestTagTtl old. TryRemove is pair-targeted
            // and idempotent, so racing continuations cannot evict a newer generation. A
            // faulted task rethrows out of WaitAsync to THIS caller — it must propagate, never
            // loop into a synchronous refetch storm.
            _ = task.ContinueWith(
                t =>
                {
                    if (t.IsFaulted || t.IsCanceled || t.Result.Kind != TagObservationKind.Found)
                    {
                        _tagObservations.TryRemove(pair);
                    }
                },
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);

            // WaitAsync(ct) lets this caller abandon the wait without cancelling the shared HEAD.
            return await task.WaitAsync(ct);
        }
    }

    // Returns a still-fresh cached observation without ever touching the network, or null.
    // Used by the first-fetch path, where a direct GET-by-tag is otherwise the cheaper call.
    private TagObservation? TryGetFreshObservation(
        OciUpstreamRegistryOptions upstream, string repository, string tag)
    {
        var key = new OciTagObservationKey(upstream.Host, repository, tag, CredentialFingerprint(upstream));
        return _tagObservations.TryGetValue(key, out var lazy)
            && lazy.IsValueCreated
            && lazy.Value.IsCompletedSuccessfully
            && lazy.Value.Result is { Kind: TagObservationKind.Found } done
            && IsObservationFresh(done)
            ? done
            : null;
    }

    // Records an observation derived from a digest-verified per-org GET-by-tag body, so
    // sequential callers (same credential identity) within the TTL reuse it without a HEAD.
    private void StoreTagObservation(
        OciUpstreamRegistryOptions upstream, string repository, string tag,
        string digest, string mediaType, long sizeBytes)
    {
        if (_tagObservations.Count >= MaxTagObservations)
        {
            PruneTagObservations();
        }

        var key = new OciTagObservationKey(upstream.Host, repository, tag, CredentialFingerprint(upstream));
        var obs = new TagObservation(TagObservationKind.Found, digest, mediaType, sizeBytes, _time.GetUtcNow());
        _tagObservations[key] = new Lazy<Task<TagObservation>>(
            () => Task.FromResult(obs), LazyThreadSafetyMode.ExecutionAndPublication);
    }

    // Expiry-ordered pruning, mirroring OciUpstreamAuthService.PruneTokens: drop completed
    // stale/non-Found entries first, then evict oldest-observed completed entries while still
    // over the cap. In-flight entries are never pruned.
    private void PruneTagObservations()
    {
        foreach (var kv in _tagObservations)
        {
            if (kv.Value.IsValueCreated && kv.Value.Value.IsCompleted
                && (!kv.Value.Value.IsCompletedSuccessfully
                    || kv.Value.Value.Result.Kind != TagObservationKind.Found
                    || !IsObservationFresh(kv.Value.Value.Result)))
            {
                _tagObservations.TryRemove(kv);
            }
        }

        int overBy = _tagObservations.Count - MaxTagObservations + 1;
        if (overBy <= 0)
        {
            return;
        }

        foreach (var kv in _tagObservations
            .Where(e => e.Value.IsValueCreated && e.Value.Value.IsCompletedSuccessfully)
            .OrderBy(e => e.Value.Value.Result.ObservedAt)
            .Take(overBy))
        {
            _tagObservations.TryRemove(kv);
        }
    }

    // The shared HEAD that produces an observation. Issued with the creating org's credentials;
    // only callers whose upstream carries byte-identical credential material can ever share the
    // resulting entry (the fingerprint is part of the cache key).
    private async Task<TagObservation> FetchTagObservationAsync(
        string orgId, OciUpstreamRegistryOptions upstream, string repository, string tag)
    {
        string url = $"https://{upstream.Host}/v2/{repository}/manifests/{tag}";
        var client = _http.CreateClient("OciUpstream");
        string logContext = $"OCI tag observation HEAD {repository}:{tag} upstream {upstream.Host}";

        using var resp = await SendUpstreamWithAuthRetryAsync(
            orgId, client, HttpMethod.Head, url, ManifestAcceptTypes, upstream, repository, "pull",
            logContext, CancellationToken.None);
        if (resp is null)
        {
            return new TagObservation(TagObservationKind.NotFound, null, "", 0, _time.GetUtcNow());
        }

        var meta = ExtractManifestMetadataFromHeadResponse(resp, repository, tag, upstream.Host);
        return meta is null
            ? new TagObservation(TagObservationKind.NoDigest, null, "", 0, _time.GetUtcNow())
            : new TagObservation(TagObservationKind.Found, meta.Digest, meta.MediaType, meta.SizeBytes, _time.GetUtcNow());
    }

    // ── Tag revalidation + promotion gate ─────────────────────────────────────

    // The org's oci_tags row for one tag, or all-null when the tag has never been recorded.
    private sealed record OciTagRow(
        string? Digest, string? LastRevalidated, string? PendingDigest, string? PendingFirstSeenAt);

    private async Task<OciTagRow> ReadTagRowAsync(
        string orgId, string repository, string tag, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (org_id, repository, tag) PK.
        var row = await conn.QuerySingleOrDefaultAsync<OciTagRow>(
            "SELECT digest AS Digest, last_revalidated AS LastRevalidated, " +
            "pending_digest AS PendingDigest, pending_first_seen_at AS PendingFirstSeenAt " +
            "FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND tag = @tag",
            new { orgId, repo = repository, tag });
        return row ?? new OciTagRow(null, null, null, null);
    }

    // A successful revalidation confirmed the accepted mapping: refresh the freshness stamp and
    // drop any pending observation (upstream no longer advertises it, so it must not stick).
    private async Task ConfirmTagUnchangedAsync(
        string orgId, string repository, string tag, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (org_id, repository, tag) PK.
        await conn.ExecuteAsync(
            "UPDATE oci_tags SET last_revalidated = @now, pending_digest = NULL, pending_first_seen_at = NULL " +
            "WHERE org_id = @orgId AND repository = @repo AND tag = @tag",
            new { orgId, repo = repository, tag, now = UtcTimestamp.Now(_time) });
    }

    // Records a newly observed digest as pending WITHOUT advancing the tag. pending_first_seen_at
    // resets only when the observed digest differs from the held pending one (upstream moved on
    // again — the stuck-pending case), so the promotion age keeps accruing across revalidations
    // that keep observing the same digest. refreshStamp marks the revalidation itself as
    // successful (the upstream answered; holding is a policy decision, not a failure) — the HEAD
    // path passes false when it wants the next GET-by-tag to revalidate and repoint promptly.
    private async Task HoldPendingDigestAsync(
        string orgId, string repository, string tag, string observedDigest, bool refreshStamp, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        string now = UtcTimestamp.Now(_time);
        // xtenant: (org_id, repository, tag) PK.
        await conn.ExecuteAsync(
            """
            UPDATE oci_tags SET
                pending_digest = @observed,
                pending_first_seen_at = CASE WHEN pending_digest = @observed THEN pending_first_seen_at ELSE @now END,
                last_revalidated = CASE WHEN @refresh = 1 THEN @now ELSE last_revalidated END
            WHERE org_id = @orgId AND repository = @repo AND tag = @tag
            """,
            new { orgId, repo = repository, tag, observed = observedDigest, now, refresh = refreshStamp ? 1 : 0 });
    }

    /// <summary>
    /// Whether a newly observed digest may be promoted onto the tag right now.
    ///
    /// <para>
    /// Age is measured from the FIRST LOCAL OBSERVATION of the digest
    /// (<c>oci_tags.pending_first_seen_at</c>) — deliberately NOT from the image config blob's
    /// <c>created</c> timestamp. That is a security requirement, not a convenience:
    /// <c>created</c> is publisher-controlled, so a malicious rebuild can backdate it and
    /// bypass the cooldown entirely, whereas the local observation clock is this instance's
    /// own and cannot be influenced by the publisher.
    /// </para>
    /// </summary>
    private bool IsPromotionAllowed(OciTagRow row, string observedDigest, int? minReleaseAgeHours)
    {
        if (minReleaseAgeHours is null or <= 0)
        {
            return true; // policy off — promote immediately, preserving pre-gate behaviour
        }

        return string.Equals(row.PendingDigest, observedDigest, StringComparison.OrdinalIgnoreCase)
            && row.PendingFirstSeenAt is not null
            && DateTimeOffset.TryParse(
                row.PendingFirstSeenAt, null, System.Globalization.DateTimeStyles.RoundtripKind, out var firstSeen)
            && _time.GetUtcNow() - firstSeen >= TimeSpan.FromHours(minReleaseAgeHours.Value);
    }

    private async Task<int?> GetMinReleaseAgeHoursAsync(string orgId, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<int?>(
            "SELECT min_release_age_hours FROM org_settings WHERE org_id = @orgId",
            new { orgId });
    }

    // Serves the digest the tag currently (still) resolves to: from the local cache when
    // present, otherwise re-fetched by digest from upstream with this org's own credentials —
    // a by-digest fetch is content-addressed and never touches the tag row, so an evicted
    // accepted manifest does not make a promotion-held or unchanged tag unavailable.
    private async Task<OciManifestResult?> ServeAcceptedDigestAsync(
        OciUpstreamRegistryOptions upstream, string orgId, string repository, string digest, CancellationToken ct)
        => await TryGetCachedManifestByDigestAsync(orgId, digest, ct)
            ?? await FetchAndCacheManifestAsync(upstream, orgId, repository, digest, ct);

    /// <summary>
    /// Revalidates (or first-fetches) a tag reference against upstream, applying the promotion
    /// gate. The three policies stay orthogonal here: the TTL decided that this method runs at
    /// all (the caller found the entry stale); <c>min_release_age_hours</c> decides only whether
    /// a newly observed digest may be PROMOTED (a too-young digest keeps the previously
    /// accepted one serving — never an unavailable tag); and the stale grace lives in the
    /// controller, on the failure path of the upstream calls made here.
    /// </summary>
    private async Task<OciManifestResult?> RevalidateOrFetchTagAsync(
        OciUpstreamRegistryOptions upstream, string orgId, string repository, string tag, CancellationToken ct)
    {
        var row = await ReadTagRowAsync(orgId, repository, tag, ct);
        if (row.Digest is null)
        {
            // First local sighting of the tag: there is no accepted digest the promotion gate
            // could hold the tag AT, and min_release_age gates promotion, never availability —
            // so the first resolution always lands. A fresh shared observation (another
            // caller's recent answer under the same credential identity) skips the upstream
            // ask entirely; otherwise a direct GET-by-tag is the cheaper single round-trip.
            var cachedObs = TryGetFreshObservation(upstream, repository, tag);
            if (cachedObs?.Digest is { } observedDigest)
            {
                var promoted = await PromoteTagAsync(upstream, orgId, repository, tag, observedDigest, ct);
                if (promoted is not null)
                {
                    return promoted;
                }
            }

            return await FetchAndCacheManifestAsync(upstream, orgId, repository, tag, ct);
        }

        int? minAgeHours = await GetMinReleaseAgeHoursAsync(orgId, ct);
        var obs = await ObserveUpstreamTagAsync(orgId, upstream, repository, tag, ct);
        return obs.Kind switch
        {
            // A definitive upstream "this tag does not exist" is a genuine miss — the one case
            // that correctly becomes MANIFEST_UNKNOWN. Upstream errors never reach here; they
            // throw out of ObserveUpstreamTagAsync into the controller's stale-if-error handling.
            TagObservationKind.NotFound => null,
            // Registry answered HEAD without a usable digest: revalidate the legacy way with a
            // full GET by tag, gating the repoint on the digest computed from the verified body.
            TagObservationKind.NoDigest => await RevalidateWithBodyAsync(
                upstream, orgId, repository, tag, row, minAgeHours, ct),
            _ => await ApplyRevalidationAsync(
                upstream, orgId, repository, tag, row, minAgeHours, obs.Digest!, ct),
        };
    }

    // Applies one successful upstream observation to the org's tag row: confirm, promote, or
    // hold-pending — and serve whichever digest the tag resolves to after that decision.
#pragma warning disable S107 // Revalidation threads the routing context (upstream/org/repo/tag) plus the decision inputs (row, policy, observation)
    private async Task<OciManifestResult?> ApplyRevalidationAsync(
        OciUpstreamRegistryOptions upstream, string orgId, string repository, string tag,
        OciTagRow row, int? minAgeHours, string observedDigest, CancellationToken ct)
#pragma warning restore S107
    {
        if (string.Equals(observedDigest, row.Digest, StringComparison.OrdinalIgnoreCase))
        {
            await ConfirmTagUnchangedAsync(orgId, repository, tag, ct);
            return await ServeAcceptedDigestAsync(upstream, orgId, repository, row.Digest!, ct);
        }

        if (IsPromotionAllowed(row, observedDigest, minAgeHours))
        {
            var promoted = await PromoteTagAsync(upstream, orgId, repository, tag, observedDigest, ct);
            if (promoted is not null)
            {
                return promoted;
            }

            // The observed digest vanished between the HEAD and the by-digest fetch (an
            // upstream mid-repoint). The accepted mapping is still the best true answer.
            return await ServeAcceptedDigestAsync(upstream, orgId, repository, row.Digest!, ct);
        }

        // Too young to promote: record (or keep aging) the observation and keep serving the
        // previously accepted digest. The revalidation itself succeeded, so the stamp refreshes —
        // the next upstream ask comes after another TTL, by which time the pending digest has
        // aged that much further.
        await HoldPendingDigestAsync(orgId, repository, tag, observedDigest, refreshStamp: true, ct);
        return await ServeAcceptedDigestAsync(upstream, orgId, repository, row.Digest!, ct);
    }

    // Legacy-shaped revalidation for registries whose HEAD carries no Docker-Content-Digest:
    // one GET by tag, promotion gated on the digest computed from the verified body.
    private async Task<OciManifestResult?> RevalidateWithBodyAsync(
        OciUpstreamRegistryOptions upstream, string orgId, string repository, string tag,
        OciTagRow row, int? minAgeHours, CancellationToken ct)
    {
        string url = $"https://{upstream.Host}/v2/{repository}/manifests/{tag}";
        var m = await TryFetchManifestAsync(orgId, upstream, repository, tag, url, ct);
        if (m is null)
        {
            return null;
        }

        StoreTagObservation(upstream, repository, tag, m.Digest, m.MediaType, m.Bytes.Length);

        if (string.Equals(m.Digest, row.Digest, StringComparison.OrdinalIgnoreCase)
            || IsPromotionAllowed(row, m.Digest, minAgeHours))
        {
            // Unchanged (repoint is a no-op that refreshes the stamp) or promotable: the full
            // cache-and-repoint path, which writes the body before the tag as always.
            return await CacheAndReturnManifestAsync(upstream, orgId, repository, tag, m, ct);
        }

        await HoldPendingDigestAsync(orgId, repository, tag, m.Digest, refreshStamp: true, ct);
        return await ServeAcceptedDigestAsync(upstream, orgId, repository, row.Digest!, ct);
    }

    /// <summary>
    /// Promotes a tag to a newly observed digest: fetches the manifest body BY DIGEST with this
    /// org's own credentials (digest-verified by <see cref="TryFetchManifestAsync"/>), caches
    /// it, and only then repoints the tag — the write ordering that guarantees a tag never
    /// points at a digest whose manifest body is absent. Returns null when the digest is no
    /// longer fetchable upstream (nothing is written in that case).
    /// </summary>
    private async Task<OciManifestResult?> PromoteTagAsync(
        OciUpstreamRegistryOptions upstream, string orgId, string repository, string tag,
        string digest, CancellationToken ct)
    {
        string url = $"https://{upstream.Host}/v2/{repository}/manifests/{digest}";
        var m = await TryFetchManifestAsync(orgId, upstream, repository, digest, url, ct);
        if (m is null)
        {
            return null;
        }

        var result = await CacheAndReturnManifestAsync(upstream, orgId, repository, digest, m, ct);
        await RepointTagAsync(upstream, orgId, repository, tag, m, ct);
        return result;
    }

    // ── Cache lookup helpers ───────────────────────────────────────────────────

    private async Task<OciManifestResult?> TryGetCachedManifestByDigestAsync(
        string orgId, string digest, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (digest, org_id) PK is already tenant-scoped.
        var (MediaType, SizeBytes, BlobKey) = await conn.QuerySingleOrDefaultAsync<(string? MediaType, long SizeBytes, string? BlobKey)>(
            "SELECT media_type AS MediaType, size_bytes AS SizeBytes, blob_key AS BlobKey " +
            "FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });
        if (BlobKey is null)
        {
            return null;
        }

        var stream = await _blobs.Cache.GetAsync(BlobKey, ct);
        if (stream is null)
        {
            return null; // evicted — fall through to upstream
        }

        return new OciManifestResult(stream, MediaType ?? "application/octet-stream", digest, SizeBytes);
    }

    private async Task<OciManifestResult?> TryGetCachedTagManifestAsync(
        string orgId, string repository, string tag, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (org_id, repository, tag) PK.
        var (Digest, LastRevalidated) = await conn.QuerySingleOrDefaultAsync<(string? Digest, string? LastRevalidated)>(
            "SELECT digest AS Digest, last_revalidated AS LastRevalidated " +
            "FROM oci_tags WHERE org_id = @orgId AND repository = @repo AND tag = @tag",
            new { orgId, repo = repository, tag });

        if (Digest is null)
        {
            return null;
        }

        if (IsTagEntryFresh(LastRevalidated))
        {
            return await TryGetCachedManifestByDigestAsync(orgId, Digest, ct);
        }

        // Stale or missing — fall through to upstream.
        return null;
    }

    // ── Upstream fetch + cache-write helpers ──────────────────────────────────

    private async Task<OciManifestResult?> FetchAndCacheManifestAsync(
        OciUpstreamRegistryOptions upstream,
        string orgId,
        string repository,
        string reference,
        CancellationToken ct)
    {
        string url = $"https://{upstream.Host}/v2/{repository}/manifests/{reference}";
        var manifest = await TryFetchManifestAsync(orgId, upstream, repository, reference, url, ct);
        return manifest is null ? null : await CacheAndReturnManifestAsync(upstream, orgId, repository, reference, manifest, ct);
    }

    private async Task<FetchedManifest?> TryFetchManifestAsync(
        string orgId, OciUpstreamRegistryOptions upstream, string repository, string reference,
        string url, CancellationToken ct)
    {
        var client = _http.CreateClient("OciUpstream");
        // A non-success status (e.g. Docker Hub returns 401 — not 404 — for a
        // nonexistent/unauthorized repository even after the token retry) must surface
        // as a clean OCI MANIFEST_UNKNOWN 404 from the controller, not an unhandled
        // HttpRequestException → 500. Mirror the blob/tags paths: log and return null.
        string logContext = $"OCI manifest {repository}:{reference} upstream {upstream.Host}";

        using var resp = await SendUpstreamWithAuthRetryAsync(
            orgId, client, HttpMethod.Get, url, ManifestAcceptTypes, upstream, repository, "pull", logContext, ct);
        if (resp is null)
        {
            return null;
        }

        string mediaType = resp.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";
        byte[] bytes;
        try
        {
            // Manifests are small JSON documents (the spec recommends ≤ 4 MB); cap the buffered
            // read so a hostile upstream cannot materialise an arbitrarily large body in memory.
            bytes = await UpstreamClient.ReadBodyCappedAsync(
                resp, UpstreamClient.MaxMetadataResponseBytes, url, ct);
        }
        catch (UpstreamResponseTooLargeException ex)
        {
            _logger.LogWarning(ex,
                "OCI manifest {Repository}:{Reference} from {Host} exceeded the metadata cap; refusing.",
                repository, reference, upstream.Host);
            return null;
        }
        string digest = ResolveDigest(resp, repository, reference, bytes, out string? sha256Hex);

        // For by-digest references the caller already knows which digest to expect.
        // Verify the computed digest matches before caching — if upstream returns bytes
        // that hash to a different digest the fetch fails closed (no cache write, no DB
        // row) rather than serving attacker-controlled content under the requested key.
        if (OciCoordinatesParser.IsValidDigest(reference) &&
            !string.Equals(digest, reference, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning(
                "OCI manifest digest mismatch for {Repository}/{Reference}: computed {Computed} does not match requested digest",
                repository, reference, digest);
            return null;
        }

        return new FetchedManifest(bytes, mediaType, digest, sha256Hex);
    }

    private string ResolveDigest(
        HttpResponseMessage resp, string repository, string reference, byte[] bytes, out string sha256Hex)
    {
        byte[] sha256Bytes = SHA256.HashData(bytes);
        sha256Hex = Convert.ToHexString(sha256Bytes).ToLowerInvariant();
        string digest = "sha256:" + sha256Hex;

        // The content-addressed identity is the SHA-256 of the exact bytes cached and served, so
        // a by-digest fetch always returns bytes that hash to the requested digest (the OCI
        // Distribution Spec invariant). If upstream's Docker-Content-Digest disagrees, treat it
        // as an upstream integrity anomaly and keep the computed value — never adopt an
        // unverified header as the stored digest identity.
        if (resp.Headers.TryGetValues("Docker-Content-Digest", out var dcdValues))
        {
            string? upstreamDigest = dcdValues.FirstOrDefault();
            if (!string.IsNullOrEmpty(upstreamDigest) && upstreamDigest != digest)
            {
                _logger.LogWarning(
                    "OCI {Repository}/{Reference}: upstream Docker-Content-Digest {Upstream} differs from computed {Computed}; using computed",
                    repository, reference, upstreamDigest, digest);
            }
        }
        return digest;
    }

    private async Task<OciManifestResult> CacheAndReturnManifestAsync(
        OciUpstreamRegistryOptions upstream, string orgId, string repository, string reference,
        FetchedManifest m, CancellationToken ct)
    {
        string blobKey = BlobKeys.OciBlob("sha256", m.Sha256Hex);

        // Write manifest bytes into the proxy cache tier.
        await _blobs.Cache.PutAsync(blobKey, new MemoryStream(m.Bytes), ct);

        await using var conn = await _db.OpenAsync(ct);

        // xtenant: (digest, org_id) PK is tenant-scoped.
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin, cached_at)
            VALUES (@digest, @orgId, @mediaType, @sizeBytes, @blobKey, 'proxy', @now)
            ON CONFLICT(digest, org_id) DO UPDATE SET
                upstream_checked_at = @now
            """,
            new
            {
                digest = m.Digest,
                orgId,
                mediaType = m.MediaType,
                sizeBytes = (long)m.Bytes.Length,
                blobKey,
                now = UtcTimestamp.Now(_time),
            });

        // Capture the image license from the config label onto this manifest row. Runs outside the
        // tag branch so by-digest child manifests of a pulled index are covered too. Best-effort.
        await _licenseRecorder.RecordManifestAsync(orgId, m.Digest, m.Bytes, ct);

        // Record what this manifest references, so eviction can tell a shared layer from an
        // orphaned one. Outside the tag branch for the same reason as the license capture: an
        // index's by-digest children are manifests in their own right and each has a closure.
        // A body that does not parse records nothing, leaving the manifest un-evictable — the
        // conservative direction, and the same posture the read path takes on a malformed body.
        if (OciManifestParser.ParseReferences(m.Bytes) is { } refs)
        {
            await _referenceGraph.RecordAsync(orgId, m.Digest, refs.Digests, ct);
        }

        // Upsert tag → digest when the reference is a tag (not a digest). The manifest body was
        // written above, preserving the body-before-tag write ordering.
        if (!OciCoordinatesParser.IsValidDigest(reference))
        {
            await RepointTagAsync(upstream, orgId, repository, reference, m, ct);
        }

        _logger.LogInformation(
            "OCI manifest proxy {Repository}/{Reference} → {Digest} ({Bytes} B) from {Host}",
            repository, reference, m.Digest, m.Bytes.Length, upstream.Host);

        return new OciManifestResult(new MemoryStream(m.Bytes), m.MediaType, m.Digest, m.Bytes.Length);
    }

    /// <summary>
    /// Repoints (or first-records) a tag at a manifest whose body is already durably cached —
    /// every caller runs after the body write, keeping the body-before-tag ordering — and
    /// surfaces the pull in the shared package catalogue. Clears any pending observation: the
    /// repoint IS the promotion (or a confirmation of the same digest), so nothing is pending
    /// afterwards. Also records the tag → digest answer in the shared observation cache, since
    /// a digest-verified body is at least as authoritative as an upstream HEAD.
    /// </summary>
    private async Task RepointTagAsync(
        OciUpstreamRegistryOptions upstream, string orgId, string repository, string tag,
        FetchedManifest m, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (org_id, repository, tag) PK.
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_tags (org_id, repository, tag, digest, updated_at, last_revalidated)
            VALUES (@orgId, @repo, @tag, @digest, @now, @now)
            ON CONFLICT(org_id, repository, tag) DO UPDATE SET
                digest          = excluded.digest,
                updated_at      = excluded.updated_at,
                last_revalidated = excluded.last_revalidated,
                pending_digest = NULL,
                pending_first_seen_at = NULL
            """,
            new { orgId, repo = repository, tag, digest = m.Digest, now = UtcTimestamp.Now(_time) });

        StoreTagObservation(upstream, repository, tag, m.Digest, m.MediaType, m.Bytes.Length);

        // Surface the pulled image in the shared package catalogue the dashboards +
        // Packages page read from. OCI otherwise lives only in oci_blobs/oci_tags and
        // counts as zero everywhere. Only tag pulls are catalogued (the user-facing
        // unit); by-digest sub-manifest fetches the daemon issues afterwards are not.
        string blobKey = BlobKeys.OciBlob("sha256", m.Sha256Hex);
        string manifestUrl = $"https://{upstream.Host}/v2/{repository}/manifests/{tag}";
        await RecordCatalogVersionAsync(
            orgId,
            new OciCatalogEntry(repository, tag, m.Digest, m.Sha256Hex, (long)m.Bytes.Length, blobKey, manifestUrl),
            ct);
    }

    private sealed record FetchedManifest(byte[] Bytes, string MediaType, string Digest, string Sha256Hex);

    private readonly record struct OciCatalogEntry(
        string Repository, string Tag, string Digest, string Sha256Hex, long SizeBytes, string BlobKey,
        string? UpstreamUrl);

    /// <summary>
    /// Records the pulled image in the shared package catalogue: a <c>packages</c> row (so the
    /// Packages page and its detail route resolve the repository name) plus a global-plane
    /// <c>cache_artifact</c> / <c>tenant_artifact_access</c> row pair — the same shared cache
    /// plane every other proxy ecosystem uses — rather than a <c>package_versions</c> row. The
    /// manifest digest is the content-addressed version identity; the resolving tag is captured
    /// in the PURL qualifier. Only manifest pulls land a row here — one per pullable image,
    /// matching a <c>docker pull</c> 1:1; layers and config blobs stay in <c>oci_blobs</c> as
    /// pure byte storage with no cache-plane entry.
    ///
    /// Best-effort: the caller (<see cref="CacheAndReturnManifestAsync"/>) awaits this before
    /// returning the manifest to the client, so an unhandled exception here would 500 a pull
    /// whose bytes are already durably cached (blob store + <c>oci_blobs</c> row, both written
    /// before this call). <see cref="CacheAccessRecorder.RecordAccessAsync"/> already swallows
    /// its own failures and <see cref="PackageRepository.GetOrCreateAsync"/> resolves races via
    /// <c>ON CONFLICT DO NOTHING</c> + re-read, but <see cref="CacheArtifactRepository.UpdateGlobalFactsAsync"/>
    /// and the <c>GetOrCreateAsync</c> call itself are plain Dapper calls that still throw on a
    /// transient fault (SQLITE_BUSY, a dropped connection) — caught here so cataloguing can never
    /// fail the pull.
    /// </summary>
    private async Task RecordCatalogVersionAsync(string orgId, OciCatalogEntry entry, CancellationToken ct)
    {
        try
        {
            // purl_name == repository so the Packages-page detail route (/packages/oci/{name})
            // resolves; isProxy=true marks the package as upstream-backed.
            await _packages.GetOrCreateAsync(orgId, "oci", entry.Repository, entry.Repository, isProxy: true, ct);
            string purl = PurlNormalizer.Oci(entry.Repository, entry.Digest, entry.Tag);

            // Name is entry.Repository, matching the purl_name GetOrCreateAsync just wrote onto
            // the packages row above — the cross-plane version-count join in PackageRepository
            // keys on ca.name = p.purl_name. BlobKey is left as the oci/{algo}/{hex} store key
            // rather than routed through BlobKeys.Proxy, which throws on a non-64-hex key.
            string? cacheArtifactId = await _cacheRecorder.RecordAccessAsync(
                new CacheAccess(
                    orgId, "oci", entry.Repository, entry.Digest, ManifestCacheFilename,
                    entry.Sha256Hex, entry.SizeBytes, entry.BlobKey, entry.UpstreamUrl,
                    // The manifest was pulled and digested on this request. The coordinate is the
                    // digest itself, so two orgs resolving one coordinate to different bytes is
                    // not expressible here — the binding is recorded for uniformity, not defence.
                    CacheAccessOrigin.FirstFetch),
                ct);

            if (cacheArtifactId is not null)
            {
                await _cacheArtifacts.UpdateGlobalFactsAsync(
                    cacheArtifactId,
                    purl: purl,
                    checksumSha1: null,
                    publishedAt: null,
                    deprecated: null,
                    hasInstallScript: false,
                    installScriptKind: null,
                    provenanceStatus: null,
                    provenanceSigner: null,
                    upstreamIntegrityValue: null,
                    upstreamIntegrityAlgorithm: null,
                    ct: ct);
            }

            // The manifest's license was stamped onto oci_blobs before this row existed; project it
            // onto the row now so every license reader sees it through the shared table.
            await _licenseRecorder.ProjectLicenseToCatalogAsync(orgId, entry.Digest, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(
                "{ExceptionType} cataloguing OCI version {Repository}@{Digest}; pull unaffected. BlobKey={BlobKey} TraceId={TraceId}",
                ex.GetType().Name, entry.Repository, entry.Digest, entry.BlobKey,
                System.Diagnostics.Activity.Current?.TraceId.ToString());
        }
    }

    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out", Justification = "Descriptive documentation comment, not commented-out code.")]
    private async Task<OciBlobFetchMetadata?> FetchAndCacheBlobAsync(
        string orgId,
        OciUpstreamRegistryOptions upstream,
        string repository,
        string digest,
        string blobKey,
        CancellationToken ct)
    {
        var client = _http.CreateClient("OciUpstream");
        string url = $"https://{upstream.Host}/v2/{repository}/blobs/{digest}";
        string logContext = $"OCI blob {digest} upstream {upstream.Host}";

        // Expected hex for post-download verification.
        string[] digestParts = digest.Split(':', DigestSplitParts);
        string expectedHex = digestParts.Length == DigestSplitParts ? digestParts[1].ToLowerInvariant() : "";

        // ResponseHeadersRead → don't buffer response in memory; stream body directly to blob store.
        using var resp = await SendUpstreamWithAuthRetryAsync(
            orgId, client, HttpMethod.Get, url, ["application/octet-stream"], upstream, repository, "pull", logContext, ct,
            completionOption: HttpCompletionOption.ResponseHeadersRead);
        if (resp is null)
        {
            return null;
        }

        string mediaType = resp.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";
        long bytesWritten;

        // Cheap fail-fast on a declared Content-Length before streaming a single byte, mirroring
        // every other ecosystem's upstream-fetch path (UpstreamClient.FetchAndStageCoreAsync).
        // OciDigestVerifyStream below still enforces the same cap for chunked transfers that
        // arrive with no Content-Length header at all.
        if (resp.Content.Headers.ContentLength > UpstreamClient.MaxUpstreamResponseBytes)
        {
            _logger.LogWarning(
                "OCI blob {Repository}/{Digest} from {Host} declared Content-Length {ContentLength} exceeding the {MaxBytes}-byte upstream cap; refusing.",
                repository, digest, upstream.Host, resp.Content.Headers.ContentLength, UpstreamClient.MaxUpstreamResponseBytes);
            return null;
        }

        // Verify-then-commit: stream upstream bytes into an ephemeral staging key so
        // the content-addressed blobKey is never written until the digest is confirmed.
        // A concurrent cache-first reader (FetchBlobAsync) checks blobKey directly;
        // because blobKey is only populated after a successful verification here, a
        // cache-first branch can only ever serve verified bytes.
        string stagingKey = BlobKeys.OciStaging(Guid.NewGuid().ToString("N"));

        try
        {
            await using var contentStream = await resp.Content.ReadAsStreamAsync(ct);
            await using var verifyStream = new OciDigestVerifyStream(contentStream, UpstreamClient.MaxUpstreamResponseBytes);

            await _blobs.Cache.PutAsync(stagingKey, verifyStream, ct);
            bytesWritten = verifyStream.BytesWritten;

            string computedDigest = verifyStream.ComputedDigest;
            if (!string.Equals(computedDigest, $"sha256:{expectedHex}", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning(
                    "OCI blob digest mismatch for {Repository}/{Digest}: expected sha256:{Expected}, computed {Computed}",
                    repository, digest, expectedHex, computedDigest);
                await _blobs.Cache.DeleteAsync(stagingKey, ct);
                return null;
            }
        }
        catch (UpstreamResponseTooLargeException)
        {
            // Delete-on-refuse: a coordinate-addressed staging entry left behind here would be a
            // permanent bypass of this cap for every future request that races the same digest.
            _logger.LogWarning(
                "OCI blob {Repository}/{Digest} from {Host} exceeded the {MaxBytes}-byte upstream cap mid-stream; refusing.",
                repository, digest, upstream.Host, UpstreamClient.MaxUpstreamResponseBytes);
            await _blobs.Cache.DeleteAsync(stagingKey, ct);
            return null;
        }

        // Digest verified — promote staging entry to the content-addressed key, then
        // clean up the staging slot so it never persists beyond this request.
        var stagedStream = await _blobs.Cache.GetAsync(stagingKey, ct);
        if (stagedStream is not null)
        {
            await _blobs.Cache.PutAsync(blobKey, stagedStream, ct);
        }

        await _blobs.Cache.DeleteAsync(stagingKey, ct);

        // Persist DB row for this org.
        bool inserted = await EnsureBlobDbRowAsync(orgId, digest, mediaType, bytesWritten, blobKey, ct);
        if (inserted)
        {
            // First insert of this blob for the org: reverse-lookup any manifest awaiting its
            // config license. Runs under the same single-flight token as the surrounding fetch.
            await _licenseRecorder.RecordConfigBlobArrivalAsync(orgId, digest, blobKey, ct);
        }

        _logger.LogInformation(
            "OCI blob proxy {Repository}/{Digest} ({Bytes} B) from {Host}",
            repository, digest, bytesWritten, upstream.Host);

        // Return only metadata — each waiter opens its own stream independently in
        // FetchBlobAsync, so the single shared result never carries a shared stream.
        return new OciBlobFetchMetadata(blobKey, mediaType);
    }

    // Decides whether a bare hit on the shared content-addressed blob store may be served to
    // orgId. The store is content-addressed with no org segment, so in the default
    // single-store deployment (cache == registry) one tenant's bytes — private uploads AND
    // proxy-cached layers pulled through an authenticated upstream — resolve under the same key
    // as anyone else's; a raw store hit is never proof of authorization on its own. Entitlement
    // holds only when the caller's own org already has an oci_blobs row for the digest: its own
    // upload, or a proxy fetch it already performed (and so already authenticated) itself.
    //
    // Deliberately no cross-org exception for proxy-origin rows: a repository name is
    // caller-supplied and an upstream with an empty prefix matches every repository, so "the
    // caller has some configured upstream" proves nothing about whether that upstream's
    // credentials can actually reach this digest — it lets a caller who guesses a digest (they
    // leak routinely via SBOMs, CI logs, pinned references) read another org's private layer
    // without ever presenting that org's upstream credentials. A non-owning org falls through to
    // its own real, org-scoped upstream fetch below, which re-authenticates and re-verifies the
    // digest — the only trustworthy proof the caller is entitled to the bytes. The single-flight
    // dedup on that path is keyed on (org, blob key), so a caller racing another org's in-flight
    // pull of the same digest still makes its own authenticated request rather than awaiting,
    // and inheriting the result of, a fetch made with another tenant's credentials.
    private async Task<bool> CanServeSharedBlobAsync(
        string orgId, string digest, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (digest, org_id) PK is tenant-scoped — the same predicate the blob HEAD path
        // (TryGetCachedBlobMetadataByDigestAsync) answers existence with, so GET and HEAD cannot
        // disagree about which org may see a digest.
        int owned = await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(1) FROM oci_blobs WHERE digest = @digest AND org_id = @orgId",
            new { digest, orgId });
        return owned > 0;
    }

    // Returns true when a NEW row was inserted (ON CONFLICT DO NOTHING → 0 rows on an existing
    // row). Callers use the flag to run the config-blob license reverse-lookup ONLY on a genuine
    // first insert, so a warm blob GET — which runs this on every request — pays nothing extra.
    private async Task<bool> EnsureBlobDbRowAsync(
        string orgId, string digest, string mediaType, long sizeBytes, string blobKey, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: (digest, org_id) PK is tenant-scoped.
        int rows = await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin, cached_at)
            VALUES (@digest, @orgId, @mediaType, @sizeBytes, @blobKey, 'proxy', @now)
            ON CONFLICT(digest, org_id) DO NOTHING
            """,
            new { digest, orgId, mediaType, sizeBytes, blobKey, now = UtcTimestamp.Now(_time) });
        return rows > 0;
    }

    // In-flight identity for a blob fetch. The org is part of the identity because the fetch it
    // guards runs with one org's upstream and credentials, and its result may only be handed to
    // callers of that org.
    private readonly record struct OciBlobInflightKey(string OrgId, string BlobKey);
}

// ── Result types ────────────────────────────────────────────────

/// <summary>
/// Thrown when a configured OCI upstream answered but failed to serve — a 429 rate limit or a
/// 5xx — as opposed to a definitive 404/401/403 (a miss) or a transport-layer failure (an
/// <see cref="HttpRequestException"/> etc.). The controller treats it exactly like a transport
/// failure: 502 upstream-unreachable, or a stale serve within the tag grace window. It must
/// never surface as MANIFEST_UNKNOWN/BLOB_UNKNOWN — docker reacts to a 404 by treating the
/// image as nonexistent, which turns a Docker Hub rate limit into "the image does not exist".
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S3925:\"ISerializable\" should be implemented correctly",
    Justification = "Not binary-serialized across AppDomain boundaries.")]
public sealed class OciUpstreamUnavailableException : Exception
{
    public OciUpstreamUnavailableException(System.Net.HttpStatusCode? status, string context)
        : base($"OCI upstream unavailable ({(status is { } s ? ((int)s).ToString() : "no status")}): {context}")
    {
        UpstreamStatus = status;
    }

    /// <summary>The upstream's HTTP status, when the failure was an answered error status.</summary>
    public System.Net.HttpStatusCode? UpstreamStatus { get; }
}

/// <summary>Resolved manifest with its content stream, media type, digest, and byte count.</summary>
public sealed record OciManifestResult(Stream Content, string MediaType, string Digest, long SizeBytes);

/// <summary>
/// Manifest header metadata returned by a HEAD-only upstream fetch: digest, media type, and
/// byte count. No content stream is opened — used by the manifest HEAD handler on a cache-miss
/// to populate response headers without downloading the manifest body.
/// </summary>
public sealed record OciManifestMetadata(string Digest, string MediaType, long SizeBytes);

/// <summary>Resolved blob with its content stream and media type.</summary>
public sealed record OciBlobResult(Stream Content, string MediaType);

/// <summary>
/// Blob header metadata returned by a HEAD-only upstream fetch: media type only.
/// The digest and size are already known from the request (digest is the request parameter;
/// size is not needed for OCI blob HEAD — <c>Content-Length</c> is set from the DB row or
/// omitted on a cache-miss HEAD where the blob has not yet been fetched).
/// </summary>
public sealed record OciBlobMetadata(string MediaType);

/// <summary>
/// Metadata returned by the single-flight blob fetch work item (<c>_blobInflight</c>).
/// Carries only the content-addressed cache key and media type — NOT an open stream.
/// Each concurrent waiter opens its own stream from the cache store after the Lazy resolves,
/// preventing use-after-dispose when multiple callers race on the same digest.
/// </summary>
internal sealed record OciBlobFetchMetadata(string BlobKey, string MediaType);

// ── Digest-verifying pass-through stream ─────────────────────────────────────

/// <summary>
/// A read-only pass-through stream that computes a running SHA-256 digest over all bytes read.
/// Used by <see cref="OciUpstreamResolver"/> to verify OCI blob integrity while streaming to
/// the blob store — avoids buffering large layer blobs in memory.
/// </summary>
internal sealed class OciDigestVerifyStream : Stream
{
    private readonly Stream _inner;
    private readonly IncrementalHash _hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private readonly long _maxBytes;

    /// <param name="inner">The upstream response body to hash and pass through.</param>
    /// <param name="maxBytes">
    /// Hard ceiling on total bytes read. Every other ecosystem's binary download path caps the
    /// upstream body (<see cref="HashingFileStream"/> for the hash-and-stage MISS path); this is
    /// OCI's equivalent for the blob proxy path, which streams straight into the blob store
    /// without ever buffering the whole body. Catches a Content-Length-less (chunked) response
    /// that a fixed pre-check on the header alone would miss.
    /// </param>
    public OciDigestVerifyStream(Stream inner, long maxBytes)
    {
        _inner = inner;
        _maxBytes = maxBytes;
    }

    public long BytesWritten { get; private set; }

    /// <summary>Returns <c>sha256:{lowercaseHex}</c> of all bytes read so far.</summary>
    public string ComputedDigest
        => "sha256:" + Convert.ToHexString(_hasher.GetCurrentHash()).ToLowerInvariant();

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    private void CheckCap()
    {
        if (BytesWritten > _maxBytes)
        {
            throw new UpstreamResponseTooLargeException("(oci-blob)", _maxBytes);
        }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        int read = _inner.Read(buffer, offset, count);
        if (read > 0)
        {
            _hasher.AppendData(buffer, offset, read);
            BytesWritten += read;
            CheckCap();
        }
        return read;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        int read = await _inner.ReadAsync(buffer.AsMemory(offset, count), cancellationToken);
        if (read > 0)
        {
            _hasher.AppendData(buffer, offset, read);
            BytesWritten += read;
            CheckCap();
        }
        return read;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        int read = await _inner.ReadAsync(buffer, cancellationToken);
        if (read > 0)
        {
            _hasher.AppendData(buffer.Span[..read]);
            BytesWritten += read;
            CheckCap();
        }
        return read;
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _inner.Dispose();
            _hasher.Dispose();
        }
        base.Dispose(disposing);
    }
}
