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
public sealed partial class OciUpstreamResolver
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
