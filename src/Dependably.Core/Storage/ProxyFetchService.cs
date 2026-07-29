using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Protocol;
using Dependably.Protocol.Provenance;

namespace Dependably.Storage;

/// <summary>
/// Orchestrates the post-fetch half of the proxy cache-miss flow shared by the three
/// ecosystem controllers (PyPI, npm, NuGet). Each ecosystem still owns its own upstream
/// URL shape and the per-format extractors; once those produce a verified, blob-cached
/// artefact (described by a <see cref="BlobHandle"/>), every controller does the same dance:
///
/// <list type="number">
///   <item>Trust-boundary checksum re-verify against an upstream-supplied integrity hash
///         (the SHA-256 itself is already known — <see cref="UpstreamClient"/> computed it
///         inline during hash-and-stage).</item>
///   <item>First-fetch deprecation gate (<see cref="BlockGateService.EvaluateFirstFetchDeprecationAsync"/>):
///         under <c>block_new</c>/<c>block_all</c> a deprecated version is refused here, before
///         the version row is recorded, so it never enters the cache catalogue.</item>
///   <item>Best-effort <see cref="CacheAccessRecorder"/> tick (per-tenant first/last access).</item>
///   <item>Record the version row via <see cref="ProxyVersionRecorder"/> (handles the
///         unique-constraint race when two concurrent first-fetches collide).</item>
///   <item>Synchronous OSV scan so the block gate can fire on the very first fetch.</item>
///   <item><see cref="BlockGateService"/> evaluate; on Blocked the caller returns 403.</item>
/// </list>
///
/// This service is the single home for that sequence. Each controller's proxy method
/// shrinks to: build the upstream URL → fetch+stage → call <see cref="RecordAndScanAsync"/>.
/// </summary>
public sealed class ProxyFetchService
{
    private readonly CacheAccessRecorder _cacheRecorder;
    private readonly ProxyVersionRecorder _proxyVersions;
    private readonly CacheArtifactRepository _cacheArtifacts;
    private readonly TenantArtifactAccessRepository _tenantAccess;
    private readonly VulnerabilityScanService _scanner;
    private readonly BlockGateService _blockGate;
    private readonly AuditRepository _audit;
    private readonly TimeProvider _time;
    private readonly Infrastructure.SourcePinRepository _sourcePins;
    private readonly Security.WeakAlgorithmAcceptance _weakAlgorithms;

    // DI constructor: 10 dependencies are required by the post-fetch pipeline stages (access
    // recording, version recording, artifact repository, tenant access, scan, block gate,
    // audit, time, source-pin enforcement, and the weak-algorithm acceptance posture). No
    // cleaner grouping exists — each dependency serves a distinct pipeline step and splitting
    // the class would scatter the shared sequencing logic.
#pragma warning disable S107 // DI constructor — all 10 dependencies are distinct pipeline stages
    public ProxyFetchService(
        CacheAccessRecorder cacheRecorder,
        ProxyVersionRecorder proxyVersions,
        CacheArtifactRepository cacheArtifacts,
        TenantArtifactAccessRepository tenantAccess,
        VulnerabilityScanService scanner,
        BlockGateService blockGate,
        AuditRepository audit,
        TimeProvider time,
        Infrastructure.SourcePinRepository sourcePins,
        Security.WeakAlgorithmAcceptance? weakAlgorithms = null)
#pragma warning restore S107
    {
        _cacheRecorder = cacheRecorder;
        _proxyVersions = proxyVersions;
        _cacheArtifacts = cacheArtifacts;
        _tenantAccess = tenantAccess;
        _scanner = scanner;
        _blockGate = blockGate;
        _audit = audit;
        _time = time;
        _sourcePins = sourcePins;

        // Absent the DI singleton the safe posture applies: every weak-algorithm opt-in off.
        _weakAlgorithms = weakAlgorithms ?? Security.WeakAlgorithmAcceptance.RefuseAll;
    }

    /// <summary>
    /// Runs the post-fetch pipeline: optional fail-fast checksum verify, cache-access
    /// tick, record version row, scan, evaluate block gate. The blob has already been
    /// written by <see cref="UpstreamClient.FetchAndStageAsync"/> and the
    /// SHA-256 was computed inline — both are passed through on <see cref="BlobHandle"/>.
    /// </summary>
    public async Task<ProxyFetchResult> RecordAndScanAsync(
        ProxyFetchRequest request, CancellationToken ct = default)
    {
        string sha256 = request.Blob.Sha256Hex;
        string blobKey = request.Blob.BlobKey;
        long sizeBytes = request.Blob.SizeBytes;

        // Source pin: bind the name to its first-serving upstream and refuse a later serve from a
        // different upstream (dependency-confusion guard). Runs before any version row is written
        // so a shadowed name is never adopted into the cache catalogue.
        var pinBlock = await EvaluateSourcePinAsync(request, sha256, blobKey, ct);
        if (pinBlock is not null)
        {
            return pinBlock;
        }

        await VerifyChecksumOrThrowAsync(request, sha256, ct);
        var earlyBlock = await EvaluateFirstFetchGatesAsync(request, sha256, blobKey, ct);
        if (earlyBlock is not null)
        {
            return earlyBlock;
        }

        string? cacheArtifactId = await RecordCacheAccessAsync(request, sha256, blobKey, sizeBytes, ct);

        // No cache-plane row means the artefact cannot be scanned or gated: the OSV lookup and every
        // gate below run against that row. So the fetch is refused rather than served ungated. The
        // bytes are staged in the blob store and have not reached the client — refusing here costs a
        // retry, and serving would cost the guarantee the registry exists to provide.
        //
        // Falling back to a package_versions row is not an option: package_versions is the hosted
        // plane, and the vulnerability sweep and retention both read it as origin = 'uploaded'. An
        // artefact standing in there is never scanned, never collected, and its blob never reclaimed,
        // while the licence readers still see it — it looks catalogued and is not gateable.
        string catalogueId = cacheArtifactId
            ?? throw new ProxyCatalogueUnavailableException(
                request.Ecosystem, request.PurlName, request.Version);

        await _proxyVersions.RecordAsync(
            new ProxyVersionRequest(
                OrgId: request.OrgId, Ecosystem: request.Ecosystem,
                PackageName: request.PackageName, PurlName: request.PurlName,
                Version: request.Version, Purl: request.Purl,
                Sha256: sha256, File: request.File, Blob: request.Blob,
                UserId: request.UserId, ActorKind: request.ActorKind, SourceIp: request.SourceIp,
                PublishedAt: request.PublishedAt,
                Sha1Hex: request.Sha1Hex,
                UpstreamIntegrityValue: request.UpstreamIntegrityValue,
                UpstreamIntegrityAlgorithm: request.UpstreamIntegrityAlgorithm,
                Deprecated: request.Deprecated),
            request.ExtractLicenses, request.ExtractManifest, catalogueId, ct);

        return await ScanAndGateGlobalPlaneAsync(request, sha256, blobKey, catalogueId, ct);
    }

    // Fail-fast verification against the upstream-supplied integrity hash (PyPI #sha256=,
    // npm dist.integrity / dist.shasum, NuGet packageHash). The SHA-256 was already verified
    // inline by UpstreamClient.FetchAndStageAsync; for other algorithms we stream the cached
    // blob through ChecksumVerifier. On mismatch audits a checksum_failure event and throws
    // ChecksumException → caller returns 502 Bad Gateway.
    //
    // This is the cache-admission decision, so it is also where a weak digest is refused the
    // status of "verified": a SHA-1 spec (an npm packument carrying only dist.shasum) counts as
    // a verification only under the Npm:AcceptSha1Shasum opt-in. Otherwise the artefact is
    // admitted unverified — the same footing as an upstream that publishes no digest at all —
    // rather than the registry recording a chosen-prefix-collision-broken digest as an
    // integrity guarantee. The spec is honoured for every other algorithm.
    private async Task VerifyChecksumOrThrowAsync(
        ProxyFetchRequest request, string sha256, CancellationToken ct)
    {
        if (request.UpstreamChecksum is not { } spec)
        {
            return;
        }

        if (spec.Algorithm == ChecksumAlgorithm.Sha1)
        {
            if (!_weakAlgorithms.NpmSha1Shasum)
            {
                _weakAlgorithms.NoteNpmSha1Skipped();
                return;
            }

            _weakAlgorithms.NoteNpmSha1Accepted();
        }

        if (await VerifyChecksumAsync(spec, sha256, request, ct))
        {
            return;
        }

        DependablyMeter.UpstreamChecksumFailures.Add(1,
            new KeyValuePair<string, object?>("ecosystem", request.Ecosystem));
        await _audit.LogAsync(
            "checksum_failure",
            orgId: request.OrgId,
            ecosystem: request.Ecosystem,
            purl: request.Purl,
            detail: $"{{\"version\":\"{request.Version}\",\"file\":\"{request.File}\",\"algorithm\":\"{spec.Algorithm}\",\"expected\":\"{spec.ExpectedValue}\",\"actual_sha256\":\"{sha256}\"}}",
            ct: ct);
        throw new ChecksumException(
            $"Upstream-supplied {spec.Algorithm} hash for {request.Purl} did not match the downloaded bytes.");
    }

    // Source-pin gate. Binds the (org, ecosystem, name) to the upstream host that first serves it
    // and refuses a later serve from a different upstream host — the non-OCI dependency-confusion
    // guard. No-ops when pinning is disabled or the serving upstream is unknown (fail-open on
    // missing routing information rather than blocking a legitimate fetch).
    private async Task<ProxyFetchResult?> EvaluateSourcePinAsync(
        ProxyFetchRequest request, string sha256, string blobKey, CancellationToken ct)
    {
        if (!_sourcePins.Enabled)
        {
            return null;
        }

        string? servingHost = ExtractHost(request.UpstreamUrl);
        if (servingHost is null)
        {
            return null;
        }

        string pinnedHost = await _sourcePins.PinIfAbsentAsync(
            request.OrgId, request.Ecosystem, request.PurlName, servingHost, ct);

        if (string.Equals(pinnedHost, servingHost, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        // The name is pinned to a different upstream than the one that just answered. Refuse the
        // serve so a squatted public name cannot shadow a private-upstream name on miss.
        await _audit.LogAsync(
            "upstream_source_pin_violation",
            orgId: request.OrgId,
            ecosystem: request.Ecosystem,
            purl: request.Purl,
            detail: $"{{\"name\":\"{request.PurlName}\",\"pinned_host\":\"{pinnedHost}\",\"serving_host\":\"{servingHost}\"}}",
            ct: ct);

        return new ProxyFetchResult(BlockDecision.Blocked, sha256, blobKey);
    }

    // Returns the scheme+authority (e.g. https://registry.npmjs.org) of an absolute URL, or null
    // when the URL is absent or unparseable.
    private static string? ExtractHost(string? url) =>
        !string.IsNullOrEmpty(url) && Uri.TryCreate(url, UriKind.Absolute, out var uri)
            ? uri.GetLeftPart(UriPartial.Authority)
            : null;

    // Runs the pre-record gates (deprecation + provenance) that must fire BEFORE the version row
    // is written. A blocked result means the version is never adopted into the cache catalogue.
    // Returns a blocked ProxyFetchResult when a gate fires, null when all gates pass.
    private async Task<ProxyFetchResult?> EvaluateFirstFetchGatesAsync(
        ProxyFetchRequest request, string sha256, string blobKey, CancellationToken ct)
    {
        // First-fetch deprecation gate. Runs BEFORE the version row is recorded so a deprecated
        // version is never adopted into the cache catalogue under block_new / block_all: with no
        // version row, the controllers' cache-hit lookup misses and every subsequent request
        // re-enters this fetch path and re-blocks. block_new vs block_all is resolved here — both
        // deny on the first fetch; only block_all additionally denies cached versions, which is
        // handled later by EvaluateAsync on the serve path.
        if (request.Deprecated is not null)
        {
            var firstFetch = await _blockGate.EvaluateFirstFetchDeprecationAsync(
                BlockGateRequest.ForFirstFetchDeprecation(
                    request.OrgId, request.Ecosystem, request.Purl,
                    request.UserId, request.ActorKind, request.MaxOsvScoreTolerance, request.SourceIp,
                    request.Deprecated, request.BlockDeprecatedMode), ct);
            if (firstFetch == BlockDecision.Blocked)
            {
                return new ProxyFetchResult(BlockDecision.Blocked, sha256, blobKey);
            }
        }

        // First-fetch provenance gate. Runs BEFORE the version row is recorded so a version that
        // fails signature verification under a block policy is never adopted into the cache
        // catalogue (fail closed). The provenance result was computed by the ecosystem handler;
        // warn/off/NotApplicable proceed and the status is persisted on the recorded row.
        //
        // A 'block' policy whose trust-anchor set is empty produces NotApplicable for every
        // artifact — the ecosystem handlers short-circuit verification when nothing can verify —
        // so the unbacked-enforcement check is what keeps that from reading as a pass.
        if (request.VerifyProvenanceMode == "block")
        {
            string? status =
                request.ProvenanceStatus is ProvenanceStatuses.Failed or ProvenanceStatuses.Unsigned
                    ? request.ProvenanceStatus
                    : await _blockGate.IsProvenanceEnforcementUnbackedAsync(
                        request.OrgId, request.Ecosystem, request.VerifyProvenanceMode, ct)
                        ? ProvenanceStatuses.Unverifiable
                        : null;

            if (status is not null)
            {
                await _blockGate.RecordProvenanceBlockAsync(
                    BlockGateRequest.ForFirstFetchProvenance(
                        request.OrgId, request.Ecosystem, request.Purl,
                        request.UserId, request.ActorKind, request.MaxOsvScoreTolerance, request.SourceIp,
                        status, request.VerifyProvenanceMode), ct);
                return new ProxyFetchResult(BlockDecision.Blocked, sha256, blobKey);
            }
        }

        return null;
    }

    // Records access into cache_artifact + tenant_artifact_access (best-effort: a recorder
    // failure must not fail the proxy fetch). Returns the cache_artifact id when the global
    // plane path is active, null when the caller passed no CacheAccess record.
    //
    // When PreRecordedCacheArtifactId is set, the cache-access recording was already done by
    // the caller (PyPI records it once in FetchAndCacheUpstreamAsync to cover both hit and miss
    // paths). The id is reused directly; UpsertStateAsync still fires to count this download.
    private async Task<string?> RecordCacheAccessAsync(
        ProxyFetchRequest request, string sha256, string blobKey, long sizeBytes, CancellationToken ct)
    {
        if (request.PreRecordedCacheArtifactId is { } preRecordedId)
        {
            // Cache-access was already recorded by the caller; tick the per-tenant download
            // count without writing a second cache_artifact row.
            await _tenantAccess.UpsertStateAsync(request.OrgId, preRecordedId, _time.GetUtcNow(), ct);
            return preRecordedId;
        }

        if (request.CacheAccess is not { } access)
        {
            return null;
        }

        // Name is overridden with request.PurlName (the canonical PURL name) so that
        // cache_artifact.name always equals packages.purl_name — the cross-plane version-count
        // and vuln-count joins depend on this equality. A caller-supplied CacheAccess.Name may
        // carry a raw, non-normalized form (e.g. mixed-case) that would silently break the join.
        string? cacheArtifactId = await _cacheRecorder.RecordAccessAsync(
            access with { Name = request.PurlName, Sha256 = sha256, BlobKey = blobKey, SizeBytes = sizeBytes }, ct);

        // Per-tenant download state on the global plane. Runs before RecordAsync so the
        // download_count is counted even when RecordAsync takes the global-plane path.
        if (cacheArtifactId is not null)
        {
            await _tenantAccess.UpsertStateAsync(request.OrgId, cacheArtifactId, _time.GetUtcNow(), ct);
        }

        return cacheArtifactId;
    }

    // Global-plane scan and block-gate path: cacheArtifactId is set, RecordAsync returned null.
    // Provenance facts are written to cache_artifact; the scan and block-gate use
    // the cache_artifact id rather than a version id.
    //
    // The facts come from GetServeFactsByIdAsync — the same per-tenant projection the cache-HIT
    // serve path reads — and the request is built by BlockGateRequest.ForProxyFirstFetch, which
    // lives next to ForProxyCacheFacts. Both halves are deliberate: reading the same row means the
    // first requester cannot be shown something a later one would be refused, and building both
    // requests in one file means a gate signal added later reaches both paths at once instead of
    // waiting for someone to notice the second call site.
    private async Task<ProxyFetchResult> ScanAndGateGlobalPlaneAsync(
        ProxyFetchRequest request, string sha256, string blobKey, string cacheArtifactId, CancellationToken ct)
    {
        if (request.ProvenanceStatus is not null)
        {
            await _cacheArtifacts.UpdateGlobalFactsAsync(
                cacheArtifactId,
                purl: null,
                checksumSha1: null,
                publishedAt: null,
                deprecated: null,
                hasInstallScript: false,
                installScriptKind: null,
                provenanceStatus: request.ProvenanceStatus,
                provenanceSigner: request.ProvenanceSigner,
                upstreamIntegrityValue: null,
                upstreamIntegrityAlgorithm: null,
                ct: ct);
        }

        await _scanner.ScanCacheArtifactAsync(request.Purl, cacheArtifactId,
            request.Ecosystem, request.PurlName, ct);

        var caFacts = await _cacheArtifacts.GetServeFactsByIdAsync(request.OrgId, cacheArtifactId, ct);
        if (caFacts is null)
        {
            // The row was written a few statements ago and is already unreadable through the serve
            // projection. Whatever the cause, this request cannot be gated on the facts a later
            // request would be gated on, and the bytes have not reached the client yet — so refuse
            // rather than serve ungated, the same posture the missing-catalogue-row branch takes.
            return new ProxyFetchResult(BlockDecision.Blocked, sha256, blobKey);
        }

        var caDecision = await _blockGate.EvaluateAsync(
            BlockGateRequest.ForProxyFirstFetch(
                request.OrgId, request.Ecosystem, caFacts,
                request.UserId, request.ActorKind, request.SourceIp,
                request.MaxOsvScoreTolerance,
                request.MinReleaseAgeHours,
                request.BlockDeprecatedMode,
                request.BlockMaliciousMode,
                request.BlockKevMode,
                request.MaxEpssTolerance,
                request.BlockInstallScriptsMode,
                request.VerifyProvenanceMode,
                request.BlockRevokedMode,
                request.LicenseEnforcementMode), ct);

        return new ProxyFetchResult(caDecision, sha256, blobKey);
    }

    /// <summary>
    /// Stream the cached blob through <see cref="ChecksumVerifier.VerifyAsync"/> for
    /// non-SHA-256 specs. SHA-256 short-circuits against the already-known hex from
    /// <see cref="BlobHandle.Sha256Hex"/>.
    /// </summary>
    private static async Task<bool> VerifyChecksumAsync(
        ChecksumSpec spec, string sha256Hex, ProxyFetchRequest request, CancellationToken ct)
    {
        if (spec.Algorithm == ChecksumAlgorithm.Sha256)
        {
            return string.Equals(sha256Hex, spec.ExpectedValue.ToLowerInvariant(), StringComparison.Ordinal);
        }

        // SHA-1 (npm shasum) and SHA-512 (npm SRI / NuGet packageHash) — stream the
        // cached blob through the verifier rather than buffering. The stream comes
        // from BlobHandle, so the cost is one extra GET on remote backends.
        await using var stream = await request.Blob.OpenAsync(ct);
        return await ChecksumVerifier.VerifyAsync(stream, spec, ct);
    }
}

/// <summary>
/// Reference to a blob that's already been written to <see cref="IBlobStore"/> and whose
/// SHA-256 is known. Replaces the byte[]-shaped <c>Bytes</c>/<c>Sha256Hex</c>/<c>SizeBytes</c>
/// triple that ProxyFetchService still threaded through. <see cref="OpenAsync"/>
/// lazily opens a fresh blob-store stream when the consumer actually needs the bytes
/// (license extraction, non-SHA-256 checksum re-verify); cache HITs that only need to
/// stream the response body never call it.
/// </summary>
public sealed record BlobHandle(
    string BlobKey,
    string Sha256Hex,
    long SizeBytes,
    Func<CancellationToken, Task<Stream>> OpenAsync);

/// <summary>Inputs to <see cref="ProxyFetchService.RecordAndScanAsync"/>.</summary>
public sealed record ProxyFetchRequest(
    string OrgId,
    string Ecosystem,
    string PackageName,
    string PurlName,
    string Version,
    string Purl,
    string File,
    BlobHandle Blob,
    /// <summary>
    /// Per-ecosystem licence extractor. Receives a fresh, position-0 stream over the cached
    /// blob; the extractor takes ownership and disposes it. Failure-tolerant: any throw
    /// inside the extractor is swallowed by <see cref="Infrastructure.ProxyVersionRecorder"/>
    /// and the licence row is silently skipped — the first-fetch artefact still serves.
    /// </summary>
    Func<Stream, LicenseExtractor.ExtractedMetadata>? ExtractLicenses,
    string? UserId,
    /// <summary>
    /// Discriminator persisted alongside <see cref="UserId"/> in <c>activity.actor_kind</c>:
    /// <see cref="Infrastructure.ActorKinds.User"/> or <see cref="Infrastructure.ActorKinds.Service"/>
    /// (or NULL for truly-anonymous fetches). Without this, service-token first fetches show
    /// up as "anonymous" in the audit UI — see <see cref="Infrastructure.ProxyVersionRequest.ActorKind"/>.
    /// </summary>
    string? ActorKind,
    string? SourceIp,
    double MaxOsvScoreTolerance,
    /// <summary>
    /// Optional cache-access record. Pass null to skip recording. The recorder updates
    /// Sha256/BlobKey/SizeBytes from the freshly-computed values regardless of what the
    /// caller seeded them with.
    /// </summary>
    CacheAccess? CacheAccess,
    /// <summary>
    /// Pre-recorded cache_artifact id for ecosystems that record cache-access before calling
    /// <see cref="RecordAndScanAsync"/> (PyPI covers both hit and miss paths in
    /// FetchAndCacheUpstreamAsync). When set, <see cref="RecordCacheAccessAsync"/> skips the
    /// second <see cref="CacheAccessRecorder.RecordAccessAsync"/> call to avoid a duplicate
    /// row, and instead reuses this id for the global-plane dispatch and download-count tick.
    /// Mutually exclusive with <see cref="CacheAccess"/> (set one or the other, never both).
    /// </summary>
    string? PreRecordedCacheArtifactId = null,
    /// <summary>
    /// Tenant's <c>org_settings.min_release_age_hours</c> at the time of the fetch. NULL = no
    /// policy. Plumbed through to <see cref="BlockGateService"/>, where a positive value blocks
    /// versions whose upstream publish timestamp is younger than the hold window. Fail-open
    /// when <see cref="PublishedAt"/> is null.
    /// </summary>
    int? MinReleaseAgeHours = null,
    /// <summary>
    /// Upstream first-publish timestamp the caller extracted from registry metadata. Null
    /// when the caller couldn't reach or parse the metadata — captured fail-soft.
    /// </summary>
    DateTimeOffset? PublishedAt = null,
    /// <summary>
    /// Upstream-supplied integrity hash for fail-fast verification of the downloaded bytes.
    /// PyPI sets a SHA-256 from the simple-index fragment or the JSON API <c>digests</c>;
    /// npm sets a SHA-512 SRI from <c>dist.integrity</c> (or hex SHA-1 from <c>dist.shasum</c>);
    /// NuGet sets a SHA-512 from <c>packageHash</c>. Null when the metadata couldn't be parsed
    /// or didn't carry an integrity field — the request proceeds without verification, same
    /// fail-soft semantics as <see cref="PublishedAt"/>. On mismatch <see cref="ProxyFetchService"/>
    /// audits a <c>checksum_failure</c> event and throws <see cref="ChecksumException"/>.
    /// </summary>
    ChecksumSpec? UpstreamChecksum = null,
    /// <summary>
    /// Hex SHA-1 of the artefact bytes, captured by the npm controller from the packument's
    /// <c>dist.shasum</c> for persistence so the packument we re-emit later carries a correct
    /// SHA-1. Stored in <c>package_versions.checksum_sha1</c>. Null for non-npm ecosystems and
    /// when the upstream packument didn't include the field.
    /// </summary>
    string? Sha1Hex = null,
    /// <summary>
    /// Upstream-published integrity hash, stored verbatim in upstream's native encoding so
    /// the version detail UI can show "this is what npmjs.com / nuget.org / pypi.org claims"
    /// alongside our own SHA-256. Paired with <see cref="UpstreamIntegrityAlgorithm"/>.
    /// Null when the metadata couldn't be parsed or didn't carry an integrity field.
    /// </summary>
    string? UpstreamIntegrityValue = null,
    /// <summary>
    /// Tag describing <see cref="UpstreamIntegrityValue"/>: <c>'sha256'</c> (hex),
    /// <c>'sha512-sri'</c> (npm SRI form), or <c>'sha512-b64'</c> (NuGet packageHash).
    /// </summary>
    string? UpstreamIntegrityAlgorithm = null,
    /// <summary>
    /// Upstream deprecation message captured from registry metadata: npm
    /// <c>versions[v].deprecated</c> free-text; PyPI <c>yanked_reason</c> (or
    /// <c>"Yanked"</c> when reason is empty) when <c>yanked: true</c>; NuGet
    /// <c>"Unlisted upstream"</c> when the registration leaf reports
    /// <c>listed: false</c>. Persisted into <c>package_versions.deprecated</c> so
    /// the existing UI badge surfaces it. Null when upstream didn't flag the version.
    /// </summary>
    string? Deprecated = null,
    /// <summary>Tenant policy from <c>org_settings.block_deprecated</c>: 'off' | 'warn' | 'block'.</summary>
    string? BlockDeprecatedMode = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.block_malicious</c>: 'off' | 'warn' | 'block'.
    /// Evaluated by <see cref="Protocol.BlockGateService"/> right after the synchronous
    /// first-fetch OSV scan, so a version with a malicious-package advisory is denied on
    /// the very first fetch.
    /// </summary>
    string? BlockMaliciousMode = null,
    /// <summary>Tenant policy from <c>org_settings.block_kev</c>: 'off' | 'warn' | 'block'.</summary>
    string? BlockKevMode = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.block_revoked</c>: 'off' | 'warn' | 'block'. Only 'block'
    /// denies a version withdrawn upstream. This reaches the first-fetch gate for the same reason
    /// every other mode does: the fetch path is re-entered whenever the cached blob has been
    /// evicted, so an artifact that has since been revoked upstream would otherwise be re-served to
    /// the very requester a 'block' policy exists to protect.
    /// </summary>
    string? BlockRevokedMode = null,
    /// <summary>Tenant ceiling from <c>org_settings.max_epss_tolerance</c> (0.0–1.0); null = off.</summary>
    double? MaxEpssTolerance = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.block_install_scripts</c>: 'off' | 'warn' | 'block'.
    /// Evaluated on the serve path after the install-script signal is persisted at first-fetch,
    /// so a version that ships an install hook is denied once detection has run.
    /// </summary>
    string? BlockInstallScriptsMode = null,
    /// <summary>
    /// Provenance/signature-verification outcome the ecosystem handler computed for this version
    /// before staging: <c>'verified'</c> / <c>'failed'</c> / <c>'unsigned'</c>, or NULL when
    /// verification was not applicable (policy off, no verifier, no pinned keys). Persisted on the
    /// recorded row and fed to the provenance block-gate arm. Under a 'block' policy a
    /// Failed/Unsigned status is refused before the version is recorded (fail closed).
    /// </summary>
    string? ProvenanceStatus = null,
    /// <summary>Verifying trust-anchor keyid when <see cref="ProvenanceStatus"/> is verified; NULL otherwise.</summary>
    string? ProvenanceSigner = null,
    /// <summary>Tenant policy from <c>org_settings.verify_npm_signatures</c>: 'off' | 'warn' | 'block'.</summary>
    string? VerifyProvenanceMode = null,
    /// <summary>
    /// The upstream URL this artefact was fetched from. The scheme+authority is bound to the
    /// package name as a source pin so a later serve of the same name from a different upstream
    /// is refused (dependency-confusion guard). Null skips pinning for this fetch.
    /// </summary>
    string? UpstreamUrl = null,
    /// <summary>
    /// Tenant policy from <c>org_settings.license_enforcement_mode</c>: 'off' | 'warn' | 'block'.
    /// Threaded through to <see cref="Protocol.BlockGateService"/> so a blocklisted-license artifact
    /// is refused on its FIRST fetch (the proxy first-fetch path builds the block-gate request
    /// field-by-field here rather than via the factories, so it must carry this explicitly). Only
    /// 'block' denies; 'warn'/'off'/null keep the license signal advisory.
    /// </summary>
    string? LicenseEnforcementMode = null,
    /// <summary>
    /// Optional npm install-manifest extractor. Receives a fresh, position-0 stream over the
    /// cached tarball; unlike <see cref="ExtractLicenses"/>, the extractor does NOT own the
    /// stream — <see cref="Infrastructure.ProxyVersionRecorder"/> opens and disposes it (<see
    /// cref="Protocol.NpmTarballValidator.Validate(Stream)"/> deliberately leaves the source
    /// stream open for the caller to dispose, matching the same validator's use against an owned
    /// <c>FileStream</c> at hosted publish). Returns
    /// the same install-relevant subset (dependencies/optionalDependencies/bin/engines/…)
    /// persisted at hosted publish (<see cref="Protocol.NpmInstallManifest.BuildJson"/>), or null
    /// when the tarball carries nothing extractable. Failure-tolerant like
    /// <see cref="ExtractLicenses"/>: any throw is swallowed and the artifact keeps rendering the
    /// minimal packument shape. Null for every non-npm ecosystem.
    /// </summary>
    Func<Stream, string?>? ExtractManifest = null);

/// <summary>Outcome of <see cref="ProxyFetchService.RecordAndScanAsync"/>.</summary>
public sealed record ProxyFetchResult(
    BlockDecision Decision,
    string Sha256,
    string BlobKey);
