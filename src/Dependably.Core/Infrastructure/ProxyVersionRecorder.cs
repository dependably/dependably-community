using System.Diagnostics.CodeAnalysis;
using Dependably.Protocol;
using Dependably.Storage;
using Microsoft.Extensions.Logging;

namespace Dependably.Infrastructure;

/// <summary>
/// Records a first-fetch proxy artifact. The cache plane (<c>cache_artifact</c>) is the
/// catalogue for a proxied artefact and the only one: this writes the global-plane facts —
/// licences, install-script detection, provenance, manifest — against the row the caller has
/// already created there, and emits the <c>first_fetch</c> activity row. <c>package_versions</c>
/// is the hosted plane and is not written here; a row there would be skipped by the vulnerability
/// sweep and by retention, both of which read it as origin = 'uploaded'.
/// </summary>
public sealed class ProxyVersionRecorder
{
    private readonly PackageRepository _packages;
    private readonly AuditRepository _audit;
    private readonly LicenseRepository _licenses;
    private readonly CacheArtifactRepository _cacheArtifacts;
    private readonly IUpstreamLatestVersionResolver _latestResolver;
    private readonly ILogger<ProxyVersionRecorder> _logger;

    public ProxyVersionRecorder(
        PackageRepository packages,
        AuditRepository audit,
        LicenseRepository licenses,
        CacheArtifactRepository cacheArtifacts,
        IUpstreamLatestVersionResolver latestResolver,
        ILogger<ProxyVersionRecorder> logger)
    {
        _packages = packages;
        _audit = audit;
        _licenses = licenses;
        _cacheArtifacts = cacheArtifacts;
        _latestResolver = latestResolver;
        _logger = logger;
    }

    /// <summary>
    /// Records the first-fetch event against the artefact's <c>cache_artifact</c> row: emits the
    /// <c>first_fetch</c> activity row and writes the licence, install-script and supply-chain facts
    /// the block gates read. <paramref name="cacheArtifactId"/> is required — the caller
    /// (<c>ProxyFetchService</c>) refuses the fetch outright when the cache plane could not produce
    /// a row, so there is no second plane to fall back to here.
    /// </summary>
    public async Task RecordAsync(
        ProxyVersionRequest req,
        Func<Stream, LicenseExtractor.ExtractedMetadata>? extractLicenses,
        Func<Stream, string?>? extractManifest,
        string cacheArtifactId,
        CancellationToken ct = default)
    {
        await RecordProxyViaGlobalPlaneAsync(req, extractLicenses, extractManifest, cacheArtifactId, ct);

        // Seed the upstream-latest baseline on first contact so the package shows its "Latest"
        // immediately, instead of waiting for the next daily DeprecationRefreshService pass.
        await TrySeedUpstreamLatestAsync(req, cacheArtifactId, ct);
    }

    // Sets packages.upstream_latest_version from the upstream metadata the first time a package is
    // proxied (when no baseline exists yet), and — in the same resolve — seeds this version's own
    // operational-risk versions_behind count on its cache_artifact row. Bounded to one upstream
    // metadata fetch per package: once a baseline is recorded, the daily refresh keeps both the
    // baseline and every version's versions_behind current, and this no-ops. Best-effort — a fetch
    // failure must never fail the first-fetch, which has already served the artifact.
    private async Task TrySeedUpstreamLatestAsync(ProxyVersionRequest req, string? cacheArtifactId, CancellationToken ct)
    {
        try
        {
            var pkg = await _packages.GetByPurlNameAsync(req.OrgId, req.Ecosystem, req.PurlName, ct);
            if (pkg is null || pkg.UpstreamLatestVersion is not null)
            {
                return;
            }

            var latest = await _latestResolver.ResolveAsync(req.Ecosystem, req.OrgId, req.PurlName, ct);
            if (!string.IsNullOrWhiteSpace(latest?.Version))
            {
                await _packages.UpdateUpstreamLatestAsync(pkg.Id, latest.Version, latest.PublishedAt, ct);
            }

            if (cacheArtifactId is not null)
            {
                int? versionsBehind = EcosystemVersionOrdering.CountNewerStable(
                    req.Ecosystem, latest?.StableVersionsDescending, req.Version);
                await _cacheArtifacts.UpdateVersionsBehindAsync(cacheArtifactId, versionsBehind, ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "Failed to seed upstream latest for {Ecosystem}/{Package}: {ExceptionType}",
                req.Ecosystem, req.PurlName, ex.GetType().Name);
        }
    }

    // Writes the artefact's facts to the cache plane. package_versions is not touched.
    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out",
        Justification = "Multi-sentence architectural explanation comment, not commented-out code.")]
    private async Task RecordProxyViaGlobalPlaneAsync(
        ProxyVersionRequest req,
        Func<Stream, LicenseExtractor.ExtractedMetadata>? extractLicenses,
        Func<Stream, string?>? extractManifest,
        string cacheArtifactId,
        CancellationToken ct)
    {
        // Ensure the per-tenant packages row exists so this org can discover the package in its
        // listings, simple index, and UI. The per-VERSION catalogue moves to the global plane
        // (cache_artifact), but the package identity stays per-tenant: packages has no
        // cross-tenant collision (its UNIQUE is per org), so each tenant keeps its own row.
        //
        // Catalogue-hidden ecosystems are the exception and get NO packages row: their artefacts
        // are not packages and must not surface as one. A proxied PDB is keyed by debug-id, so a
        // row here lists it as a package named 'mylib.pdb' under an ecosystem the frontend has no
        // label for. It still lands on the global plane, so it stays gated, storage-accounted, and
        // resolvable by the surface that fetched it — it is only absent from the catalogue.
        var pkg = CatalogueHiddenEcosystems.Covers(req.Ecosystem)
            ? null
            : await _packages.GetOrCreateAsync(
                req.OrgId, req.Ecosystem, req.PackageName, req.PurlName, isProxy: true, ct);

        // Emit the first_fetch activity row — audit still fires for proxy artifacts so the
        // per-tenant event stream is not silenced. Download-count is on tenant_artifact_access;
        // the caller (ProxyFetchService) already called UpsertStateAsync before RecordAsync.
        await _audit.LogActivityAsync(req.OrgId, req.Ecosystem, req.Purl, "first_fetch",
            req.UserId, actorKind: req.ActorKind, sourceIp: req.SourceIp, ct: ct);

        // License extraction writes only to the global plane.
        if (extractLicenses is not null)
        {
            LicenseExtractor.ExtractedMetadata extracted;
            try
            {
                var stream = await req.Blob.OpenAsync(ct);
                extracted = extractLicenses(stream);
            }
            catch
            {
                extracted = LicenseExtractor.ExtractedMetadata.Empty;
            }

            if (extracted.Spdx.Count > 0)
            {
                await _licenses.SetLicensesForCacheArtifactAsync(cacheArtifactId, extracted.Spdx, "upstream", ct);
            }

            // Presentation metadata (homepage/repository/description) lives on the per-tenant
            // packages row — the one row that exists on both hosted and proxy paths — rather than
            // the global cache_artifact plane. COALESCE in UpdateMetadataAsync means a manifest
            // that omits a field never clears a previously-captured value.
            // Null only for a catalogue-hidden ecosystem, which has no packages row to carry
            // presentation metadata — and no surface that would display it either.
            if (pkg is not null)
            {
                await _packages.UpdateMetadataAsync(
                    pkg.Id, extracted.Homepage, extracted.Repository, extracted.Description, ct);
            }
        }

        // Install/lifecycle-script detection on the freshly-cached artifact. Best-effort:
        // a read or parse failure leaves has_install_script at its 0 default rather than
        // failing the first-fetch — the artifact has already streamed to the client.
        bool hasScript = false;
        string? scriptKind = null;
        try
        {
            await using var stream = await req.Blob.OpenAsync(ct);
            var script = await ScriptDetectionService.DetectAsync(req.Ecosystem, req.File, stream, ct);
            if (script.HasScript)
            {
                hasScript = true;
                scriptKind = script.Kind;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Swallowed: detection is advisory; the cached version still serves.
        }

        // npm install-manifest extraction writes only to the global plane, same as license
        // extraction above. COALESCE semantics in UpdateGlobalFactsAsync mean a null result here
        // (extraction failure, or every non-npm ecosystem) never clears an already-stored value —
        // this is also how a pre-migration row (manifest_json NULL) backfills lazily the next time
        // this artifact is re-fetched from upstream.
        string? manifestJson = null;
        if (extractManifest is not null)
        {
            try
            {
                // Caller-owned stream: NpmTarballValidator.Validate (the extractor's parser)
                // deliberately leaves the source stream open for the caller to dispose, unlike
                // the license extractor above, so this recorder must close it explicitly.
                await using var stream = await req.Blob.OpenAsync(ct);
                manifestJson = extractManifest(stream);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                manifestJson = null;
            }
        }

        // Write all supply-chain facts to the global cache_artifact row. Runs after script
        // detection so has_install_script reflects the freshly-computed result.
        await _cacheArtifacts.UpdateGlobalFactsAsync(
            cacheArtifactId,
            purl: req.Purl,
            checksumSha1: req.Sha1Hex,
            publishedAt: req.PublishedAt,
            deprecated: req.Deprecated,
            hasInstallScript: hasScript,
            installScriptKind: scriptKind,
            provenanceStatus: null,
            provenanceSigner: null,
            upstreamIntegrityValue: req.UpstreamIntegrityValue,
            upstreamIntegrityAlgorithm: req.UpstreamIntegrityAlgorithm,
            manifestJson: manifestJson,
            ct: ct);

    }
}

/// <summary>
/// Per-fetch context for <see cref="ProxyVersionRecorder.RecordAsync"/>. <c>PackageName</c>
/// is the display name used on creation (NuGet preserves canonical case from the .nuspec);
/// <c>PurlName</c> is the normalised lookup key.
/// </summary>
public sealed record ProxyVersionRequest(
    string OrgId,
    string Ecosystem,
    string PackageName,
    string PurlName,
    string Version,
    string Purl,
    string Sha256,
    string File,
    BlobHandle Blob,
    string? UserId,
    /// <summary>
    /// Discriminator persisted alongside <see cref="UserId"/> in <c>activity.actor_kind</c>:
    /// <see cref="ActorKinds.User"/> for user-token-attributed first fetches,
    /// <see cref="ActorKinds.Service"/> for service-token-attributed ones, or NULL for
    /// truly-anonymous fetches (only reachable on pull paths when AnonymousPull=1). Without
    /// this, service-token first fetches show up as "anonymous" in the audit UI because
    /// <c>TokenRepository.ResolveAsync</c> never sets <c>UserId</c> for service tokens.
    /// </summary>
    string? ActorKind = null,
    string? SourceIp = null,
    /// <summary>
    /// Upstream first-publish timestamp extracted on the cache-miss path (PyPI upload_time,
    /// npm time[version], NuGet catalogEntry.published). Null if the metadata couldn't be
    /// fetched or parsed — capture is fail-soft, never blocks the artefact write.
    /// </summary>
    DateTimeOffset? PublishedAt = null,
    /// <summary>
    /// Hex SHA-1 of the artefact bytes — captured from the upstream npm packument's
    /// <c>dist.shasum</c> so the merged/local-only packument we re-emit later carries the
    /// correct SHA-1. Null outside npm and when upstream didn't supply it.
    /// </summary>
    string? Sha1Hex = null,
    /// <summary>
    /// Upstream-published integrity hash captured verbatim in upstream's native encoding,
    /// surfaced in the UI so operators can cross-check against the public registry's listing.
    /// </summary>
    string? UpstreamIntegrityValue = null,
    string? UpstreamIntegrityAlgorithm = null,
    /// <summary>
    /// Upstream deprecation message captured at first-fetch. npm carries a free-text
    /// <c>versions[v].deprecated</c> string; PyPI maps <c>yanked: true</c> to
    /// <c>yanked_reason</c> (or the literal <c>"Yanked"</c>); NuGet maps
    /// <c>listed: false</c> to <c>"Unlisted upstream"</c>. Null when upstream didn't
    /// flag the version. Persisted via <c>PackageRepository.UpdateDeprecatedAsync</c>
    /// so the UI badge mirrors the publish-path behaviour.
    /// </summary>
    string? Deprecated = null);
