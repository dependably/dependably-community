using System.Diagnostics.CodeAnalysis;
using Dependably.Protocol;
using Dependably.Storage;
using Microsoft.Extensions.Logging;

namespace Dependably.Infrastructure;

/// <summary>
/// Records a first-fetch proxy artifact. For proxy-origin artifacts, writes global-plane
/// facts (<c>cache_artifact</c>) and emits the <c>first_fetch</c> activity row; the
/// <c>package_versions</c> INSERT is skipped for proxy, because the global plane is
/// authoritative for proxy metadata. For uploaded artifacts (origin != proxy), the full
/// <c>package_versions</c> row, license, and install-script writes apply unchanged.
/// </summary>
public sealed class ProxyVersionRecorder
{
    // SQLite SQLITE_CONSTRAINT error code (unique constraint violation on insert).
    private const int SqliteConstraintErrorCode = 19;

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
    /// Records the first-fetch event for a proxy artifact via the global plane.
    ///
    /// When <paramref name="cacheArtifactId"/> is non-null (proxy path):
    ///   • Skips the <c>package_versions</c> INSERT — the global plane is authoritative.
    ///   • Emits the <c>first_fetch</c> activity row against the purl.
    ///   • Writes license, install-script, and supply-chain facts to <c>cache_artifact</c>.
    ///   • Returns null — callers detect the proxy path by non-null <paramref name="cacheArtifactId"/>
    ///     and treat a null return as "scan and gate via cache_artifact".
    ///
    /// When <paramref name="cacheArtifactId"/> is null (uploaded path, legacy callers):
    ///   • Inserts a <c>package_versions</c> row and returns its id.
    /// </summary>
    public async Task<string?> RecordAsync(
        ProxyVersionRequest req,
        Func<Stream, LicenseExtractor.ExtractedMetadata>? extractLicenses,
        CancellationToken ct = default,
        string? cacheArtifactId = null)
    {
        string? versionId = cacheArtifactId is not null
            ? await RecordProxyViaGlobalPlaneAsync(req, extractLicenses, cacheArtifactId, ct)
            : await RecordViaPvRowAsync(req, extractLicenses, cacheArtifactId: null, ct);

        // Seed the upstream-latest baseline on first contact so the package shows its "Latest"
        // immediately, instead of waiting for the next daily DeprecationRefreshService pass.
        await TrySeedUpstreamLatestAsync(req, ct);
        return versionId;
    }

    // Sets packages.upstream_latest_version from the upstream metadata the first time a package is
    // proxied (when no baseline exists yet). Bounded to one upstream metadata fetch per package:
    // once a baseline is recorded, the daily refresh keeps it current and this no-ops. Best-effort
    // — a fetch failure must never fail the first-fetch, which has already served the artifact.
    private async Task TrySeedUpstreamLatestAsync(ProxyVersionRequest req, CancellationToken ct)
    {
        try
        {
            var pkg = await _packages.GetByPurlNameAsync(req.OrgId, req.Ecosystem, req.PurlName, ct);
            if (pkg is null || pkg.UpstreamLatestVersion is not null)
            {
                return;
            }

            string? latest = await _latestResolver.ResolveAsync(req.Ecosystem, req.OrgId, req.PurlName, ct);
            if (!string.IsNullOrWhiteSpace(latest))
            {
                await _packages.UpdateUpstreamLatestAsync(pkg.Id, latest, ct);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "Failed to seed upstream latest for {Ecosystem}/{Package}: {ExceptionType}",
                req.Ecosystem, req.PurlName, ex.GetType().Name);
        }
    }

    // Proxy-origin path: write to the global plane only; skip package_versions.
    [SuppressMessage("Major Code Smell", "S125:Sections of code should not be commented out",
        Justification = "Multi-sentence architectural explanation comment, not commented-out code.")]
    private async Task<string?> RecordProxyViaGlobalPlaneAsync(
        ProxyVersionRequest req,
        Func<Stream, LicenseExtractor.ExtractedMetadata>? extractLicenses,
        string cacheArtifactId,
        CancellationToken ct)
    {
        // Ensure the per-tenant packages row exists so this org can discover the package in its
        // listings, simple index, and UI. The per-VERSION catalogue moves to the global plane
        // (cache_artifact), but the package identity stays per-tenant: packages has no
        // cross-tenant collision (its UNIQUE is per org), so each tenant keeps its own row.
        await _packages.GetOrCreateAsync(
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
            ct);

        // Null signals to the caller (ProxyFetchService) to use the cache_artifact id for scanning
        // and block-gate evaluation, rather than looking up a package_versions row.
        return null;
    }

    // Uploaded-origin or legacy path: insert a package_versions row with full dual-write.
    private async Task<string?> RecordViaPvRowAsync(
        ProxyVersionRequest req,
        Func<Stream, LicenseExtractor.ExtractedMetadata>? extractLicenses,
        string? cacheArtifactId,
        CancellationToken ct)
    {
        try
        {
            var pkg = await _packages.GetOrCreateAsync(
                req.OrgId, req.Ecosystem, req.PackageName, req.PurlName, isProxy: true, ct);

            // Proxy DB blob keys embed the filename as a suffix: "proxy/{sha256}/{filename}".
            // The blob *store* key is content-addressed ("proxy/{sha256}"); the filename suffix
            // is metadata-only so the simple index / flatcontainer responses can recover it.
            string dbBlobKey = $"{BlobKeys.Proxy(req.Sha256)}/{req.File}";
            var newVer = await _packages.CreateVersionAsync(
                new NewPackageVersion(pkg.Id, req.Version, req.Purl, dbBlobKey, req.Blob.SizeBytes, req.Sha256,
                    FirstFetch: true, PublishedAt: req.PublishedAt, ChecksumSha1: req.Sha1Hex,
                    UpstreamIntegrityValue: req.UpstreamIntegrityValue,
                    UpstreamIntegrityAlgorithm: req.UpstreamIntegrityAlgorithm),
                ct);
            await _audit.LogActivityAsync(req.OrgId, req.Ecosystem, req.Purl, "first_fetch", req.UserId, actorKind: req.ActorKind, sourceIp: req.SourceIp, ct: ct);
            // first_fetch is itself a served download (the artifact streams to the client on this
            // same request), so count it — matching the analytics 'download' + 'first_fetch'
            // taxonomy. The concurrent-insert branch logs no first_fetch and is not counted,
            // since the winning fetch already recorded the download against this row.
            await _packages.IncrementDownloadCountAsync(newVer.Id, ct);

            await WriteLicensesAsync(req, extractLicenses, newVer.Id, cacheArtifactId, ct);

            if (req.Deprecated is not null)
            {
                await _packages.UpdateDeprecatedAsync(newVer.Id, req.Deprecated, ct);
            }

            var (hasScript, scriptKind) = await WriteInstallScriptAsync(req, newVer.Id, ct);

            if (cacheArtifactId is not null)
            {
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
                    ct);
            }

            return newVer.Id;
        }
        catch (Microsoft.Data.Sqlite.SqliteException ex) when (ex.SqliteErrorCode == SqliteConstraintErrorCode)
        {
            // Concurrent first-fetch already recorded this version — look it up so the
            // caller can still gate / scan against the existing row.
            var pkg = await _packages.GetByPurlNameAsync(req.OrgId, req.Ecosystem, req.PurlName, ct);
            if (pkg is null)
            {
                return null;
            }

            var existing = await _packages.GetVersionAsync(pkg.Id, req.Version, ct);
            return existing?.Id;
        }
    }

    // Extracts and persists license data for an uploaded-origin version. Open / extract failures
    // are tolerated: the response has already streamed so the license row is skipped rather than
    // failing the caller.
    private async Task WriteLicensesAsync(
        ProxyVersionRequest req,
        Func<Stream, LicenseExtractor.ExtractedMetadata>? extractLicenses,
        string versionId,
        string? cacheArtifactId,
        CancellationToken ct)
    {
        if (extractLicenses is null)
        {
            return;
        }

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

        if (extracted.Spdx.Count == 0)
        {
            return;
        }

        await _licenses.SetLicensesAsync(versionId, extracted.Spdx, "upstream", ct);
        if (cacheArtifactId is not null)
        {
            await _licenses.SetLicensesForCacheArtifactAsync(cacheArtifactId, extracted.Spdx, "upstream", ct);
        }
    }

    // Detects install/lifecycle scripts and persists the result. Best-effort: a read or parse
    // failure leaves has_install_script at its default rather than failing the first-fetch.
    private async Task<(bool HasScript, string? Kind)> WriteInstallScriptAsync(
        ProxyVersionRequest req,
        string versionId,
        CancellationToken ct)
    {
        try
        {
            await using var stream = await req.Blob.OpenAsync(ct);
            var script = await ScriptDetectionService.DetectAsync(req.Ecosystem, req.File, stream, ct);
            if (script.HasScript)
            {
                await _packages.UpdateInstallScriptAsync(versionId, true, script.Kind, ct);
                return (true, script.Kind);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Swallowed: detection is advisory; the cached version still serves.
        }

        return (false, null);
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
