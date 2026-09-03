using Dependably.Infrastructure;
using Dependably.Infrastructure.Hex;
using Dependably.Protocol;
using Dependably.Protocol.Hex;
using Dependably.Security;
using Dependably.Storage;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// The artifact half of the Hex read plane: package tarballs and documentation tarballs.
/// A tarball this org holds serves from its plane behind the block gate; one it does not is
/// fetched from the upstream through the shared proxy pipeline — hash-and-staged, checksum
/// verified against the outer checksum the upstream's own signed index vouched for, recorded on
/// the cache plane, scanned and gated before a byte reaches the client, and source-pinned to
/// the upstream that first served the name.
/// </summary>
public sealed partial class HexController
{
    private const string TarContentType = "application/octet-stream";

    /// <summary>
    /// The coordinate and caller facts every arm of the tarball serve path needs. Threaded as one
    /// value so each arm takes the whole context rather than re-listing it parameter by parameter.
    /// </summary>
    private readonly record struct HexServeContext(
        string OrgId, string Name, string Version, string Filename,
        OrgSettings? Settings, TokenRecord? Token, string? SourceIp);

    private async Task<IActionResult> ServeTarballAsync(
        string orgId, string name, string version, OrgSettings? settings, TokenRecord? token, CancellationToken ct)
    {
        var ctx = new HexServeContext(
            orgId, name, version, $"{name}-{version}.tar",
            settings, token, HttpContext.GetNormalizedRemoteIp());

        // Hosted first: a release this org published shadows the upstream's on collision, the
        // same rule the index applies.
        var pkg = await _svc.Packages.GetByPurlNameAsync(orgId, Ecosystem, name, ct);
        var hosted = pkg is null ? null : await _svc.Packages.GetVersionAsync(pkg.Id, version, ct);
        if (hosted is not null && hosted.Origin != "proxy")
        {
            return await ServeHostedTarballAsync(ctx, hosted, ct);
        }

        // Cache hit on the global plane.
        var cached = await _svc.CacheArtifacts.GetServeFactsByCoordinateAsync(orgId, Ecosystem, name, version, ctx.Filename, ct);
        if (cached is not null)
        {
            if (!await _svc.ClaimResolver.IsProxyFetchAllowedAsync(orgId, "hex", name, ct))
            {
                return NotFound();
            }

            // A null result is a cache row whose blob is gone: fall through to the miss path and
            // re-fetch rather than serving a 404 for an artifact this org is entitled to.
            if (await ServeCachedTarballAsync(ctx, cached, ct) is { } hit)
            {
                return hit;
            }
        }

        // Cache miss: the same admission rules the index applies decide whether the upstream is
        // consulted at all.
        if (settings is null or { ProxyPassthroughEffective: false }
            || await _svc.Reserved.IsReservedAsync(orgId, Ecosystem, name, ct)
            || !await _svc.ClaimResolver.IsProxyFetchAllowedAsync(orgId, "hex", name, ct))
        {
            return NotFound();
        }

        var upstream = await FetchUpstreamPackageAsync(orgId, name, ct);
        if (upstream.Package is null || upstream.Source is null)
        {
            return upstream.Outcome == UpstreamOutcome.Fault
                ? StatusCode(StatusCodes.Status502BadGateway, "Upstream Hex repository is unavailable.")
                : NotFound();
        }

        var release = upstream.Package.Releases.FirstOrDefault(r => r.Version == version);
        return release is null
            ? NotFound()
            : await ProxyTarballAsync(ctx, release, upstream.Source, settings, ct);
    }

    /// <summary>The hosted plane's arm: the stored-state gate, then the conditional-request check, then the blob.</summary>
    private async Task<IActionResult> ServeHostedTarballAsync(
        HexServeContext ctx, PackageVersion hosted, CancellationToken ct)
    {
        if (await _svc.BlockGate.EvaluateAsync(
                BlockGateRequest.For(ctx.OrgId, Ecosystem, hosted, ctx.Token, ctx.Settings, ctx.SourceIp), ct) == BlockDecision.Blocked)
        {
            return StatusCode(StatusCodes.Status403Forbidden);
        }

        if (TarballNotModified(hosted.ChecksumSha256))
        {
            return StatusCode(StatusCodes.Status304NotModified);
        }

        var body = await _svc.Blobs.GetAsync(BlobKeys.StoreKey(hosted.BlobKey), ct);
        return body is null ? NotFound() : File(body, TarContentType, ctx.Filename);
    }

    /// <summary>
    /// The cache plane's arm, or null when the recorded blob is missing and the caller should fall
    /// through to the miss path. The gate runs on the cache facts before the bytes leave, the same
    /// evaluation first-fetch performs, so a hit and a first fetch refuse alike.
    /// </summary>
    private async Task<IActionResult?> ServeCachedTarballAsync(
        HexServeContext ctx, CacheArtifactServeFacts cached, CancellationToken ct)
    {
        var stream = await _svc.Blobs.GetAsync(BlobKeys.StoreKey(cached.BlobKey), ct);
        if (stream is null)
        {
            return null;
        }

        if (await _svc.BlockGate.EvaluateAsync(
                BlockGateRequest.ForProxyCacheFacts(ctx.OrgId, Ecosystem, cached, ctx.Token, ctx.Settings, ctx.SourceIp), ct) == BlockDecision.Blocked)
        {
            await stream.DisposeAsync();
            return StatusCode(StatusCodes.Status403Forbidden);
        }

        await RecordCacheHitAsync(ctx.OrgId, ctx.Name, ctx.Version, ctx.Filename, cached, ct);
        if (TarballNotModified(cached.ContentHash))
        {
            await stream.DisposeAsync();
            return StatusCode(StatusCodes.Status304NotModified);
        }

        Response.Headers["X-Cache"] = "HIT";
        return File(stream, TarContentType, ctx.Filename);
    }

    private async Task<IActionResult> ProxyTarballAsync(
        HexServeContext ctx, HexRelease release, UpstreamSource source, OrgSettings settings, CancellationToken ct)
    {
        // The outer checksum from the upstream's signed index is what a Hex client verifies the
        // download against, so it is what this registry verifies at the trust boundary too. An
        // index entry without one is not fetched: an unverifiable artifact is not admitted.
        if (release.OuterChecksum is null || release.OuterChecksum.Length != 32)
        {
            _svc.Logger.LogWarning("Hex upstream index for {Name} {Version} carries no outer checksum; refusing the fetch.", ctx.Name, ctx.Version);
            return StatusCode(StatusCodes.Status502BadGateway, "Upstream Hex index supplied no checksum for the tarball.");
        }

        string downloadUrl = $"{source.Url.TrimEnd('/')}/tarballs/{Uri.EscapeDataString(ctx.Filename)}";
        var checksum = new ChecksumSpec(ChecksumAlgorithm.Sha256, Convert.ToHexString(release.OuterChecksum).ToLowerInvariant());

        var (fetched, fetchFailure) = await FetchTarballToBlobAsync(ctx, source, downloadUrl, checksum, ct);
        if (fetchFailure is not null)
        {
            return fetchFailure;
        }

        var (result, recordFailure) = await RecordProxyFetchAsync(ctx, release, source, settings, fetched!, downloadUrl, checksum, ct);
        if (recordFailure is not null)
        {
            return recordFailure;
        }

        if (result!.Decision == BlockDecision.Blocked)
        {
            return StatusCode(StatusCodes.Status403Forbidden, BlockRefusal(result.Arm));
        }

        await RecordProxiedReleaseFactsAsync(ctx, release, ct);

        var body = await _svc.Blobs.GetAsync(BlobKeys.StoreKey(fetched!.BlobKey), ct);
        if (body is null)
        {
            return NotFound();
        }

        TarballNotModified(fetched.Sha256Hex);
        Response.Headers["X-Cache"] = "MISS";
        return File(body, TarContentType, ctx.Filename);
    }

    /// <summary>
    /// Fetches and checksum-verifies the tarball into its org-scoped blob key. Returns the fetch
    /// result, or the refusal to serve when the upstream is unreachable or fails verification.
    /// </summary>
    private async Task<(UpstreamFetchResult? Fetched, IActionResult? Failure)> FetchTarballToBlobAsync(
        HexServeContext ctx, UpstreamSource source, string downloadUrl, ChecksumSpec checksum, CancellationToken ct)
    {
        try
        {
            return (await _svc.Upstream.GetOrFetchToBlobKeyAsync(
                BlobKeys.Hex(ctx.OrgId, ctx.Name, ctx.Version), downloadUrl, checksum, Ecosystem, ctx.OrgId,
                PurlNormalizer.Hex(ctx.Name, ctx.Version),
                authorizationHeader: source.AuthorizationHeader, containmentBase: source.Url, ct: ct), null);
        }
        catch (ChecksumException)
        {
            _svc.Logger.LogWarning("Checksum mismatch fetching hex {Name} {Version}.", ctx.Name, ctx.Version);
            return (null, StatusCode(StatusCodes.Status502BadGateway, "Upstream checksum verification failed."));
        }
        catch (Exception ex) when (ex is SsrfBlockedException or UpstreamResponseTooLargeException or HttpRequestException or IOException)
        {
            _svc.Logger.LogWarning(ex, "Hex tarball fetch for {Name} {Version} failed: {ExceptionType}", ctx.Name, ctx.Version, ex.GetType().Name);
            return (null, StatusCode(StatusCodes.Status502BadGateway, "Upstream Hex tarball fetch failed."));
        }
    }

    /// <summary>
    /// Records the staged blob on the cache plane and runs the first-fetch gate over it. The staged
    /// blob is deleted on every refusal and on every throw, so a blob never outlives the catalogue
    /// row that would have made it discoverable.
    /// </summary>
    private async Task<(ProxyFetchResult? Result, IActionResult? Failure)> RecordProxyFetchAsync(
        HexServeContext ctx, HexRelease release, UpstreamSource source, OrgSettings settings,
        UpstreamFetchResult fetched, string downloadUrl, ChecksumSpec checksum, CancellationToken ct)
    {
        var blob = new BlobHandle(fetched.BlobKey, fetched.Sha256Hex, fetched.SizeBytes,
            async openCt => await _svc.Blobs.GetAsync(BlobKeys.StoreKey(fetched.BlobKey), openCt)
                ?? throw new InvalidOperationException($"Blob {fetched.BlobKey} vanished between fetch and serve."));

        try
        {
            return (await _svc.ProxyFetch.RecordAndScanAsync(new ProxyFetchRequest(
                OrgId: ctx.OrgId, Ecosystem: Ecosystem, PackageName: ctx.Name, PurlName: ctx.Name,
                Version: ctx.Version, Purl: PurlNormalizer.Hex(ctx.Name, ctx.Version), File: ctx.Filename, Blob: blob,
                ExtractLicenses: HexLicenses.FromTarball,
                AuditActorId: ctx.Token?.AuditActorId, AuditActorLabel: ctx.Token?.AuditActorLabel,
                ActorKind: ctx.Token?.ActorKind,
                SourceIp: ctx.SourceIp,
                MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance,
                CacheAccess: new CacheAccess(ctx.OrgId, Ecosystem, ctx.Name, ctx.Version, ctx.Filename,
                    Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: downloadUrl, Origin: CacheAccessOrigin.FirstFetch),
                // The upstream index carries the publish time and the retirement state, so the
                // release-age and deprecation arms fire on this fetch and persist on the row.
                PublishedAt: release.PublishedAt?.ToDateTimeOffset(),
                MinReleaseAgeHours: settings.MinReleaseAgeHours,
                BlockDeprecatedMode: settings.BlockDeprecated,
                BlockMaliciousMode: settings.BlockMalicious,
                BlockMaliciousLiveMode: settings.BlockMaliciousLive,
                BlockKevMode: settings.BlockKev,
                BlockRevokedMode: settings.BlockRevoked,
                MaxEpssTolerance: settings.MaxEpssTolerance,
                UpstreamChecksum: checksum,
                UpstreamUrl: source.Url,
                LicenseEnforcementMode: settings.LicenseEnforcementMode,
                Deprecated: release.Retired is { } retired ? HexIndexBuilder.RetirementAsDeprecation(retired) : null), ct), null);
        }
        catch (ProxyCatalogueUnavailableException)
        {
            await _svc.Blobs.DeleteAsync(BlobKeys.StoreKey(fetched.BlobKey), ct);
            _svc.Logger.LogWarning("Cache plane unavailable recording hex {Name} {Version} for org {OrgId}; refusing the fetch.", ctx.Name, ctx.Version, ctx.OrgId);
            return (null, StatusCode(StatusCodes.Status503ServiceUnavailable, "Package could not be recorded on the cache plane; retry."));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await _svc.Blobs.DeleteAsync(BlobKeys.StoreKey(fetched.BlobKey), ct);
            throw;
        }
    }

    /// <summary>
    /// The per-tenant packages row (so the package lists in this org) and the release facts the
    /// index needs when the upstream is unreachable later: the inner checksum and dependencies
    /// come straight from the verified upstream index, not from the tarball.
    /// </summary>
    private async Task RecordProxiedReleaseFactsAsync(HexServeContext ctx, HexRelease release, CancellationToken ct)
    {
        await _svc.Packages.GetOrCreateAsync(ctx.OrgId, Ecosystem, ctx.Name, ctx.Name, isProxy: true, ct);
        var recorded = await _svc.CacheArtifacts.GetServeFactsByCoordinateAsync(
            ctx.OrgId, Ecosystem, ctx.Name, ctx.Version, ctx.Filename, ct);
        if (recorded is null)
        {
            return;
        }

        await _svc.Releases.UpsertCachedAsync(recorded.Id, new HexReleaseFacts(
            Convert.ToHexString(release.InnerChecksum),
            release.Dependencies.Select(d => new HexRequirement(d.Package, d.Requirement, d.Optional ?? false, d.App, d.Repository)).ToList(),
            null, Array.Empty<string>(), null,
            release.Retired?.Reason, release.Retired?.Message, false, null), ct);
    }

    // A tarball's strong ETag is its SHA-256 — the same digest the index vouches for — and it is
    // required, not optional: rebar3 treats a 200 without an etag header as a failed fetch, and
    // both clients send if-none-match to skip a tarball they already hold.
    private bool TarballNotModified(string? sha256Hex)
    {
        if (string.IsNullOrEmpty(sha256Hex))
        {
            return false;
        }

        string etag = "\"" + sha256Hex.ToLowerInvariant() + "\"";
        Response.Headers.ETag = etag;
        return Request.Headers.IfNoneMatch.Any(v => v == etag);
    }

    private async Task RecordCacheHitAsync(
        string orgId, string name, string version, string filename, CacheArtifactServeFacts facts, CancellationToken ct)
    {
        string? cacheArtifactId = await _svc.CacheRecorder.RecordAccessAsync(
            new CacheAccess(orgId, Ecosystem, name, version, filename,
                facts.ContentHash, facts.SizeBytes, facts.BlobKey, UpstreamUrl: null, CacheAccessOrigin.CacheHit), ct);
        if (cacheArtifactId is not null)
        {
            await _svc.TenantAccess.RecordDownloadHitAsync(orgId, cacheArtifactId, _svc.Time.GetUtcNow(), ct);
        }
    }

    private static string BlockRefusal(BlockArm arm) =>
        arm == BlockArm.None ? "Blocked by policy." : $"Blocked by policy ({arm}).";

    // ── Documentation tarballs ───────────────────────────────────────────────

    // Docs are served only for a release whose package tarball this org would serve, decided by
    // the same gate; a blocked release keeps its documentation out of reach too. A hosted docs
    // tarball is what the publisher uploaded; a proxied one is fetched verbatim from the upstream
    // under the org-scoped docs key and is not an artifact on the cache plane — the package
    // tarball is the inventory row, the docs ride on it.
    private async Task<IActionResult> ServeDocsAsync(
        string orgId, string name, string version, OrgSettings? settings, TokenRecord? token, CancellationToken ct)
    {
        string? sourceIp = HttpContext.GetNormalizedRemoteIp();
        var pkg = await _svc.Packages.GetByPurlNameAsync(orgId, Ecosystem, name, ct);
        var hosted = pkg is null ? null : await _svc.Packages.GetVersionAsync(pkg.Id, version, ct);
        if (hosted is not null && hosted.Origin != "proxy")
        {
            if (await _svc.BlockGate.EvaluateAsync(
                    BlockGateRequest.For(orgId, Ecosystem, hosted, token, settings, sourceIp), ct) == BlockDecision.Blocked)
            {
                return StatusCode(StatusCodes.Status403Forbidden);
            }

            var docs = await _svc.Blobs.GetAsync(BlobKeys.HexDocs(orgId, name, version), ct);
            return docs is null ? NotFound() : File(docs, "application/gzip", $"{name}-{version}.tar.gz");
        }

        var cached = await _svc.CacheArtifacts.GetServeFactsByCoordinateAsync(orgId, Ecosystem, name, version, $"{name}-{version}.tar", ct);
        if (cached is null || settings is null or { ProxyPassthroughEffective: false }
            || !await _svc.ClaimResolver.IsProxyFetchAllowedAsync(orgId, "hex", name, ct))
        {
            // Docs for a release this org has never fetched are not fetched on their own: the
            // package tarball is the admission point, and a client always resolves it first.
            return NotFound();
        }

        if (await _svc.BlockGate.EvaluateAsync(
                BlockGateRequest.ForProxyCacheFacts(orgId, Ecosystem, cached, token, settings, sourceIp), ct) == BlockDecision.Blocked)
        {
            return StatusCode(StatusCodes.Status403Forbidden);
        }

        string docsKey = BlobKeys.HexDocs(orgId, name, version);
        var existing = await _svc.Blobs.GetAsync(docsKey, ct);
        if (existing is not null)
        {
            return File(existing, "application/gzip", $"{name}-{version}.tar.gz");
        }

        var upstreamDocs = await FetchDocsFromUpstreamAsync(orgId, name, version, docsKey, ct);
        return upstreamDocs is null ? NotFound() : File(upstreamDocs, "application/gzip", $"{name}-{version}.tar.gz");
    }

    /// <summary>
    /// The docs tarball from the first configured upstream that serves one, stored under the
    /// org-scoped docs key. A source that faults is logged and skipped so one unreachable upstream
    /// does not mask a later one that holds the documentation; null when none of them serve it.
    /// </summary>
    private async Task<Stream?> FetchDocsFromUpstreamAsync(
        string orgId, string name, string version, string docsKey, CancellationToken ct)
    {
        var sources = await _svc.Registries.ResolveAsync(orgId, Ecosystem, ct);
        foreach (var source in sources)
        {
            string url = $"{source.Url.TrimEnd('/')}/docs/{Uri.EscapeDataString($"{name}-{version}.tar.gz")}";
            try
            {
                var fetched = await _svc.Upstream.GetOrFetchToBlobKeyAsync(
                    docsKey, url, null, Ecosystem, orgId, PurlNormalizer.Hex(name, version),
                    authorizationHeader: source.AuthorizationHeader, containmentBase: source.Url, ct: ct);
                if (await _svc.Blobs.GetAsync(BlobKeys.StoreKey(fetched.BlobKey), ct) is { } body)
                {
                    return body;
                }
            }
            catch (Exception ex) when (ex is SsrfBlockedException or UpstreamResponseTooLargeException or HttpRequestException or IOException)
            {
                _svc.Logger.LogWarning(ex, "Hex docs fetch for {Name} {Version} failed: {ExceptionType}", name, version, ex.GetType().Name);
            }
        }

        return null;
    }

    // ── Policies ─────────────────────────────────────────────────────────────

    /// <summary>The one policy this registry publishes: the org's proxy settings, projected.</summary>
    public const string PolicyName = "dependably";

    // /repos/dependably/policies/dependably: the org's block-gate posture as a signed Policy an
    // opted-in client enforces before resolution. Only the arms with a Hex counterpart are
    // projected — the advisory-severity threshold, retirement (Hex's deprecation) and the
    // release-age cooldown — plus a DENY override for every held package the org's blocklist
    // matches, so the client learns the refusal before it asks. Visibility follows AnonymousPull.
    private async Task<IActionResult> ServePolicyAsync(string orgId, string policyName, OrgSettings? settings, CancellationToken ct)
    {
        if (policyName != PolicyName || settings is null)
        {
            return NotFound();
        }

        var restriction = new HexRestriction(
            AdvisoryMinSeverityFor(settings.MaxOsvScoreTolerance),
            settings.BlockDeprecated == "off"
                ? Array.Empty<HexRetirementReason>()
                : new[] { HexRetirementReason.Other, HexRetirementReason.Invalid, HexRetirementReason.Security, HexRetirementReason.Deprecated, HexRetirementReason.Renamed },
            settings.MinReleaseAgeHours is { } hours && hours > 0 ? $"{(hours + 23) / 24}d" : null);

        var overrides = new List<HexOverride>();
        var blocklist = await _svc.Blocklist.ListAsync(orgId, ct);
        if (blocklist.Count > 0)
        {
            var held = await _svc.Releases.ListAllAsync(orgId, ct);
            foreach (var group in held.GroupBy(h => h.Name, StringComparer.Ordinal).OrderBy(g => g.Key, StringComparer.Ordinal))
            {
                var versions = group.Select(h => h.Release.Version).ToList();
                var denied = versions.Where(v => IsBlocklisted(blocklist, PurlNormalizer.Hex(group.Key, v))).ToList();
                if (denied.Count == versions.Count)
                {
                    overrides.Add(new HexOverride(HexOverrideAction.Deny, new HexPackageRef(group.Key), Comment: "blocked by this registry's policy"));
                }
                else
                {
                    overrides.AddRange(denied.Select(v => new HexOverride(
                        HexOverrideAction.Deny, new HexPackageRef(group.Key, $"== {v}"), Comment: "blocked by this registry's policy")));
                }
            }
        }

        var policy = new HexPolicy(
            HexIndexBuilder.RepositoryName, PolicyName,
            settings.AnonymousPull ? HexVisibility.Public : HexVisibility.Private,
            new[]
            {
                new HexRepositoryPolicy(HexIndexBuilder.RepositoryName, restriction, overrides),
                // The same limits govern anything a client resolves straight from hex.pm beside
                // this registry; the overrides are this registry's own inventory and stay here.
                new HexRepositoryPolicy(HexWellKnownRepositories.HexpmRepositoryName, restriction, Array.Empty<HexOverride>()),
            },
            "This registry's block-gate posture, projected for clients that enforce dependency policies at resolution time.");

        return await SignAndServeAsync(orgId, HexRegistryCodec.EncodePolicy(policy), ct);
    }

    // max_osv_score_tolerance is a CVSS score ceiling; the policy's advisory limit is a band, so
    // the ceiling maps onto the lowest band whose scores it would refuse. A tolerance of 10 (the
    // default, refuse nothing) projects to no limit.
    internal static HexAdvisorySeverity? AdvisoryMinSeverityFor(double maxOsvScoreTolerance) => maxOsvScoreTolerance switch
    {
        >= 10.0 => null,
        >= 9.0 => HexAdvisorySeverity.Critical,
        >= 7.0 => HexAdvisorySeverity.High,
        >= 4.0 => HexAdvisorySeverity.Medium,
        > 0.0 => HexAdvisorySeverity.Low,
        _ => HexAdvisorySeverity.None,
    };

    private static bool IsBlocklisted(IReadOnlyList<BlocklistEntry> blocklist, string purl)
    {
        foreach (var entry in blocklist)
        {
            try
            {
                if (System.Text.RegularExpressions.Regex.IsMatch(purl, entry.Pattern,
                        System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromSeconds(2)))
                {
                    return true;
                }
            }
            catch (Exception ex) when (ex is ArgumentException or System.Text.RegularExpressions.RegexMatchTimeoutException)
            {
                // An unusable pattern is the operator's to fix; it blocks nothing here, as it blocks nothing at serve.
            }
        }

        return false;
    }
}
