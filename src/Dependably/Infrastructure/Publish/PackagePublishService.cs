using System.Diagnostics;
using System.Security.Cryptography;
using Dependably.Infrastructure.Observability;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;

namespace Dependably.Infrastructure.Publish;

/// <summary>
/// Default <see cref="IPackagePublishService"/>. The single tail end of the publish flow:
/// path safety → claim gate → size cap → dedup check → blob put → version create → audit.
/// Replaces what used to be inlined in three protocol controllers and three import handlers.
/// </summary>
public sealed class PackagePublishService : IPackagePublishService
{
    // Minimum slash position for a valid npm scoped package: '@' + at least one scope char.
    private const int NpmScopeMinSlashPosition = 2;

    private readonly PackageRepository _packages;
    private readonly OrgRepository _orgs;
    private readonly ITenantStorageResolver _storage;
    private readonly PublishGate _publishGate;
    private readonly PublishAuditor _auditor;
    private readonly VulnerabilityScanService _scanner;
    private readonly ILogger<PackagePublishService> _logger;

    public PackagePublishService(
        PackageRepository packages,
        OrgRepository orgs,
        ITenantStorageResolver storage,
        PublishGate publishGate,
        PublishAuditor auditor,
        VulnerabilityScanService scanner,
        ILogger<PackagePublishService> logger)
    {
        _packages = packages;
        _orgs = orgs;
        // Published artefacts always land on the registry tier, resolved per-tenant so
        // enterprise deployments route to the tenant's silo bucket. Community pool mode
        // returns the singleton registry regardless. The resolver gates on lifecycle
        // status + provisioning state — a suspended/archived tenant or a half-initialized
        // bucket raises TenantNotReadyException before any blob bytes are written.
        _storage = storage;
        _publishGate = publishGate;
        _auditor = auditor;
        _scanner = scanner;
        _logger = logger;
    }

    public async Task<PublishResult> StoreAndRecordAsync(PublishRequest request, CancellationToken ct = default)
    {
        using var activity = DependablyActivitySource.Source.StartActivity(
            "package.publish", ActivityKind.Server);
        activity?.SetTag("dependably.ecosystem", request.Ecosystem);
        activity?.SetTag("dependably.operation", "package.publish");
        activity?.SetTag("dependably.tier", "registry");
        activity?.SetTag("dependably.tenant_id", request.OrgId);
        activity?.SetTag("dependably.org_id", request.OrgId);
        activity?.SetTag("dependably.purl", request.Purl);
        activity?.SetTag("dependably.size_bytes", ArtifactLength(request));

        var stopwatch = Stopwatch.StartNew();
        string outcome = "success";
        try
        {
            var result = await StoreAndRecordInnerAsync(request, ct);
            outcome = result is PublishResult.Accepted ? "success" : "client_error";
            if (result is PublishResult.Accepted)
            {
                SnapshotCounters.IncrementPublish();
            }

            return result;
        }
        catch (Exception ex)
        {
            outcome = "server_error";
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            throw;
        }
        finally
        {
            DependablyMeter.PublishDuration.Record(
                stopwatch.Elapsed.TotalSeconds,
                new KeyValuePair<string, object?>("ecosystem", request.Ecosystem),
                new KeyValuePair<string, object?>("outcome", outcome));

            if (outcome == "success")
            {
                DependablyMeter.PublishSizeBytes.Record(
                    ArtifactLength(request),
                    new KeyValuePair<string, object?>("ecosystem", request.Ecosystem));
            }

            activity?.SetTag("dependably.outcome", outcome);
        }
    }

    private async Task<PublishResult> StoreAndRecordInnerAsync(PublishRequest request, CancellationToken ct)
    {
        if (ValidatePathSafety(request) is { } pathReject)
        {
            return pathReject;
        }

        if (CheckSizeCap(request) is { } sizeReject)
        {
            return sizeReject;
        }

        // Claim gate. The PublishGate is no-op when CLAIM_ENFORCEMENT=off and when an
        // explicit local_only/mixed claim already exists. Errors come back as 409 from
        // the gate; we translate them into the service's structured Rejected shape.
        var claimReject = await _publishGate.CheckAsync(request.OrgId, request.Ecosystem, request.PurlName, ct);
        if (claimReject is not null)
        {
            return new PublishResult.Rejected(409, "claim_required",
                $"Name '{request.PurlName}' is unclaimed; create a 'local_only' or 'mixed' claim first.");
        }

        // Dedup vs overwrite. When AllowOverwrite is false (default) a duplicate
        // coordinate rejects with 409. When true, the existing row's artefact is replaced
        // in place and a package.replace audit event records both old and new hashes.
        string blobKey = BlobKeys.Hosted(request.OrgId, request.Ecosystem, request.PurlName, request.Version, request.Filename);
        var pkg = await _packages.GetOrCreateAsync(request.OrgId, request.Ecosystem, request.Name, request.PurlName, isProxy: false, ct);
        var existing = await _packages.GetVersionAsync(pkg.Id, request.Version, ct);
        if (existing is not null && !request.AllowOverwrite)
        {
            return new PublishResult.Rejected(409, "version_exists",
                $"Tarball parsed as {request.PurlName}@{request.Version}; that version already exists. " +
                "Delete it first or enable allow_version_overwrite.");
        }

        // Atomic quota reservation: reserves the net delta (new size minus replaced size)
        // against the counter before any bytes are written. 0 rows affected = quota exceeded.
        // SQLite's single-writer lock (busy_timeout=5000) serialises the reserve UPDATE, so
        // two publishes that each individually fit cannot both pass when their combined size
        // would exceed the cap. The reservation is released on any failure after this point.
        // When quota is null (unlimited), skip the reservation — no counter to maintain.
        long artifactLength = ArtifactLength(request);
        long delta = artifactLength - (existing?.SizeBytes ?? 0);
        long? quota = await _orgs.GetEffectiveStorageQuotaAsync(request.OrgId, ct);
        bool reserved = false;
        if (quota is not null)
        {
            if (!await _orgs.TryReserveStorageAsync(request.OrgId, delta, quota, ct))
            {
                return new PublishResult.Rejected(413, "tenant_quota_exceeded",
                    $"Tenant storage quota ({quota.Value} bytes) would be exceeded by this publish.");
            }
            reserved = true;
        }

        return await HashAndStoreBlobAsync(
            request,
            new PublishStorageContext(pkg, existing, blobKey, artifactLength, delta, reserved),
            ct);
    }

    // Resolved storage context for the write tail, bundled to keep HashAndStoreBlobAsync
    // within the parameter-count threshold (S107).
    private sealed record PublishStorageContext(
        Package Pkg, PackageVersion? Existing, string BlobKey,
        long ArtifactSizeBytes, long Delta, bool Reserved);

    // Resolves the artifact's SHA-256 (and npm SHA-1), opens the artifact stream, puts the blob,
    // commits the metadata and OSV scan, emits the audit record, and releases the quota
    // reservation on any failure to keep the storage counter accurate.
    private async Task<PublishResult> HashAndStoreBlobAsync(
        PublishRequest request, PublishStorageContext ctx, CancellationToken ct)
    {
        string sha256;
        string? sha1;
        Stream artifactStream;
        bool ownsStream = false;
        if (request.ArtifactStagingPath is { } stagingPath)
        {
            // Staged path: SHA-256 and SHA-1 computed by streaming the temp file once,
            // then the same file is re-opened for the blob put. Never materialises the
            // artifact as a byte[].
            (sha256, sha1) = await ComputeHashesFromFileAsync(stagingPath, request.Ecosystem, ct);
            // deepcode ignore PT: stagingPath is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
            artifactStream = new FileStream(
                stagingPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                bufferSize: 81920, useAsync: true);
            ownsStream = true;
        }
        else
        {
            // In-memory path for Cargo and Import callers that already hold bytes.
            byte[] bytes = request.ArtifactBytes!;
            sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            // npm's packument carries dist.shasum as hex SHA-1 — compute it here so
            // BuildNpmMetadata can emit the correct hash. NULL for non-npm rows; the column
            // is read by NpmController.{Build,Merge}*. Cheap (~500 MB/s); always compute.
            sha1 = request.Ecosystem == "npm"
                ? Convert.ToHexString(SHA1.HashData(bytes)).ToLowerInvariant()
                : null;
            artifactStream = new MemoryStream(bytes);
        }

        var registry = await _storage.GetRegistryAsync(request.OrgId, ct);
        try
        {
            await registry.PutAsync(ctx.BlobKey, artifactStream, ct);

            var newVersion = await CommitMetadataAsync(request, ctx.Pkg, ctx.Existing,
                new PersistedArtifact(ctx.BlobKey, sha256, sha1, ctx.ArtifactSizeBytes), registry, ct);
            await DetectInstallScriptQuietlyAsync(request, newVersion, ctx.BlobKey, registry, ct);
            await ScanQuietlyAsync(request, newVersion, ct);
            await _auditor.RecordAsync(request, sha256, ctx.Existing, ctx.ArtifactSizeBytes, ct);

            return new PublishResult.Accepted(newVersion.Id, request.Purl, sha256);
        }
        catch
        {
            // Release the reservation so the quota counter stays accurate when the
            // blob put or metadata commit fails. Fire-and-forget: a release failure
            // leaves the counter high (conservative — subsequent publishes are more
            // likely to 413), which is safer than leaving it low.
            if (ctx.Reserved)
            {
                try { await _orgs.ReleaseStorageAsync(request.OrgId, ctx.Delta, CancellationToken.None); }
                catch (Exception releaseEx)
                {
                    _logger.LogError(releaseEx,
                        "Quota counter release failed for org {OrgId} after publish failure; " +
                        "counter may be high until the next successful publish or manual reset. TraceId={TraceId}",
                        request.OrgId,
                        System.Diagnostics.Activity.Current?.TraceId.ToString());
                }
            }
            throw;
        }
        finally
        {
            if (ownsStream)
            {
                await artifactStream.DisposeAsync();
            }
        }
    }

    /// <summary>
    /// Dry-run companion to <see cref="StoreAndRecordAsync"/>. Runs the same
    /// validation chain — path safety, size cap, claim gate, dedup — but stops short of
    /// any write: no blob put, no version row, no audit emission. Uses
    /// <see cref="PackageRepository.GetByPurlNameAsync"/> in place of
    /// <c>GetOrCreateAsync</c> so the package row is not created as a side effect.
    /// On Accepted, <c>VersionId</c> is the empty string and <c>Sha256</c> is the
    /// computed digest of the candidate bytes.
    /// </summary>
    public async Task<PublishResult> ValidateAsync(PublishRequest request, CancellationToken ct = default)
    {
        if (ValidatePathSafety(request) is { } pathReject)
        {
            return pathReject;
        }

        if (CheckSizeCap(request) is { } sizeReject)
        {
            return sizeReject;
        }

        var claimReject = await _publishGate.CheckAsync(request.OrgId, request.Ecosystem, request.PurlName, ct);
        if (claimReject is not null)
        {
            return new PublishResult.Rejected(409, "claim_required",
                $"Name '{request.PurlName}' is unclaimed; create a 'local_only' or 'mixed' claim first.");
        }

        // Non-mutating lookup. If the package row doesn't exist yet, the version can't
        // either, so dedup passes implicitly.
        var pkg = await _packages.GetByPurlNameAsync(request.OrgId, request.Ecosystem, request.PurlName, ct);
        if (pkg is not null)
        {
            var existing = await _packages.GetVersionAsync(pkg.Id, request.Version, ct);
            if (existing is not null && !request.AllowOverwrite)
            {
                return new PublishResult.Rejected(409, "version_exists",
                    $"Tarball parsed as {request.PurlName}@{request.Version}; that version already exists. " +
                    "Delete it first or enable allow_version_overwrite.");
            }
        }

        string sha256 = request.ArtifactStagingPath is { } stagePath
            ? (await ComputeHashesFromFileAsync(stagePath, request.Ecosystem, ct)).Sha256
            : Convert.ToHexString(SHA256.HashData(request.ArtifactBytes!)).ToLowerInvariant();
        return new PublishResult.Accepted(VersionId: "", request.Purl, sha256);
    }

    // Path safety on the components that land verbatim in path positions. Name is
    // intentionally not validated by PathSafeValidator: npm scoped names ("@scope/name")
    // legitimately contain a slash, and per-ecosystem callers do their own format
    // validation (PEP 508, NuGet id charset, npm name regex) before reaching the service.
    // PurlName / Name still need a traversal + separator guard: '..' and NUL always reject,
    // and path separators reject except npm's single leading '@scope/' segment — names land
    // verbatim in the hosted blob key, so a stray '/' would inject extra key segments.
    private static PublishResult.Rejected? ValidatePathSafety(PublishRequest request)
    {
        foreach (var (value, kind) in new[]
        {
            (request.Version, "version"),
            (request.Filename, "filename")
        })
        {
            var safe = PathSafeValidator.Validate(value, kind);
            if (!safe.IsValid)
            {
                return new PublishResult.Rejected(422, "path_unsafe", safe.Message ?? "Unsafe value.");
            }
        }

        return request.Name.Contains("..") || request.PurlName.Contains("..")
            || request.Name.Contains('\0') || request.PurlName.Contains('\0')
            ? new PublishResult.Rejected(422, "path_unsafe", "Name must not contain '..' or null bytes.")
            : HasUnsafeSeparator(request.Ecosystem, request.Name)
              || HasUnsafeSeparator(request.Ecosystem, request.PurlName)
            ? new PublishResult.Rejected(422, "path_unsafe",
                "Name must not contain path separators (npm permits a single leading '@scope/').")
            : null;
    }

    // npm scoped names contain exactly one slash, after a leading '@' and with non-empty
    // segments on both sides. Every other ecosystem's name is a single path segment in the
    // hosted blob key, so any separator is unsafe.
    private static bool HasUnsafeSeparator(string ecosystem, string value)
    {
        int slash = value.IndexOf('/');
        return value.Contains('\\')
            || (slash >= 0
                && (ecosystem != "npm"
                    || !value.StartsWith('@')
                    || slash != value.LastIndexOf('/')
                    || slash < NpmScopeMinSlashPosition
                    || slash == value.Length - 1));
    }

    // Artifact byte count regardless of which path (in-memory or staged) is active.
    private static long ArtifactLength(PublishRequest request)
        => request.ArtifactStagingPath is not null
            ? request.ArtifactSizeBytes
            : request.ArtifactBytes!.LongLength;

    // Size cap. Callers know per-tenant + per-ecosystem cap; we enforce as a final
    // safety net so no single path can write a too-large blob even if a caller forgets.
    private static PublishResult.Rejected? CheckSizeCap(PublishRequest request)
    {
        return ArtifactLength(request) > request.SizeCap
            ? new PublishResult.Rejected(413, "size_limit_exceeded",
                $"File exceeds the {request.Ecosystem} upload size limit ({request.SizeCap} bytes).")
            : null;
    }

    // Computes SHA-256 and (for npm) SHA-1 by streaming a staged temp file once.
    // Never materialises the artifact in managed memory.
    private static async Task<(string Sha256, string? Sha1)> ComputeHashesFromFileAsync(
        string path, string ecosystem, CancellationToken ct)
    {
        // deepcode ignore PT: path is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
        await using var fs = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 81920, useAsync: true);
        using var sha256Alg = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var sha1Alg = ecosystem == "npm"
            ? IncrementalHash.CreateHash(HashAlgorithmName.SHA1)
            : null;
        try
        {
            byte[] buffer = new byte[81920];
            int read;
            while ((read = await fs.ReadAsync(buffer, ct)) > 0)
            {
                sha256Alg.AppendData(buffer, 0, read);
                sha1Alg?.AppendData(buffer, 0, read);
            }
            string sha256 = Convert.ToHexString(sha256Alg.GetHashAndReset()).ToLowerInvariant();
            string? sha1 = sha1Alg is not null
                ? Convert.ToHexString(sha1Alg.GetHashAndReset()).ToLowerInvariant()
                : null;
            return (sha256, sha1);
        }
        finally
        {
            sha1Alg?.Dispose();
        }
    }

    // Metadata commit, with compensating blob delete on failure.
    // Blob and DB live in different stores (no shared transaction), so an exception
    // out of the version-row write would otherwise leave an orphan hosted blob. For
    // the INSERT path we can safely delete the just-put blob to compensate — nothing
    // else references it yet. For the OVERWRITE path the put was destructive (same
    // blob_key as the prior version, old bytes already replaced); a compensating
    // delete here would erase the new bytes too, leaving the existing row pointing
    // at a now-missing key. We log loudly instead so an operator can re-publish.
    // A background orphan-blob reconciler is the follow-up that closes the SIGKILL
    // window (#TBD); the try/catch here closes the application-exception window.
    private async Task<PackageVersion> CommitMetadataAsync(PublishRequest request, Package pkg,
        PackageVersion? existing, PersistedArtifact artifact, IBlobStore registry, CancellationToken ct)
    {
        try
        {
            if (existing is not null)
            {
                // Overwrite path: keep the same id so dependent rows (vulns, licenses) follow.
                // vuln_checked_at is reset by the repository so the next scan re-checks the new
                // bytes — the prior scan applied to a hash that's no longer in the blob store.
                // checksum_sha1 follows the new bytes (npm) — otherwise the packument would
                // emit a stale SHA-1 next request.
                await _packages.UpdateVersionForOverwriteAsync(existing.Id, artifact.BlobKey,
                    artifact.SizeBytes, artifact.Sha256, request.Origin, artifact.Sha1, ct);
                return (await _packages.GetVersionAsync(pkg.Id, request.Version, ct))!;
            }
            return await _packages.CreateVersionAsync(
                new NewPackageVersion(pkg.Id, request.Version, request.Purl, artifact.BlobKey,
                    artifact.SizeBytes, artifact.Sha256, Origin: request.Origin,
                    ChecksumSha1: artifact.Sha1), ct);
        }
        catch (Exception ex) when (existing is null)
        {
            _logger.LogWarning(ex,
                "Metadata write failed after blob put on INSERT path; compensating delete for {BlobKey}",
                artifact.BlobKey);
            try { await registry.DeleteAsync(artifact.BlobKey, CancellationToken.None); }
            catch (Exception delEx)
            {
                _logger.LogError(delEx,
                    "Compensating blob delete failed for {BlobKey}; orphan requires reconciliation",
                    artifact.BlobKey);
            }
            throw;
        }
        catch (Exception ex)
        {
            // OVERWRITE failure: cannot compensate without erasing the new bytes the put
            // already committed. The row still points at the prior sha256 but the bytes
            // are now the new ones — integrity divergence until the publisher retries.
            _logger.LogError(ex,
                "Metadata write failed after blob put on OVERWRITE path; row {VersionId} now diverges from blob {BlobKey}. Retry the publish to converge.",
                existing!.Id, artifact.BlobKey);
            throw;
        }
    }

    private sealed record PersistedArtifact(string BlobKey, string Sha256, string? Sha1, long SizeBytes);

    // Parity with proxy first-fetch (see NpmController/PyPiController/NuGetController
    // post-RecordOrLookupProxyVersionAsync): scan the new bytes synchronously so the
    // Unscanned banner clears before the publisher's request returns. Custom names OSV
    // doesn't know about resolve to zero advisories → status "clean", same path as a
    // public package with no known issues. Failures are swallowed so a transient OSV
    // outage cannot fail an otherwise valid publish; the scheduled pass retries later.
    // Install/lifecycle-script detection on the just-stored artefact. Re-opens the registry blob
    // (the artifact stream was already consumed by the put) and persists the signal. Best-effort:
    // a backend or parse failure leaves has_install_script at its default rather than failing an
    // otherwise valid publish. Always writes the result (including a negative on overwrite) so a
    // republished, now-script-free artefact clears a stale flag.
    private async Task DetectInstallScriptQuietlyAsync(
        PublishRequest request, PackageVersion newVersion, string blobKey, IBlobStore registry, CancellationToken ct)
    {
        try
        {
            await using var stream = await registry.GetAsync(blobKey, ct);
            if (stream is null)
            {
                return;
            }

            var script = await ScriptDetectionService.DetectAsync(
                request.Ecosystem, request.Filename, stream, ct);
            await _packages.UpdateInstallScriptAsync(newVersion.Id, script.HasScript, script.Kind, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "Install-script detection failed for {Purl}; signal left at its default.", request.Purl);
        }
    }

    private async Task ScanQuietlyAsync(PublishRequest request, PackageVersion newVersion, CancellationToken ct)
    {
        try
        {
            await _scanner.ScanVersionAsync(request.Purl, newVersion.Id, request.Ecosystem,
                request.PurlName, request.OrgId, request.ActorUserId, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Post-publish vuln scan failed for {Purl}; scheduled pass will retry.", request.Purl);
        }
    }
}
