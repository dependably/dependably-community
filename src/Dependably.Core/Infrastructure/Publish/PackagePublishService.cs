using System.Diagnostics;
using System.Security.Cryptography;
using Dependably.Infrastructure.Edge;
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
    private readonly PackageVersionFilesRepository _versionFiles;
    private readonly OrgRepository _orgs;
    private readonly ITenantStorageResolver _storage;
    private readonly PublishGate _publishGate;
    private readonly EdgePublishGuard _edgeGuard;
    private readonly PublishAuditor _auditor;
    private readonly VulnerabilityScanService _scanner;
    private readonly LicenseRepository _licenses;
    private readonly ILogger<PackagePublishService> _logger;

    // Each parameter is a distinct DI-registered collaborator this shared publish tail
    // depends on directly; grouping them into a wrapper type would just move the coupling
    // without reducing it.
#pragma warning disable S107 // constructor injection of independently-registered DI services
    public PackagePublishService(
        PackageRepository packages,
        PackageVersionFilesRepository versionFiles,
        OrgRepository orgs,
        ITenantStorageResolver storage,
        PublishGate publishGate,
        EdgePublishGuard edgeGuard,
        PublishAuditor auditor,
        VulnerabilityScanService scanner,
        LicenseRepository licenses,
        ILogger<PackagePublishService> logger)
#pragma warning restore S107
    {
        _packages = packages;
        _versionFiles = versionFiles;
        _orgs = orgs;
        _edgeGuard = edgeGuard;
        // Published artefacts always land on the registry tier, resolved per-tenant so
        // enterprise deployments route to the tenant's silo bucket. Community pool mode
        // returns the singleton registry regardless. The resolver gates on lifecycle
        // status + provisioning state — a suspended/archived tenant or a half-initialized
        // bucket raises TenantNotReadyException before any blob bytes are written.
        _storage = storage;
        _publishGate = publishGate;
        _auditor = auditor;
        _scanner = scanner;
        _licenses = licenses;
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
        // Fail-closed on an edge node: a cache edge holds no durable registry tier, so every
        // publish/push/import is refused before any validation or blob write. Non-edge: no-op.
        if (_edgeGuard.RejectPublish() is { } edgeReject)
        {
            return edgeReject;
        }

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

        // Dedup vs overwrite. Resolution is policy-driven (org tri-state + per-package override).
        // ResolveOverwriteAllowed returns true only when the effective combination permits it.
        string blobKey = BlobKeys.Hosted(request.OrgId, request.Ecosystem, request.PurlName, request.Version, request.Filename);
        var pkg = await _packages.GetOrCreateAsync(request.OrgId, request.Ecosystem, request.Name, request.PurlName, isProxy: false, ct);
        var existing = await _packages.GetVersionAsync(pkg.Id, request.Version, ct);
        var settings = await _orgs.GetSettingsAsync(request.OrgId, ct);

        // License hard-block. Runs before any dedup/quota/blob work so a blocked publish never
        // reaches the version-row write — the caller's PublishRequest.Licenses carries whatever
        // the format-specific extractor already pulled from the artifact (wheel METADATA, npm
        // tarball/packument, .nuspec, Cargo publish envelope). Strictly guarded by 'block': under
        // 'warn'/'off', or when the caller passed no license signal, this reads nothing extra.
        if (await CheckLicensePolicyAsync(request, settings, ct) is { } licenseReject)
        {
            return licenseReject;
        }

        // PyPI stores multiple distribution files per (name, version) — wheel + sdist +
        // per-platform wheels, the model pypi.org exposes. An upload whose filename is not
        // yet part of the existing version is a NEW file of the same release, not an
        // overwrite, so it bypasses the same-version-push policy (which protects artifact
        // immutability, not release completeness). Re-uploading a filename the version
        // already holds is a true overwrite and stays policy-gated. Every other ecosystem
        // keeps the one-artifact-per-version model and its filename-mismatch guard.
        var (existingFile, pypiAddsNewFile) = await ResolvePypiFileSlotAsync(request, existing, ct);

        if (existing is not null && !pypiAddsNewFile
            && !ResolveOverwriteAllowed(settings?.VersionOverwritePolicy, pkg.SameVersionPushOverride))
        {
            return new PublishResult.Rejected(409, "version_exists",
                $"Tarball parsed as {request.PurlName}@{request.Version}; that version already exists. " +
                "Same-version push is blocked by this package's policy.");
        }

        if (request.Ecosystem != "pypi"
            && ArtifactFilenameMismatch(existing, request.Filename) is { } filenameMismatch)
        {
            return filenameMismatch;
        }

        // Atomic quota reservation: reserves the net delta (new size minus replaced size)
        // against the counter before any bytes are written. 0 rows affected = quota exceeded.
        // SQLite's single-writer lock (busy_timeout=5000) serialises the reserve UPDATE, so
        // two publishes that each individually fit cannot both pass when their combined size
        // would exceed the cap. The reservation is released on any failure after this point.
        // When quota is null (unlimited), skip the reservation — no counter to maintain.
        // PyPI accounts at file granularity: a new file of an existing version replaces
        // nothing; an overwrite replaces exactly the prior bytes of that filename.
        long artifactLength = ArtifactLength(request);
        long replacedBytes = request.Ecosystem == "pypi"
            ? existingFile?.SizeBytes ?? 0
            : existing?.SizeBytes ?? 0;
        long delta = artifactLength - replacedBytes;
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
            new PublishStorageContext(pkg, existing, existingFile, blobKey, artifactLength, delta, reserved),
            ct);
    }

    // Probes the per-file slot for a PyPI same-version upload: returns the file record the
    // incoming filename would overwrite (null when the filename is new to the version), and
    // whether this upload ADDS a file rather than overwriting one. Non-PyPI ecosystems and
    // first uploads of a version always resolve to (null, false).
    private async Task<(PackageVersionFile? ExistingFile, bool AddsNewFile)> ResolvePypiFileSlotAsync(
        PublishRequest request, PackageVersion? existing, CancellationToken ct)
    {
        if (existing is null || request.Ecosystem != "pypi")
        {
            return (null, false);
        }

        var file = await _versionFiles.GetByVersionAndFilenameAsync(existing.Id, request.Filename, ct);
        return (file, file is null);
    }

    // Resolved storage context for the write tail, bundled to keep HashAndStoreBlobAsync
    // within the parameter-count threshold (S107).
    private sealed record PublishStorageContext(
        Package Pkg, PackageVersion? Existing, PackageVersionFile? ExistingFile, string BlobKey,
        long ArtifactSizeBytes, long Delta, bool Reserved);

    // Resolves the artifact's SHA-256 (and npm SHA-1), opens the artifact stream, puts the blob,
    // commits the metadata and OSV scan, emits the audit record, and releases the quota
    // reservation on any failure to keep the storage counter accurate.
    private async Task<PublishResult> HashAndStoreBlobAsync(
        PublishRequest request, PublishStorageContext ctx, CancellationToken ct)
    {
        string sha256;
        string? sha1;
        string? sha512Sri;
        Stream artifactStream;
        bool ownsStream = false;
        if (request.ArtifactStagingPath is { } stagingPath)
        {
            // Staged path: SHA-256, SHA-1, and the sha512 SRI computed by streaming the temp
            // file once, then the same file is re-opened for the blob put. Never materialises
            // the artifact as a byte[].
            (sha256, sha1, sha512Sri) = await ComputeHashesFromFileAsync(stagingPath, request.Ecosystem, ct);
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
            // sha512 SRI for the packument's dist.integrity — same npm-only rule as SHA-1.
            sha512Sri = request.Ecosystem == "npm"
                ? "sha512-" + Convert.ToBase64String(SHA512.HashData(bytes))
                : null;
            artifactStream = new MemoryStream(bytes);
        }

        // The publisher's verbatim dist.integrity claim wins (it is what the publishing
        // client computed over the same bytes it uploaded); the server-computed SRI covers
        // clients that sent none (and the in-repo import path, which has no publish body).
        string? integritySri = request.DeclaredIntegritySri ?? sha512Sri;

        var registry = await _storage.GetRegistryAsync(request.OrgId, ct);
        try
        {
            await registry.PutAsync(ctx.BlobKey, artifactStream, ct);

            var newVersion = await CommitMetadataAsync(request, ctx,
                new PersistedArtifact(ctx.BlobKey, sha256, sha1, integritySri, ctx.ArtifactSizeBytes), registry, ct);
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
        // Fail-closed on an edge node: the bulk-import pre-validation surface refuses too, so an
        // operator never sees a "would-accept" projection for a publish an edge cannot perform.
        if (_edgeGuard.RejectPublish() is { } edgeReject)
        {
            return edgeReject;
        }

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

        if (await CheckDedupForValidateAsync(request, ct) is { } dedupReject)
        {
            return dedupReject;
        }

        string sha256 = request.ArtifactStagingPath is { } stagePath
            ? (await ComputeHashesFromFileAsync(stagePath, request.Ecosystem, ct)).Sha256
            : Convert.ToHexString(SHA256.HashData(request.ArtifactBytes!)).ToLowerInvariant();
        return new PublishResult.Accepted(VersionId: "", request.Purl, sha256);
    }

    // Dry-run dedup projection: mirrors StoreAndRecordInnerAsync's version-exists and
    // filename-mismatch gates without any write. A PyPI upload adding a filename the version
    // does not yet hold is a new file of the release, not an overwrite. Non-mutating lookup —
    // if the package row doesn't exist yet, the version can't either, so dedup passes
    // implicitly.
    private async Task<PublishResult.Rejected?> CheckDedupForValidateAsync(
        PublishRequest request, CancellationToken ct)
    {
        var pkg = await _packages.GetByPurlNameAsync(request.OrgId, request.Ecosystem, request.PurlName, ct);
        if (pkg is null)
        {
            return null;
        }

        var existing = await _packages.GetVersionAsync(pkg.Id, request.Version, ct);
        if (existing is null)
        {
            return null;
        }

        var (_, pypiAddsNewFile) = await ResolvePypiFileSlotAsync(request, existing, ct);
        var settings = await _orgs.GetSettingsAsync(request.OrgId, ct);
        return !pypiAddsNewFile
            && !ResolveOverwriteAllowed(settings?.VersionOverwritePolicy, pkg.SameVersionPushOverride)
            ? new PublishResult.Rejected(409, "version_exists",
                $"Tarball parsed as {request.PurlName}@{request.Version}; that version already exists. " +
                "Same-version push is blocked by this package's policy.")
            : request.Ecosystem != "pypi"
                ? ArtifactFilenameMismatch(existing, request.Filename)
                : null;
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

    // Resolves whether a same-version overwrite is permitted given the org-level policy
    // and the per-package override. The resolution matrix is:
    //   org 'block'     -> always false  (hard lockdown; per-package overrides ignored)
    //   org 'exception' -> pkgOverride == 'allow'  (blocked by default; package can grant)
    //   org 'allow'     -> pkgOverride != 'block'  (allowed by default; package can deny)
    internal static bool ResolveOverwriteAllowed(string? orgPolicy, string? pkgOverride)
        => (orgPolicy ?? "block") switch
        {
            "allow" => pkgOverride != "block",
            "exception" => pkgOverride == "allow",
            _ => false,
        };

    // One artifact per (package, version): a same-version push whose filename differs from
    // the stored artifact's filename is rejected outright, even when the org's overwrite
    // policy would otherwise allow a same-version push. Without this guard, an overwrite
    // silently repoints the existing version row's blob_key at a differently-named artifact
    // (e.g. a wheel's version row ending up pointing at an sdist's bytes) while the row's
    // filename column — and every URL already advertising it — keeps naming the original
    // file. Coexisting wheel+sdist artifacts for one version are a distinct, larger feature
    // (a multi-file version model) and out of scope here; this only closes the silent
    // corruption path.
    private static PublishResult.Rejected? ArtifactFilenameMismatch(PackageVersion? existing, string incomingFilename)
    {
        if (existing is null)
        {
            return null;
        }

        string existingFilename = PackageRepository.DeriveFilename(existing.BlobKey);
        return !existingFilename.Equals(incomingFilename, StringComparison.Ordinal)
            ? new PublishResult.Rejected(409, "artifact_mismatch",
                $"Version {existing.Version} already exists under filename '{existingFilename}'; " +
                $"'{incomingFilename}' is a different artifact. Only one artifact per (package, version) is supported.")
            : null;
    }

    // License hard-block, governed by the existing org_settings.license_enforcement_mode
    // ('off'/'warn'/'block'). Only 'block' can reject; 'warn'/'off' never touch this path.
    // request.Licenses may carry a whole compound expression per entry — CheckPolicyAsync
    // evaluates OR/AND semantics and normalizes both the observed leaves and the stored
    // allow/block entries before comparing, mirroring the serve-path license arm.
    private async Task<PublishResult.Rejected?> CheckLicensePolicyAsync(
        PublishRequest request, OrgSettings? settings, CancellationToken ct)
    {
        if (settings?.LicenseEnforcementMode != "block" || request.Licenses is not { Count: > 0 } licenses)
        {
            return null;
        }

        var (allowed, blockedLicense) = await _licenses.CheckPolicyAsync(request.OrgId, "block", licenses, ct);
        return allowed
            ? null
            : new PublishResult.Rejected(403, "license_blocked",
                $"License '{blockedLicense}' is not permitted by this org's license policy.");
    }

    // Size cap. Callers know per-tenant + per-ecosystem cap; we enforce as a final
    // safety net so no single path can write a too-large blob even if a caller forgets.
    private static PublishResult.Rejected? CheckSizeCap(PublishRequest request)
    {
        return ArtifactLength(request) > request.SizeCap
            ? new PublishResult.Rejected(413, "size_limit_exceeded",
                $"File exceeds the {request.Ecosystem} upload size limit ({request.SizeCap} bytes).")
            : null;
    }

    // Computes SHA-256 and (for npm) SHA-1 plus a sha512 SRI by streaming a staged temp
    // file once. Never materialises the artifact in managed memory. The SRI backs the
    // packument's dist.integrity when the publish body carried no publisher-declared value.
    private static async Task<(string Sha256, string? Sha1, string? Sha512Sri)> ComputeHashesFromFileAsync(
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
        var sha512Alg = ecosystem == "npm"
            ? IncrementalHash.CreateHash(HashAlgorithmName.SHA512)
            : null;
        try
        {
            byte[] buffer = new byte[81920];
            int read;
            while ((read = await fs.ReadAsync(buffer, ct)) > 0)
            {
                sha256Alg.AppendData(buffer, 0, read);
                sha1Alg?.AppendData(buffer, 0, read);
                sha512Alg?.AppendData(buffer, 0, read);
            }
            string sha256 = Convert.ToHexString(sha256Alg.GetHashAndReset()).ToLowerInvariant();
            string? sha1 = sha1Alg is not null
                ? Convert.ToHexString(sha1Alg.GetHashAndReset()).ToLowerInvariant()
                : null;
            string? sha512Sri = sha512Alg is not null
                ? "sha512-" + Convert.ToBase64String(sha512Alg.GetHashAndReset())
                : null;
            return (sha256, sha1, sha512Sri);
        }
        finally
        {
            sha1Alg?.Dispose();
            sha512Alg?.Dispose();
        }
    }

    // Metadata commit, with compensating blob delete on failure.
    // Blob and DB live in different stores (no shared transaction), so an exception
    // out of the version-row write would otherwise leave an orphan hosted blob. For
    // paths that wrote a FRESH blob key (new version, or a new PyPI file of an existing
    // version) we can safely delete the just-put blob to compensate — nothing else
    // references it yet. For the OVERWRITE paths the put was destructive (same
    // blob_key as the prior artifact, old bytes already replaced); a compensating
    // delete here would erase the new bytes too, leaving the existing row pointing
    // at a now-missing key. We log loudly instead so an operator can re-publish.
    // A background orphan-blob reconciler is the follow-up that closes the SIGKILL
    // window; the try/catch here closes the application-exception window.
    private async Task<PackageVersion> CommitMetadataAsync(PublishRequest request, PublishStorageContext ctx,
        PersistedArtifact artifact, IBlobStore registry, CancellationToken ct)
    {
        var existing = ctx.Existing;
        // A fresh blob key means nothing referenced it before this publish, so the blob
        // is deletable on a failed metadata write. Both overwrite shapes reuse the prior
        // artifact's key and are NOT compensable.
        bool freshBlob = existing is null || (request.Ecosystem == "pypi" && ctx.ExistingFile is null);
        try
        {
            if (existing is not null)
            {
                return await CommitToExistingVersionAsync(request, ctx, existing, artifact, ct);
            }

            var created = await _packages.CreateVersionAsync(
                new NewPackageVersion(ctx.Pkg.Id, request.Version, request.Purl, artifact.BlobKey,
                    artifact.SizeBytes, artifact.Sha256, Origin: request.Origin,
                    ChecksumSha1: artifact.Sha1,
                    UpstreamIntegrityValue: artifact.IntegritySri,
                    UpstreamIntegrityAlgorithm: artifact.IntegritySri is not null ? "sha512-sri" : null,
                    ManifestJson: request.ManifestJson), ct);
            if (request.Ecosystem == "pypi")
            {
                await AddFirstPypiFileWithRollbackAsync(request, created, artifact, ct);
            }
            return created;
        }
        catch (Exception ex) when (freshBlob)
        {
            // A uniqueness violation means a CONCURRENT publish of the same coordinate won
            // the insert race — and both publishes PutAsync the SAME hosted blob key, so the
            // "fresh" blob is now referenced by the winner's committed row. Deleting it here
            // would 404 the winner's artifact; skip the compensation and let the loser's
            // failure propagate (a retry resolves against the now-existing row/file).
            bool blobSharedWithRaceWinner = IsUniqueViolation(ex);
            _logger.LogWarning(ex,
                "Metadata write failed after blob put on INSERT path for {BlobKey}; " +
                "compensating delete {Action}",
                artifact.BlobKey,
                blobSharedWithRaceWinner ? "skipped (blob shared with concurrent-publish winner)" : "attempted");
            if (!blobSharedWithRaceWinner)
            {
                try { await registry.DeleteAsync(artifact.BlobKey, CancellationToken.None); }
                catch (Exception delEx)
                {
                    _logger.LogError(delEx,
                        "Compensating blob delete failed for {BlobKey}; orphan requires reconciliation",
                        artifact.BlobKey);
                }
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

    // Records the first file of a new PyPI release. A failed file-row insert must not leave
    // a version row with zero files — delete the ROW before the caller's outer compensation
    // removes the blob. Row-only delete: this publish's own quota reservation is released by
    // HashAndStoreBlobAsync's catch, so the counter-coupled DeleteVersionAsync would decrement
    // the tenant counter a second time.
    private async Task AddFirstPypiFileWithRollbackAsync(
        PublishRequest request, PackageVersion created, PersistedArtifact artifact, CancellationToken ct)
    {
        try
        {
            await _versionFiles.AddAsync(created.Id, request.OrgId, request.Filename,
                artifact.BlobKey, artifact.SizeBytes, artifact.Sha256, ct);
        }
        catch
        {
            try { await _packages.DeleteVersionRowForPublishRollbackAsync(created.Id, CancellationToken.None); }
            catch (Exception rollbackEx)
            {
                _logger.LogError(rollbackEx,
                    "Version-row rollback failed for {VersionId} after file-record insert failure",
                    created.Id);
            }
            throw;
        }
    }

    // Same-version commit: PyPI adds or overwrites one file record of the release; every
    // other ecosystem overwrites the version row's single artifact.
    private async Task<PackageVersion> CommitToExistingVersionAsync(
        PublishRequest request, PublishStorageContext ctx, PackageVersion existing,
        PersistedArtifact artifact, CancellationToken ct)
    {
        if (request.Ecosystem == "pypi" && ctx.ExistingFile is null)
        {
            // New distribution file of an existing PyPI release (e.g. the sdist joining the
            // wheel). The version row keeps its identity and primary-artifact columns; the
            // repository refreshes the row's size sum and resets its scan state so the next
            // OSV pass covers the new bytes.
            await _versionFiles.AddAsync(existing.Id, request.OrgId, request.Filename,
                artifact.BlobKey, artifact.SizeBytes, artifact.Sha256, ct);
            return (await _packages.GetVersionAsync(ctx.Pkg.Id, request.Version, ct))!;
        }

        // Overwrite path: keep the same id so dependent rows (vulns, licenses) follow.
        // vuln_checked_at is reset by the repository so the next scan re-checks the new
        // bytes — the prior scan applied to a hash that's no longer in the blob store.
        // checksum_sha1, the integrity SRI, and the stored manifest all follow the new
        // bytes (npm) — otherwise the packument would emit stale metadata next request.
        // For PyPI the version row's artifact columns follow only when the overwritten
        // filename IS the row's primary artifact; a non-primary overwrite touches the
        // file record alone (which also restores the row's size sum afterwards).
        bool updateVersionRow = request.Ecosystem != "pypi"
            || PackageRepository.DeriveFilename(existing.BlobKey).Equals(request.Filename, StringComparison.Ordinal);
        if (updateVersionRow)
        {
            await _packages.UpdateVersionForOverwriteAsync(existing.Id, artifact.BlobKey,
                artifact.SizeBytes, artifact.Sha256, request.Origin, artifact.Sha1,
                integrityValue: artifact.IntegritySri,
                integrityAlgorithm: artifact.IntegritySri is not null ? "sha512-sri" : null,
                manifestJson: request.ManifestJson, ct: ct);
        }

        if (request.Ecosystem == "pypi" && ctx.ExistingFile is not null)
        {
            await _versionFiles.UpdateForOverwriteAsync(ctx.ExistingFile.Id, artifact.BlobKey,
                artifact.SizeBytes, artifact.Sha256, ct);
        }

        return (await _packages.GetVersionAsync(ctx.Pkg.Id, request.Version, ct))!;
    }

    // SQLITE_CONSTRAINT (19) / PostgreSQL unique_violation (23505): the row this publish
    // tried to insert already exists — a concurrent publish of the same coordinate won the
    // race. Used to decide whether the just-put blob is genuinely fresh (deletable) or
    // shared with the race winner's committed row.
    private static bool IsUniqueViolation(Exception ex) =>
        ex is Microsoft.Data.Sqlite.SqliteException { SqliteErrorCode: 19 }
            or System.Data.Common.DbException { SqlState: "23505" };

    private sealed record PersistedArtifact(
        string BlobKey, string Sha256, string? Sha1, string? IntegritySri, long SizeBytes);

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
