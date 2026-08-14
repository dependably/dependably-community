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
    private readonly NameBindingGate _nameBinding;
    private readonly VersionTombstoneRepository _tombstones;
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
        NameBindingGate nameBinding,
        VersionTombstoneRepository tombstones,
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
        _nameBinding = nameBinding;
        _tombstones = tombstones;
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

        // now-ok: measures real elapsed time for a duration log/metric only — no control
        // flow branches on the value, so a substitutable clock would change the reported
        // number without changing what the code does.
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

        // Name-level publish authorization. Keys on the authenticated principal (never a request
        // field), so a token scoped only to publish this ecosystem cannot seize a name a
        // different principal already owns.
        if (await NameBindingRejectionAsync(request, ct) is { } nameReject)
        {
            return nameReject;
        }

        // Dedup vs overwrite. Resolution is policy-driven (org tri-state + per-package override).
        // ResolveOverwriteAllowed returns true only when the effective combination permits it.
        var pkg = await _packages.GetOrCreateAsync(request.OrgId, request.Ecosystem, request.Name, request.PurlName, isProxy: false, ct);
        // Refresh the package's presentation metadata from this publish's manifest. COALESCE
        // semantics mean a manifest that omits a field never clears an earlier value.
        await _packages.UpdateMetadataAsync(pkg.Id, request.Homepage, request.Repository, request.Description, ct);
        var existing = await _packages.GetVersionAsync(pkg.Id, request.Version, ct);
        var settings = await _orgs.GetSettingsAsync(request.OrgId, ct);

        // License hard-block. Runs before any dedup/quota/blob work so a blocked publish never
        // reaches the version-row write — the caller's PublishRequest.Licenses carries whatever
        // the format-specific extractor already pulled from the artifact (wheel METADATA, npm
        // tarball/packument, .nuspec, Cargo publish envelope). A declared license is gated by
        // 'block'-only org_settings.license_enforcement_mode (the serve-path mode); no declared
        // license at all is gated separately by org_settings.license_publish_enforcement_mode,
        // which defaults 'off' and never touches the serve-path mode.
        if (await CheckLicensePolicyAsync(request, settings, ct) is { } licenseReject)
        {
            return licenseReject;
        }

        // Multi-file ecosystems store several artefacts under one version row — PyPI's
        // sdist + per-platform wheels, NuGet's .nupkg + .snupkg (see MultiFileEcosystems).
        // An upload whose filename is not yet part of the existing version is a NEW file of
        // the same release, not an overwrite, so it bypasses the same-version-push policy
        // (which protects artifact immutability, not release completeness). Re-uploading a
        // filename the version already holds is a true overwrite and stays policy-gated.
        // Every other ecosystem keeps the one-artifact-per-version model and its
        // filename-mismatch guard.
        var (existingFile, addsNewFile) = await ResolveVersionFileSlotAsync(request, existing, ct);
        bool overwriteAllowed = ResolveOverwriteAllowed(
            settings?.VersionOverwritePolicy, pkg.SameVersionPushOverride);

        if (await CheckVersionAdmissionAsync(request, existing, addsNewFile, overwriteAllowed, ct) is { } admissionReject)
        {
            return admissionReject;
        }

        // Quota reservation: claims the net delta (new size minus replaced size) against the
        // tenant's ceiling before any bytes are written — the same gate, reading the same derived
        // org_storage_bytes sum and charging the same in-flight ledger, that OCI push and the
        // proxy cache fill go through. Two publishes that each individually fit therefore cannot
        // both pass when their combined size would exceed the cap, and neither can a publish
        // racing a proxy fill. Held until the version row is committed — that commit is what makes
        // these bytes visible to the sum — and released by the same `using` on any failure.
        // Multi-file ecosystems account at file granularity: a new file of an existing version
        // replaces nothing; an overwrite replaces exactly the prior bytes of that filename.
        long artifactLength = ArtifactLength(request);
        long replacedBytes = MultiFileEcosystems.Covers(request.Ecosystem)
            ? existingFile?.SizeBytes ?? 0
            : existing?.SizeBytes ?? 0;
        long delta = artifactLength - replacedBytes;
        long? quota = await _orgs.GetEffectiveStorageQuotaAsync(request.OrgId, ct);
        using var reservation = await _orgs.TryReserveStorageAsync(request.OrgId, delta, quota, ct);
        if (reservation is null)
        {
            return new PublishResult.Rejected(413, "tenant_quota_exceeded",
                $"Tenant storage quota ({quota!.Value} bytes) would be exceeded by this publish.");
        }

        var result = await HashAndStoreBlobAsync(
            request,
            new PublishStorageContext(pkg, existing, existingFile, artifactLength),
            ct);

        // Record first-publisher ownership only after the artifact is durably stored, so a
        // publish that fails a later step never leaves a stray binding (and tombstone) behind.
        if (result is PublishResult.Accepted && NameBindingEcosystems.Covers(request.Ecosystem))
        {
            await _nameBinding.RecordOwnershipAsync(
                request.OrgId, request.Ecosystem, request.PurlName, PrincipalOf(request), ct);
        }

        return result;
    }

    /// <summary>
    /// The three checks that gate whether this (existing-version, overwrite-policy) combination
    /// may proceed: same-version-push policy, the tombstone-of-a-hard-deleted-coordinate gate one
    /// step further back, and the filename-mismatch guard for single-artifact-per-version
    /// ecosystems. Runs before the quota reservation and the blob write.
    /// </summary>
    private async Task<PublishResult.Rejected?> CheckVersionAdmissionAsync(
        PublishRequest request, PackageVersion? existing, bool addsNewFile, bool overwriteAllowed, CancellationToken ct)
    {
        if (existing is not null && !addsNewFile && !overwriteAllowed)
        {
            return new PublishResult.Rejected(409, "version_exists",
                $"Tarball parsed as {request.PurlName}@{request.Version}; that version already exists. " +
                "Same-version push is blocked by this package's policy.");
        }

        // Same gate, one step further back in time: a coordinate that was published and then
        // hard-deleted is still spent.
        var tombstoneReject = existing is null
            ? await TombstoneRejectionAsync(request, overwriteAllowed, ct)
            : null;

        return tombstoneReject ?? (!MultiFileEcosystems.Covers(request.Ecosystem)
            && ArtifactFilenameMismatch(existing, request.Filename) is { } filenameMismatch
            ? filenameMismatch
            : null);
    }

    // Projects the publish request's authenticated actor into a name-ownership principal. A
    // service-token publish carries no ActorUserId, so its stable identity is the token id;
    // user/import callers attribute to their user id. Null for anonymous/background callers.
    private static NamePrincipal? PrincipalOf(PublishRequest request)
        => request.ActorKind == ActorKinds.Service
            ? NamePrincipal.From(ActorKinds.Service, request.ActorTokenId)
            : NamePrincipal.From(ActorKinds.User, request.ActorUserId);

    // Name-level authorization gate: rejects when enforcement is on and the authenticated
    // principal is neither the name's owner nor a grantee. No-op for ecosystems without a hosted
    // push, when enforcement is off, or for an unattributed caller.
    private async Task<PublishResult.Rejected?> NameBindingRejectionAsync(
        PublishRequest request, CancellationToken ct)
        => !NameBindingEcosystems.Covers(request.Ecosystem)
            || await _nameBinding.IsPublishAuthorizedAsync(
                request.OrgId, request.Ecosystem, request.PurlName, PrincipalOf(request), ct)
            ? null
            : new PublishResult.Rejected(403, "name_not_owned",
                $"Publishing to '{request.PurlName}' is not permitted: the name is owned by a " +
                "different principal in this org and you hold no publish grant for it.");

    // Probes the per-file slot for a multi-file same-version upload: returns the file record the
    // incoming filename would overwrite (null when the filename is new to the version), and
    // whether this upload ADDS a file rather than overwriting one. Single-artefact ecosystems and
    // first uploads of a version always resolve to (null, false).
    private async Task<(PackageVersionFile? ExistingFile, bool AddsNewFile)> ResolveVersionFileSlotAsync(
        PublishRequest request, PackageVersion? existing, CancellationToken ct)
    {
        if (existing is null || !MultiFileEcosystems.Covers(request.Ecosystem))
        {
            return (null, false);
        }

        var file = await _versionFiles.GetByVersionAndFilenameAsync(existing.Id, request.Filename, ct);
        return (file, file is null);
    }

    // Resolved storage context for the write tail, bundled to keep HashAndStoreBlobAsync
    // within the parameter-count threshold (S107). The blob key is NOT resolved here: it is
    // content-addressed and therefore not knowable until the artifact has been hashed.
    private sealed record PublishStorageContext(
        Package Pkg, PackageVersion? Existing, PackageVersionFile? ExistingFile,
        long ArtifactSizeBytes);

    // Resolves the artifact's SHA-256 (and npm SHA-1), derives the content-addressed blob key
    // from that digest, opens the artifact stream, puts the blob, commits the metadata and OSV
    // scan, and emits the audit record. The caller holds the quota reservation across this whole
    // call, so a failure here needs no compensating release — nothing was committed, and the
    // derived sum never saw the bytes.
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
            // stagingPath is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
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

        // A publisher-declared dist.integrity is compared against the server-computed SRI over
        // the bytes actually staged, and rejected on mismatch: a caller that PUTs one tarball
        // while declaring another's SRI must not have the registry advertise dist.integrity that
        // is untrue of the bytes it stores. When the two agree — or the caller declared none —
        // the server-computed SRI covers the response and the packument (and the in-repo import
        // path, which has no publish body and so never sets DeclaredIntegritySri).
        if (request.DeclaredIntegritySri is { } declared && sha512Sri is { } computed
            && !string.Equals(declared, computed, StringComparison.Ordinal))
        {
            if (ownsStream)
            {
                await artifactStream.DisposeAsync();
            }

            return new PublishResult.Rejected(422, "integrity_mismatch",
                "Declared dist.integrity does not match the SHA-512 of the uploaded bytes.");
        }

        string? integritySri = request.DeclaredIntegritySri ?? sha512Sri;

        // Content-addressed key: the artifact's own digest is a key segment, so the bytes at
        // this key can only ever be the bytes that hash to sha256. Concurrent publishes of the
        // same coordinate with different bytes land on disjoint keys — neither can overwrite
        // the other's artifact, and the (blob_key, checksum_sha256) pair each one commits below
        // stays true of the stored bytes for the life of the row. A coordinate-addressed key
        // would instead make the last put win over every committed row naming that key.
        string blobKey = BlobKeys.HostedArtifact(
            request.OrgId, request.Ecosystem, request.PurlName, request.Version, sha256, request.Filename);

        var registry = await _storage.GetRegistryAsync(request.OrgId, ct);
        try
        {
            await registry.PutAsync(blobKey, artifactStream, ct);

            var newVersion = await CommitMetadataAsync(request, ctx,
                new PersistedArtifact(blobKey, sha256, sha1, integritySri, ctx.ArtifactSizeBytes), registry, ct);
            await DetectInstallScriptQuietlyAsync(request, newVersion, blobKey, registry, ct);
            await ScanQuietlyAsync(request, newVersion, ct);
            await _auditor.RecordAsync(request, sha256, ctx.Existing, ctx.ArtifactSizeBytes, ct);

            return new PublishResult.Accepted(newVersion.Id, request.Purl, sha256, blobKey);
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

        // Name-level authorization mirrors the real path so bulk-import pre-validation surfaces
        // the same rejection. Dry run stores nothing, so no ownership is recorded here.
        if (await NameBindingRejectionAsync(request, ct) is { } nameReject)
        {
            return nameReject;
        }

        if (await CheckDedupForValidateAsync(request, ct) is { } dedupReject)
        {
            return dedupReject;
        }

        string sha256 = request.ArtifactStagingPath is { } stagePath
            ? (await ComputeHashesFromFileAsync(stagePath, request.Ecosystem, ct)).Sha256
            : Convert.ToHexString(SHA256.HashData(request.ArtifactBytes!)).ToLowerInvariant();
        // Dry run: nothing was stored, so there is no blob key to report.
        return new PublishResult.Accepted(VersionId: "", request.Purl, sha256, BlobKey: "");
    }

    // Dry-run dedup projection: mirrors StoreAndRecordInnerAsync's version-exists and
    // filename-mismatch gates without any write. A PyPI upload adding a filename the version
    // does not yet hold is a new file of the release, not an overwrite. Non-mutating lookup —
    // if the package row doesn't exist yet, the version can't either, so dedup passes
    // implicitly.
    private async Task<PublishResult.Rejected?> CheckDedupForValidateAsync(
        PublishRequest request, CancellationToken ct)
    {
        // The package row is absent both for a name never published and for one whose last
        // version was deleted (empty-package GC removes it), so the tombstone probe cannot be
        // gated on it — that second case is exactly the one this gate exists for.
        var pkg = await _packages.GetByPurlNameAsync(request.OrgId, request.Ecosystem, request.PurlName, ct);
        var settings = await _orgs.GetSettingsAsync(request.OrgId, ct);
        bool overwriteAllowed = ResolveOverwriteAllowed(
            settings?.VersionOverwritePolicy, pkg?.SameVersionPushOverride);

        var existing = pkg is null ? null : await _packages.GetVersionAsync(pkg.Id, request.Version, ct);
        if (existing is null)
        {
            return await TombstoneRejectionAsync(request, overwriteAllowed, ct);
        }

        var (_, addsNewFile) = await ResolveVersionFileSlotAsync(request, existing, ct);
        return !addsNewFile && !overwriteAllowed
            ? new PublishResult.Rejected(409, "version_exists",
                $"Tarball parsed as {request.PurlName}@{request.Version}; that version already exists. " +
                "Same-version push is blocked by this package's policy.")
            : !MultiFileEcosystems.Covers(request.Ecosystem)
                ? ArtifactFilenameMismatch(existing, request.Filename)
                : null;
    }

    // Version-granular delete tombstone. A hard delete of a hosted version records its
    // coordinate, so a republish of that coordinate is gated by exactly the policy that gates
    // overwriting the live version: an org whose policy permits the overwrite is unaffected (for
    // it, delete-then-republish was always a supported workflow), while under a blocking policy
    // the coordinate stays spent. Without this, deleting the version first defeats the policy —
    // there is nothing left to collide with — which puts an immutable-version guarantee inside
    // the reach of the publish+yank credential it exists to constrain.
    //
    // Relaxing the org's version_overwrite_policy is the deliberate escape hatch; it takes
    // tenant:configure, which a publish token does not hold, and it is audited.
    private async Task<PublishResult.Rejected?> TombstoneRejectionAsync(
        PublishRequest request, bool overwriteAllowed, CancellationToken ct)
    {
        if (overwriteAllowed
            || !await _tombstones.ExistsAsync(
                request.OrgId, request.Ecosystem, request.PurlName, request.Version, ct))
        {
            return null;
        }

        _logger.LogWarning(
            "Republish of deleted version refused: {Ecosystem}/{PurlName}@{Version} in org {OrgId} " +
            "carries a delete tombstone and the version-overwrite policy blocks reuse.",
            request.Ecosystem, request.PurlName, request.Version, request.OrgId);

        return new PublishResult.Rejected(409, "version_tombstoned",
            $"{request.PurlName}@{request.Version} was previously published and then deleted. " +
            "This org's version-overwrite policy blocks reusing a deleted version's coordinates; " +
            "publish a new version, or have an administrator relax the policy.");
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
    // allow/block entries before comparing, mirroring the serve-path license arm. A caller that
    // passed no license signal skips this arm entirely and falls through to the independent
    // publish-side gate below.
    private async Task<PublishResult.Rejected?> CheckLicensePolicyAsync(
        PublishRequest request, OrgSettings? settings, CancellationToken ct)
    {
        if (request.Licenses is not { Count: > 0 } licenses)
        {
            return await CheckLicenselessPublishPolicyAsync(request, settings, ct);
        }

        if (settings?.LicenseEnforcementMode != "block")
        {
            return null;
        }

        var (allowed, blockedLicense) = await _licenses.CheckPolicyAsync(request.OrgId, "block", licenses, ct);
        return allowed
            ? null
            : new PublishResult.Rejected(403, "license_blocked",
                $"License '{blockedLicense}' is not permitted by this org's license policy.");
    }

    // Publish-side licence gate for a hosted publish that declares no license at all, governed by
    // the independent org_settings.license_publish_enforcement_mode ('off' default / 'warn' /
    // 'block') — never license_enforcement_mode, which stays the serve-path gate's alone. Only
    // engages for the ecosystems whose manifests declare a licence (BlockGateService.
    // DeclaredLicenseEcosystems); go/apk/oci keep the empty-set pass-through because they
    // routinely record no licence at all. 'off' (the default) reproduces today's behaviour
    // byte-for-byte: no currently-succeeding licence-less publish starts failing on upgrade.
    private async Task<PublishResult.Rejected?> CheckLicenselessPublishPolicyAsync(
        PublishRequest request, OrgSettings? settings, CancellationToken ct)
    {
        if (!BlockGateService.DeclaredLicenseEcosystems.Contains(request.Ecosystem))
        {
            return null;
        }

        string mode = settings?.LicensePublishEnforcementMode ?? "off";
        switch (mode)
        {
            case "off":
                return null;
            case "warn":
                await _auditor.RecordLicensePublishWarnAsync(request, ct);
                return null;
            default:
                return new PublishResult.Rejected(403, "license_publish_blocked",
                    $"Publish rejected: {request.Ecosystem} declares no license, and this org's " +
                    "publish policy (license_publish_enforcement_mode=block) refuses an artifact " +
                    "with no declared license.");
        }
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
        // path is "publish-stage-{server-guid}.tmp" under the operator-configured staging root — no user input reaches the path.
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
    // Blob and DB live in different stores (no shared transaction), so an exception out of the
    // version-row write would otherwise leave an orphan hosted blob. On the INSERT paths (new
    // version, or a new file of an existing multi-file version) no committed row can name this
    // key yet, so the just-put blob is deletable to compensate. On the OVERWRITE paths the row
    // still names the PRIOR artifact's key — the put was non-destructive, so the prior bytes
    // and the row remain mutually consistent and there is nothing to repair; the newly written
    // blob is simply unreferenced and left for the orphan reconciler.
    // A background orphan-blob reconciler closes the SIGKILL window; the try/catch here closes
    // the application-exception window.
    private async Task<PackageVersion> CommitMetadataAsync(PublishRequest request, PublishStorageContext ctx,
        PersistedArtifact artifact, IBlobStore registry, CancellationToken ct)
    {
        var existing = ctx.Existing;
        // The INSERT shapes: no pre-existing row references this artifact, so a failed metadata
        // write leaves a blob that only the compensating delete can reclaim.
        bool freshBlob = existing is null
            || (MultiFileEcosystems.Covers(request.Ecosystem) && ctx.ExistingFile is null);
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
            if (MultiFileEcosystems.Covers(request.Ecosystem))
            {
                await AddFirstVersionFileWithRollbackAsync(request, created, artifact, ct);
            }
            return created;
        }
        catch (Exception ex) when (freshBlob)
        {
            // A uniqueness violation means a CONCURRENT publish of the same coordinate won
            // the insert race. When that winner uploaded byte-for-byte identical content it
            // content-addressed to THIS key too, so its committed row references the blob we
            // would compensate — deleting it would 404 the winner's artifact. Skip the
            // compensation whenever the row write lost a race and let the loser's failure
            // propagate (a retry resolves against the now-existing row/file); at worst a
            // distinct-bytes loser leaves a blob for the orphan reconciler.
            bool blobMayBeSharedWithRaceWinner = IsUniqueViolation(ex);
            _logger.LogWarning(ex,
                "Metadata write failed after blob put on INSERT path for {BlobKey}; " +
                "compensating delete {Action}",
                artifact.BlobKey,
                blobMayBeSharedWithRaceWinner ? "skipped (blob may be shared with concurrent-publish winner)" : "attempted");
            if (!blobMayBeSharedWithRaceWinner)
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
            // OVERWRITE failure. The put wrote a content-addressed key of its own, so the row
            // and the artifact it still references are untouched and mutually consistent — the
            // version simply keeps its prior bytes. The blob just written is unreferenced, and
            // is NOT deleted here: a concurrent publish of the identical bytes addresses the
            // same key and may already have committed a row against it. The orphan reconciler
            // reclaims it once no row references it.
            _logger.LogError(ex,
                "Metadata write failed after blob put on OVERWRITE path; version {VersionId} keeps its prior artifact and blob {BlobKey} is unreferenced pending reconciliation. Retry the publish.",
                existing!.Id, artifact.BlobKey);
            throw;
        }
    }

    // Records the first file of a new multi-file release. A failed file-row insert must not leave
    // a version row with zero files — delete the ROW before the caller's outer compensation
    // removes the blob. Row-only delete: this publish's own quota reservation is released by
    // HashAndStoreBlobAsync's catch, so the counter-coupled DeleteVersionAsync would decrement
    // the tenant counter a second time.
    private async Task AddFirstVersionFileWithRollbackAsync(
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

    // Same-version commit: a multi-file ecosystem adds or overwrites one file record of the
    // release; every other ecosystem overwrites the version row's single artifact.
    private async Task<PackageVersion> CommitToExistingVersionAsync(
        PublishRequest request, PublishStorageContext ctx, PackageVersion existing,
        PersistedArtifact artifact, CancellationToken ct)
    {
        bool multiFile = MultiFileEcosystems.Covers(request.Ecosystem);
        string currentPrimaryFilename = PackageRepository.DeriveFilename(existing.BlobKey);

        if (multiFile && ctx.ExistingFile is null)
        {
            // New file of an existing release (the sdist joining the wheel; the .snupkg joining
            // the .nupkg). The version row keeps its identity, and normally its primary-artifact
            // columns too; the repository refreshes the row's size sum and resets its scan state
            // so the next OSV pass covers the new bytes.
            //
            // The exception is a promotion: a .nupkg arriving at a coordinate whose row still
            // names a .snupkg (the symbols-first push order) must take over the primary columns,
            // or every reader that resolves the version without a filename would keep serving
            // symbol bytes to package clients. Ordered BEFORE the file insert because
            // UpdateVersionForOverwriteAsync writes size_bytes as this one artifact's size, and
            // AddAsync's refresh is what restores it to the SUM across the file set.
            if (MultiFileEcosystems.PromotesToPrimary(
                    request.Ecosystem, request.Filename, currentPrimaryFilename))
            {
                await _packages.UpdateVersionForOverwriteAsync(existing.Id, artifact.BlobKey,
                    artifact.SizeBytes, artifact.Sha256, request.Origin, artifact.Sha1,
                    integrityValue: artifact.IntegritySri,
                    integrityAlgorithm: artifact.IntegritySri is not null ? "sha512-sri" : null,
                    manifestJson: request.ManifestJson, ct: ct);
            }

            await _versionFiles.AddAsync(existing.Id, request.OrgId, request.Filename,
                artifact.BlobKey, artifact.SizeBytes, artifact.Sha256, ct);
            return (await _packages.GetVersionAsync(ctx.Pkg.Id, request.Version, ct))!;
        }

        // Overwrite path: keep the same id so dependent rows (vulns, licenses) follow. The row
        // is REPOINTED at the new artifact's content-addressed key; blob_key and
        // checksum_sha256 are written together in one UPDATE, so the row always names bytes
        // that hash to the checksum beside it, whichever of two concurrent overwrites lands
        // last. The superseded artifact is left in place (an in-flight download may still be
        // streaming it) and is reclaimed by the orphan reconciler once no row references it.
        // vuln_checked_at is reset by the repository so the next scan re-checks the new
        // bytes — the prior scan applied to the artifact the row no longer points at.
        // checksum_sha1, the integrity SRI, and the stored manifest all follow the new
        // bytes (npm) — otherwise the packument would emit stale metadata next request.
        // For a multi-file ecosystem the version row's artifact columns follow only when the
        // overwritten filename IS the row's primary artifact; a non-primary overwrite (a
        // re-pushed .snupkg, a re-pushed non-primary wheel) touches the file record alone
        // (which also restores the row's size sum afterwards).
        bool updateVersionRow = !multiFile
            || currentPrimaryFilename.Equals(request.Filename, StringComparison.Ordinal);
        if (updateVersionRow)
        {
            await _packages.UpdateVersionForOverwriteAsync(existing.Id, artifact.BlobKey,
                artifact.SizeBytes, artifact.Sha256, request.Origin, artifact.Sha1,
                integrityValue: artifact.IntegritySri,
                integrityAlgorithm: artifact.IntegritySri is not null ? "sha512-sri" : null,
                manifestJson: request.ManifestJson, ct: ct);
        }

        if (multiFile && ctx.ExistingFile is not null)
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
                request.PurlName, request.OrgId, request.ActorUserId,
                actorKind: request.ActorKind, sourceIp: request.SourceIp, ct: ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Post-publish vuln scan failed for {Purl}; scheduled pass will retry.", request.Purl);
        }
    }
}
