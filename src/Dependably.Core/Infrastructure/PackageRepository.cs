using Dapper;

namespace Dependably.Infrastructure;

public sealed partial class PackageRepository
{
    private readonly IMetadataStore _db;
    private readonly DownloadCountWriter? _downloadCountWriter;
    private readonly TimeProvider _time;

    public PackageRepository(IMetadataStore db, DownloadCountWriter? downloadCountWriter = null, TimeProvider? time = null)
    {
        _db = db;
        _downloadCountWriter = downloadCountWriter;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>
    /// Returns the trailing path segment of <paramref name="blobKey"/>. Surface-internal —
    /// callers building a <see cref="NewPackageVersion"/> only need to pass a blob key
    /// and the repository populates <c>filename</c> via this helper so the equality lookup
    /// in <see cref="FindVersionByBlobKeySuffixAsync"/> can use idx_package_versions_filename.
    /// </summary>
    internal static string DeriveFilename(string blobKey)
    {
        int lastSlash = blobKey.LastIndexOf('/');
        return lastSlash >= 0 ? blobKey[(lastSlash + 1)..] : blobKey;
    }

    public async Task<IReadOnlyList<Package>> ListAsync(string orgId, string ecosystem, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<Package>(
            """
            SELECT id, org_id as OrgId, ecosystem, name, purl_name as PurlName,
                   is_proxy as IsProxy, created_at as CreatedAt
            FROM packages
            WHERE org_id = @orgId AND ecosystem = @ecosystem
            ORDER BY purl_name
            """,
            new { orgId, ecosystem });
        return rows.ToList();
    }

    public async Task<Package?> GetByPurlNameAsync(string orgId, string ecosystem, string purlName, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var pkg = await conn.QuerySingleOrDefaultAsync<Package>(
            """
            SELECT p.id, p.org_id as OrgId, p.ecosystem, p.name, p.purl_name as PurlName,
                   p.is_proxy as IsProxy, p.created_at as CreatedAt,
                   p.upstream_latest_version as UpstreamLatestVersion,
                   p.upstream_latest_published_at as UpstreamLatestPublishedAt,
                   p.same_version_push_override as SameVersionPushOverride,
                   p.homepage as Homepage,
                   p.repository_url as RepositoryUrl,
                   p.description as Description,
                   CASE
                     WHEN p.upstream_latest_version IS NULL THEN 'unknown'
                     WHEN EXISTS (
                         SELECT 1 FROM package_versions pvl
                         WHERE pvl.package_id = p.id
                           AND pvl.version = p.upstream_latest_version
                           AND pvl.origin = 'uploaded'
                     ) OR EXISTS (
                         SELECT 1 FROM cache_artifact ca
                         JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                         WHERE taa.org_id = p.org_id
                           AND ca.ecosystem = p.ecosystem
                           AND ca.name = p.purl_name
                           AND ca.version = p.upstream_latest_version
                     ) THEN 'current'
                     ELSE 'stale'
                   END as LatestState
            FROM packages p
            WHERE p.org_id = @orgId AND p.ecosystem = @ecosystem AND p.purl_name = @purlName
            """,
            new { orgId, ecosystem, purlName });
        // S1121 false positive: this is C#'s null-conditional assignment statement, not an
        // assignment inside a sub-expression; IDE0031 requires this form.
#pragma warning disable S1121
        pkg?.AbandonedState = AbandonedStateOf(pkg.UpstreamLatestPublishedAt);
#pragma warning restore S1121
        return pkg;
    }

    // Tri-state derivation of the "abandoned" signal, computed in C# against the injected
    // TimeProvider (never SQL date math, so it stays deterministic under frozen-clock tests):
    // "unknown" when no publish timestamp is known (hosted-only package, unsupported ecosystem,
    // air-gapped, or not yet refreshed) — never rendered as "abandoned", since that would assert
    // a fact the server doesn't actually know. "abandoned" when the upstream latest release is at
    // least a year old; "active" otherwise.
    private string AbandonedStateOf(DateTimeOffset? upstreamLatestPublishedAt) =>
        upstreamLatestPublishedAt is not { } publishedAt
            ? "unknown"
            : _time.GetUtcNow() - publishedAt >= TimeSpan.FromDays(365) ? "abandoned" : "active";

    /// <summary>
    /// The exact INSERT statement <see cref="GetOrCreateAsync"/> runs for a new package.
    /// Internal (not private) so the race-safety test can execute this literal statement a
    /// second time against a seeded coordinate and assert the ON CONFLICT no-op directly,
    /// instead of a test-owned copy that could silently drift from the production statement.
    /// </summary>
    internal const string InsertPackageSql = """
        INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy)
        VALUES (@id, @orgId, @ecosystem, @name, @purlName, @isProxy)
        ON CONFLICT (org_id, ecosystem, purl_name) DO NOTHING
        """;

    /// <summary>Gets or creates a package row; returns the resolved Package.</summary>
    public async Task<Package> GetOrCreateAsync(string orgId, string ecosystem, string name, string purlName, bool isProxy, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var existing = await conn.QuerySingleOrDefaultAsync<Package>(
            """
            SELECT id, org_id as OrgId, ecosystem, name, purl_name as PurlName,
                   is_proxy as IsProxy, created_at as CreatedAt,
                   same_version_push_override as SameVersionPushOverride
            FROM packages WHERE org_id = @orgId AND ecosystem = @ecosystem AND purl_name = @purlName
            """,
            new { orgId, ecosystem, purlName });

        if (existing is not null)
        {
            return existing;
        }

        string id = Guid.NewGuid().ToString("N");
        // ON CONFLICT (org_id, ecosystem, purl_name) DO NOTHING lets concurrent first
        // publish / first-fetch races converge on a single winner row instead of the loser
        // throwing a UNIQUE-constraint violation. When the INSERT is a no-op (another request
        // won the race) the locally generated id was never persisted, so the winner is fetched
        // back by coordinate, never by @id.
        await conn.ExecuteAsync(
            InsertPackageSql,
            new { id, orgId, ecosystem, name, purlName, isProxy = isProxy ? 1 : 0 });

        return (await conn.QuerySingleOrDefaultAsync<Package>(
            """
            SELECT id, org_id as OrgId, ecosystem, name, purl_name as PurlName, is_proxy as IsProxy,
                   created_at as CreatedAt, same_version_push_override as SameVersionPushOverride
            FROM packages WHERE org_id = @orgId AND ecosystem = @ecosystem AND purl_name = @purlName
            """,
            new { orgId, ecosystem, purlName }))!;
    }

    /// <summary>
    /// Persists package-level metadata (homepage / repository / description) parsed from an
    /// artifact manifest at hosted publish or proxy first-fetch. Each field is COALESCEd against
    /// the stored value, so a later ingest whose manifest omits a field never nulls out a value an
    /// earlier ingest captured. A no-op when all three inputs are null. Keyed by the FK-bound
    /// package id, which is already org-scoped.
    /// </summary>
    public async Task UpdateMetadataAsync(
        string packageId, string? homepage, string? repositoryUrl, string? description, CancellationToken ct = default)
    {
        if (homepage is null && repositoryUrl is null && description is null)
        {
            return;
        }

        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by the packages.id primary key, which is itself org-scoped.
        await conn.ExecuteAsync(
            """
            UPDATE packages
               SET homepage       = COALESCE(@homepage, homepage),
                   repository_url = COALESCE(@repositoryUrl, repository_url),
                   description    = COALESCE(@description, description)
             WHERE id = @packageId
            """,
            new { packageId, homepage, repositoryUrl, description });
    }

    /// <summary>
    /// Finds a package version by its filename (the trailing path segment of blob_key), joined
    /// with its parent package. When <paramref name="uploadedOnly"/> is <c>true</c> (default),
    /// only <c>origin='uploaded'</c> rows are returned — proxy artifacts for ecosystems that
    /// have been flipped to the global plane are excluded. Pass <c>false</c> for ecosystems
    /// (e.g. RPM) that still record proxy origin rows in <c>package_versions</c>.
    /// Uses an equality lookup against <c>idx_package_versions_filename</c>.
    /// </summary>
    public async Task<(Package Package, PackageVersion Version)?> FindVersionByBlobKeySuffixAsync(
        string orgId, string ecosystem, string filename, bool uploadedOnly = true,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var (PkgId, PkgOrgId, PkgEcosystem, PkgName, PkgPurlName, PkgIsProxy, PkgCreatedAt,
            VerId, VerPackageId, VerVersion, VerPurl, VerBlobKey, VerSizeBytes, VerChecksumSha256,
            VerYanked, VerYankReason, VerFirstFetch, VerCreatedAt, VerVulnCheckedAt,
            VerManualBlockState, VerDeprecated, VerOrigin, VerPublishedAt, VerChecksumSha1,
            VerUpstreamIntegrityValue, VerUpstreamIntegrityAlgorithm) =
            await conn.QuerySingleOrDefaultAsync<(
            string PkgId, string PkgOrgId, string PkgEcosystem, string PkgName, string PkgPurlName, bool PkgIsProxy, string PkgCreatedAt,
            string VerId, string VerPackageId, string VerVersion, string VerPurl, string VerBlobKey,
            long VerSizeBytes, string? VerChecksumSha256, bool VerYanked, string? VerYankReason,
            bool VerFirstFetch, string VerCreatedAt, string? VerVulnCheckedAt, string? VerManualBlockState,
            string? VerDeprecated, string VerOrigin, string? VerPublishedAt, string? VerChecksumSha1,
            string? VerUpstreamIntegrityValue, string? VerUpstreamIntegrityAlgorithm)>(
            // plane-ok: point lookup by (org, ecosystem, filename) on the hosted serve/delete path; flipped-ecosystem proxy is served from cache_artifact.
            """
            SELECT p.id, p.org_id, p.ecosystem, p.name, p.purl_name, p.is_proxy, p.created_at,
                   pv.id, pv.package_id, pv.version, pv.purl, pv.blob_key,
                   pv.size_bytes, pv.checksum_sha256, pv.yanked, pv.yank_reason,
                   pv.first_fetch, pv.created_at, pv.vuln_checked_at, pv.manual_block_state,
                   pv.deprecated, pv.origin, pv.published_at, pv.checksum_sha1,
                   pv.upstream_integrity_value, pv.upstream_integrity_algorithm
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE pv.filename = @filename AND p.org_id = @orgId AND p.ecosystem = @ecosystem
              AND (@uploadedOnly = 0 OR pv.origin = 'uploaded')
            LIMIT 1
            """,
            new { orgId, ecosystem, filename, uploadedOnly = uploadedOnly ? 1 : 0 });

        if (PkgId is null)
        {
            return null;
        }

        var pkg = new Package
        {
            Id = PkgId,
            OrgId = PkgOrgId,
            Ecosystem = PkgEcosystem,
            Name = PkgName,
            PurlName = PkgPurlName,
            IsProxy = PkgIsProxy,
            CreatedAt = DateTimeOffset.Parse(PkgCreatedAt)
        };
        var ver = new PackageVersion
        {
            Id = VerId,
            PackageId = VerPackageId,
            Version = VerVersion,
            Purl = VerPurl,
            BlobKey = VerBlobKey,
            SizeBytes = VerSizeBytes,
            ChecksumSha256 = VerChecksumSha256,
            Yanked = VerYanked,
            YankReason = VerYankReason,
            FirstFetch = VerFirstFetch,
            CreatedAt = DateTimeOffset.Parse(VerCreatedAt),
            VulnCheckedAt = VerVulnCheckedAt is not null ? DateTimeOffset.Parse(VerVulnCheckedAt) : null,
            ManualBlockState = VerManualBlockState,
            Deprecated = VerDeprecated,
            Origin = VerOrigin,
            PublishedAt = VerPublishedAt is not null ? DateTimeOffset.Parse(VerPublishedAt) : null,
            ChecksumSha1 = VerChecksumSha1,
            UpstreamIntegrityValue = VerUpstreamIntegrityValue,
            UpstreamIntegrityAlgorithm = VerUpstreamIntegrityAlgorithm
        };
        return (pkg, ver);
    }

    public async Task<IReadOnlyList<PackageVersion>> GetVersionsAsync(string packageId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // is_malicious / has_advisory are derived from the version's advisory links: a MAL-
        // osv_id marks a known-malicious version; any link marks it as carrying advisories.
        // xtenant: keyed by package_id which the caller obtained via an org-scoped lookup;
        // package_versions FKs into packages(id), so org isolation rides on the parent.
        // plane-ok: PV-plane version list; callers pair it with a cache-plane read (ArtifactInventoryRepository.ListServeableVersionsAsync).
        var rows = await conn.QueryAsync<PackageVersion>(
            """
            SELECT pv.id, pv.package_id as PackageId, pv.version, pv.purl, pv.blob_key as BlobKey,
                   pv.filename as Filename,
                   pv.size_bytes as SizeBytes, pv.checksum_sha256 as ChecksumSha256,
                   pv.yanked, pv.yank_reason as YankReason, pv.first_fetch as FirstFetch, pv.download_count as DownloadCount, pv.created_at as CreatedAt,
                   pv.updated_at as UpdatedAt,
                   pv.vuln_checked_at as VulnCheckedAt, pv.manual_block_state as ManualBlockState,
                   pv.deprecated as Deprecated, pv.revoked_at as RevokedAt, pv.origin as Origin, pv.published_at as PublishedAt,
                   pv.checksum_sha1 as ChecksumSha1,
                   pv.upstream_integrity_value as UpstreamIntegrityValue,
                   pv.upstream_integrity_algorithm as UpstreamIntegrityAlgorithm,
                   pv.has_install_script as HasInstallScript,
                   pv.install_script_kind as InstallScriptKind,
                   pv.provenance_status as ProvenanceStatus,
                   pv.provenance_signer as ProvenanceSigner,
                   pv.manifest_json as ManifestJson,
                   pv.versions_behind as VersionsBehind,
                   EXISTS (SELECT 1 FROM package_version_vulns pvv
                           JOIN vulnerabilities v ON v.id = pvv.vuln_id
                           WHERE pvv.package_version_id = pv.id
                             AND v.osv_id LIKE 'MAL-%') as IsMalicious,
                   EXISTS (SELECT 1 FROM package_version_vulns pvv
                           WHERE pvv.package_version_id = pv.id) as HasAdvisory
            FROM package_versions pv
            WHERE pv.package_id = @packageId
            ORDER BY pv.created_at DESC
            """,
            new { packageId });
        return rows.ToList();
    }

    public async Task<PackageVersion?> GetVersionAsync(string packageId, string version, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by package_id (caller-org-scoped); inherited via FK to packages(id).
        return await conn.QuerySingleOrDefaultAsync<PackageVersion>(
            // plane-ok: point lookup by (package_id, version) on the hosted serve path; proxy versions are read via CacheArtifactRepository.
            """
            SELECT id, package_id as PackageId, version, purl, blob_key as BlobKey,
                   size_bytes as SizeBytes, checksum_sha256 as ChecksumSha256,
                   yanked, yank_reason as YankReason, first_fetch as FirstFetch, download_count as DownloadCount, created_at as CreatedAt,
                   updated_at as UpdatedAt,
                   vuln_checked_at as VulnCheckedAt, manual_block_state as ManualBlockState,
                   deprecated as Deprecated, revoked_at as RevokedAt, origin as Origin, published_at as PublishedAt,
                   checksum_sha1 as ChecksumSha1,
                   upstream_integrity_value as UpstreamIntegrityValue,
                   upstream_integrity_algorithm as UpstreamIntegrityAlgorithm,
                   has_install_script as HasInstallScript,
                   install_script_kind as InstallScriptKind,
                   provenance_status as ProvenanceStatus,
                   provenance_signer as ProvenanceSigner,
                   manifest_json as ManifestJson,
                   versions_behind as VersionsBehind
            FROM package_versions
            WHERE package_id = @packageId AND version = @version
            """,
            new { packageId, version });
    }

    /// <summary>
    /// Lookup by blob_key, scoped to <paramref name="orgId"/> via the parent package's org_id.
    /// The org filter is defence-in-depth: blob_key is globally unique today, but joining
    /// through packages.org_id makes the tenancy invariant load-bearing in SQL rather than
    /// relying on every caller having org-scoped the lookup beforehand.
    /// </summary>
    public async Task<PackageVersion?> GetVersionByBlobKeyAsync(string orgId, string blobKey, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.QuerySingleOrDefaultAsync<PackageVersion>(
            // plane-ok: point lookup by hosted blob_key (hosted/ prefix); proxy/ keys resolve through cache_artifact.
            """
            SELECT pv.id, pv.package_id as PackageId, pv.version, pv.purl, pv.blob_key as BlobKey,
                   pv.filename as Filename,
                   pv.size_bytes as SizeBytes, pv.checksum_sha256 as ChecksumSha256,
                   pv.yanked, pv.yank_reason as YankReason, pv.first_fetch as FirstFetch, pv.download_count as DownloadCount, pv.created_at as CreatedAt,
                   pv.updated_at as UpdatedAt,
                   pv.vuln_checked_at as VulnCheckedAt, pv.manual_block_state as ManualBlockState,
                   pv.deprecated as Deprecated, pv.revoked_at as RevokedAt, pv.origin as Origin, pv.published_at as PublishedAt,
                   pv.checksum_sha1 as ChecksumSha1,
                   pv.upstream_integrity_value as UpstreamIntegrityValue,
                   pv.upstream_integrity_algorithm as UpstreamIntegrityAlgorithm,
                   pv.has_install_script as HasInstallScript,
                   pv.install_script_kind as InstallScriptKind,
                   pv.provenance_status as ProvenanceStatus,
                   pv.provenance_signer as ProvenanceSigner,
                   pv.manifest_json as ManifestJson,
                   pv.versions_behind as VersionsBehind
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE pv.blob_key = @blobKey AND p.org_id = @orgId
            """,
            new { orgId, blobKey });
    }

    public async Task<PackageVersion> CreateVersionAsync(
        NewPackageVersion data, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        string id = Guid.NewGuid().ToString("N");
        // Derive filename from blob_key's last path segment so download lookups can
        // hit idx_package_versions_filename instead of a leading-wildcard LIKE.
        string filename = DeriveFilename(data.BlobKey);
        // xtenant: INSERT pinned to a caller-supplied package_id (org-scoped via FK).
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key, filename, size_bytes,
                 checksum_sha256, first_fetch, origin, published_at,
                 checksum_sha1, upstream_integrity_value, upstream_integrity_algorithm,
                 manifest_json)
            VALUES
                (@id, @packageId, @version, @purl, @blobKey, @filename, @sizeBytes,
                 @checksumSha256, @firstFetch, @origin, @publishedAt,
                 @checksumSha1, @upstreamIntegrityValue, @upstreamIntegrityAlgorithm,
                 @manifestJson)
            """,
            new
            {
                id,
                packageId = data.PackageId,
                version = data.Version,
                purl = data.Purl,
                blobKey = data.BlobKey,
                filename,
                sizeBytes = data.SizeBytes,
                checksumSha256 = data.ChecksumSha256,
                firstFetch = data.FirstFetch ? 1 : 0,
                origin = data.Origin,
                // Microsecond precision, matching CacheArtifactRepository.UpdateGlobalFactsAsync's
                // writer of the same logical published_at/upstream_latest_published_at column (see
                // artifact_inventory / QuarantineRepository's cross-plane MAX() aggregation) — this
                // instant is declared by the upstream registry and re-served to clients, so seconds
                // would drop information the registry reports.
                publishedAt = data.PublishedAt.ToUtcIsoPreciseOrNull(),
                checksumSha1 = data.ChecksumSha1,
                upstreamIntegrityValue = data.UpstreamIntegrityValue,
                upstreamIntegrityAlgorithm = data.UpstreamIntegrityAlgorithm,
                manifestJson = data.ManifestJson,
            });

        // xtenant: keyed by version id (globally unique UUID, already org-scoped via FK)
        return (await conn.QuerySingleOrDefaultAsync<PackageVersion>(
            // plane-ok: reselect of the PV row just INSERTed by id on the hosted/legacy-proxy write path.
            """
            SELECT id, package_id as PackageId, version, purl, blob_key as BlobKey,
                   size_bytes as SizeBytes, checksum_sha256 as ChecksumSha256,
                   yanked, yank_reason as YankReason, first_fetch as FirstFetch,
                   download_count as DownloadCount, created_at as CreatedAt,
                   vuln_checked_at as VulnCheckedAt, manual_block_state as ManualBlockState,
                   deprecated as Deprecated, revoked_at as RevokedAt, origin as Origin, published_at as PublishedAt,
                   checksum_sha1 as ChecksumSha1,
                   upstream_integrity_value as UpstreamIntegrityValue,
                   upstream_integrity_algorithm as UpstreamIntegrityAlgorithm,
                   has_install_script as HasInstallScript,
                   install_script_kind as InstallScriptKind,
                   provenance_status as ProvenanceStatus,
                   provenance_signer as ProvenanceSigner,
                   manifest_json as ManifestJson,
                   versions_behind as VersionsBehind
            FROM package_versions WHERE id = @id
            """,
            new { id }))!;
    }

    public async Task TouchLastUsedAsync(string versionId, CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by version PK; the id reaches this method from an org-scoped package
        // lookup (GetByPurlNameAsync(orgId, …) → GetVersionAsync(pkg.Id, …)) on the serve path.
        await conn.ExecuteAsync(
            "UPDATE package_versions SET last_used = @now WHERE id = @id",
            new { now, id = versionId });
    }

    /// <summary>
    /// Records one served download against a version: bumps the durable all-time counter and
    /// stamps <c>last_used</c> in the same write (the download is the moment the retention/eviction
    /// freshness signal should advance). Called from every download-serve path — proxy first-fetch,
    /// protocol-client pulls, and UI downloads — so the counter matches the analytics download
    /// taxonomy ('download' + 'first_fetch').
    ///
    /// When a <see cref="DownloadCountWriter"/> is wired in, the increment is enqueued into the
    /// bounded channel and returns immediately without touching the DB. The companion
    /// <see cref="DownloadCountWriterHostedService"/> drains and aggregates the channel in batched
    /// UPDATEs off the request path. Falls back to a synchronous UPDATE when no writer is present
    /// (tests, embedded use-cases).
    /// </summary>
    public async Task IncrementDownloadCountAsync(string versionId, CancellationToken ct = default)
    {
        if (_downloadCountWriter is not null)
        {
            _downloadCountWriter.TryEnqueue(new DownloadCountRecord(VersionId: versionId, Purl: null));
            return;
        }

        string now = _time.GetUtcNow().ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by version PK; every download path resolves the id through an org-scoped
        // package lookup before counting the pull (see PyPiDownloadHandler, NpmTarballHandler,
        // NuGetFlatContainerHandler, RpmController, OrgController).
        await conn.ExecuteAsync(
            "UPDATE package_versions SET download_count = download_count + 1, last_used = @now WHERE id = @id",
            new { now, id = versionId });
    }

    /// <summary>
    /// Same as <see cref="IncrementDownloadCountAsync(string,CancellationToken)"/> but keyed by
    /// <c>purl</c> and scoped to <paramref name="orgId"/>. Used by download-serve paths (RPM proxy,
    /// Maven proxy) that hold the purl but not the version id. Increments
    /// <c>tenant_artifact_access.download_count</c> for the org's cache_artifact rows matching the
    /// purl. A no-op if no matching row exists yet.
    ///
    /// When a <see cref="DownloadCountWriter"/> is wired in, the increment is enqueued off the
    /// request path; otherwise falls back to a synchronous UPDATE.
    /// </summary>
    public async Task IncrementDownloadCountByPurlAsync(string orgId, string purl, CancellationToken ct = default)
    {
        if (_downloadCountWriter is not null)
        {
            _downloadCountWriter.TryEnqueue(new DownloadCountRecord(VersionId: null, Purl: purl, OrgId: orgId));
            return;
        }

        string now = _time.GetUtcNow().ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            UPDATE tenant_artifact_access
            SET download_count = download_count + 1,
                last_used = @now
            WHERE org_id = @orgId
              AND cache_artifact_id IN (
                  SELECT id FROM cache_artifact WHERE purl = @purl
              )
            """,
            new { now, orgId, purl });
    }

    public async Task UpdateDeprecatedAsync(string versionId, string? message, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: keyed by version PK; callers (NpmPublishHandler, ProxyVersionRecorder) hold an
        // id they just created or resolved under an org-scoped package lookup.
        await conn.ExecuteAsync(
            "UPDATE package_versions SET deprecated = @message WHERE id = @id",
            new { id = versionId, message });
    }

    /// <summary>
    /// Persists the install/lifecycle-script signal detected at ingest. <paramref name="kind"/>
    /// is NULL when no script was found. Called by the proxy first-fetch recorder and the
    /// hosted publish path after the version row exists.
    /// </summary>
    public async Task UpdateInstallScriptAsync(
        string versionId, bool hasScript, string? kind, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: UPDATE by version_id; caller obtained the id from an org-scoped lookup.
        await conn.ExecuteAsync(
            "UPDATE package_versions SET has_install_script = @has, install_script_kind = @kind WHERE id = @id",
            new { id = versionId, has = hasScript ? 1 : 0, kind = hasScript ? kind : null });
    }

    /// <summary>
    /// Persists the provenance/signature-verification outcome captured at proxy first-fetch.
    /// <paramref name="status"/> is one of <c>'verified'</c>/<c>'failed'</c>/<c>'unsigned'</c> (or
    /// NULL when not applicable); <paramref name="signer"/> is the verifying trust-anchor keyid,
    /// non-null only for <c>'verified'</c>. Called by the proxy first-fetch recorder after the
    /// version row exists.
    /// </summary>
    public async Task UpdateProvenanceAsync(
        string versionId, string? status, string? signer, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: UPDATE by version_id; caller obtained the id from an org-scoped lookup.
        await conn.ExecuteAsync(
            "UPDATE package_versions SET provenance_status = @status, provenance_signer = @signer WHERE id = @id",
            new { id = versionId, status, signer });
    }

    /// <summary>
    /// Replacement-policy update: rewrites blob_key/size/checksum/origin on an existing
    /// row when allow_version_overwrite is on. The package_version id is preserved so vuln
    /// scans, license rows, and existing FKs follow the new artefact without re-stitching.
    /// Stamps updated_at to now (the "Pushed" date the frontend renders for a re-push) and
    /// clears provenance_status/provenance_signer, since new bytes invalidate any prior
    /// provenance verdict — mirroring the vuln_checked_at reset.
    /// </summary>
    // Most parameters beyond the required artifact fields are optional (default null) and
    // called with named arguments at every call site; a wrapper type would just move the
    // named-argument call shape into a second type without reducing real coupling.
#pragma warning disable S107 // optional named-argument parameter set, not positional coupling
    public async Task UpdateVersionForOverwriteAsync(
        string versionId, string blobKey, long sizeBytes, string sha256, string origin,
        string? sha1, string? integrityValue = null, string? integrityAlgorithm = null,
        string? manifestJson = null, CancellationToken ct = default)
#pragma warning restore S107
    {
        await using var conn = await _db.OpenAsync(ct);
        string now = _time.GetUtcNow().ToUtcIso();
        // xtenant: UPDATE by version_id; caller obtained the id from an org-scoped lookup.
        // Integrity + manifest follow the new bytes: a stale value from the prior artefact
        // (including a proxy row overwritten by a hosted push) must never survive the overwrite.
        await conn.ExecuteAsync(
            """
            UPDATE package_versions
               SET blob_key = @blobKey,
                   size_bytes = @sizeBytes,
                   checksum_sha256 = @sha256,
                   checksum_sha1 = @sha1,
                   origin = @origin,
                   vuln_checked_at = NULL,
                   updated_at = @now,
                   provenance_status = NULL,
                   provenance_signer = NULL,
                   upstream_integrity_value = @integrityValue,
                   upstream_integrity_algorithm = @integrityAlgorithm,
                   manifest_json = @manifestJson
             WHERE id = @id
            """,
            new { id = versionId, blobKey, sizeBytes, sha256, sha1, origin, now, integrityValue, integrityAlgorithm, manifestJson });
    }

}

public sealed record PackageListQuery(
    string OrgId,
    int Limit,
    int Offset,
    string? Ecosystem,
    string? Search = null,
    string SortBy = "created",
    string SortDir = "asc");

public sealed record NewPackageVersion(
    string PackageId,
    string Version,
    string Purl,
    string BlobKey,
    long SizeBytes,
    string? ChecksumSha256,
    // Required, with no default. package_versions is the hosted plane: the vulnerability sweep,
    // retention, the packages count and artifact_inventory all read it as such, so a row that says
    // otherwise is invisible to every one of them. Making the caller say it means the compiler
    // enforces that, rather than a comment asking nicely.
    string Origin,
    bool FirstFetch = false,
    DateTimeOffset? PublishedAt = null,  // upstream first-publish timestamp; null on capture failure or for uploaded versions
    string? ChecksumSha1 = null,         // hex SHA-1 (npm only — for packument dist.shasum); null elsewhere
    string? UpstreamIntegrityValue = null,      // upstream's published hash, verbatim in its native encoding
    string? UpstreamIntegrityAlgorithm = null,  // 'sha256' | 'sha512-sri' | 'sha512-b64'
    string? ManifestJson = null);        // install-relevant manifest subset (hosted npm publish); null elsewhere
