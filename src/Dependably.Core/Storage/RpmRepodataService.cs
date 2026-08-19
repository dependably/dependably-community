using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;

namespace Dependably.Storage;

/// <summary>
/// Generates the three documents <c>dnf</c>/<c>yum</c> read out of <c>repodata/</c>:
/// <c>repomd.xml</c> (index), <c>primary.xml</c> (per-package summary, dependencies,
/// file location, sizes, checksums), <c>filelists.xml</c> (per-package file paths extracted
/// from RPMTAG_BASENAMES/DIRNAMES/DIRINDEXES), and <c>other.xml</c> (per-package changelogs
/// extracted from RPMTAG_CHANGELOG* tags). Enough to drive <c>dnf repolist</c> +
/// <c>dnf install</c> + <c>dnf provides</c> against an arch-uniform repository.
/// </summary>
public sealed class RpmRepodataService
{
    // RPM repodata XML namespace identifiers, fixed by the repodata format (createrepo). These
    // are XML namespace names, not network endpoints — they are never resolved or fetched over
    // HTTP, so the http:// scheme is correct and required (changing it would break the format).
    private static readonly XNamespace CommonNs = "http://linux.duke.edu/metadata/common";
    private static readonly XNamespace RpmNs = "http://linux.duke.edu/metadata/rpm";
    private static readonly XNamespace RepoNs = "http://linux.duke.edu/metadata/repo";
    private static readonly XNamespace FilelistsNs = "http://linux.duke.edu/metadata/filelists";
    private static readonly XNamespace OtherNs = "http://linux.duke.edu/metadata/other";

    private readonly IMetadataStore _db;
    private readonly ILogger<RpmRepodataService> _logger;
    private readonly TimeProvider _time;
    private readonly OrgRepository _orgs;
    private readonly VulnerabilityRepository _vulns;

    public RpmRepodataService(
        IMetadataStore db, ILogger<RpmRepodataService> logger, TimeProvider time,
        OrgRepository orgs, VulnerabilityRepository vulns)
    {
        _db = db;
        _logger = logger;
        _time = time;
        _orgs = orgs;
        _vulns = vulns;
    }

    /// <summary>
    /// Builds the <c>primary.xml</c> document for one tenant. Streams every published RPM
    /// under that tenant in a single pass — <c>maven-metadata.xml</c>-style live render,
    /// since the rebuild service will cache the compressed result.
    /// </summary>
    public async Task<string> BuildPrimaryAsync(string orgId, CancellationToken ct)
    {
        var rows = await LoadLocalRowsAsync(orgId, ct);

        var common = CommonNs;
        var rpm = RpmNs;

        var doc = new XDocument(
            new XDeclaration("1.0", "UTF-8", null),
            new XElement(common + "metadata",
                new XAttribute(XNamespace.Xmlns + "rpm", rpm.NamespaceName),
                new XAttribute("packages", rows.Count),
                rows.Select(r => RenderPackage(r, common, rpm, _time.GetUtcNow()))));

        using var sw = new Utf8StringWriter();
        doc.Save(sw, SaveOptions.None);
        return sw.ToString();
    }

    /// <summary>
    /// Builds the <c>filelists.xml</c> document for one tenant. Each package gets a
    /// <c>&lt;package&gt;</c> element with all file paths extracted from the stored
    /// <c>files_json</c> column. Packages published before this feature was deployed have an
    /// empty <c>files_json</c> (<c>[]</c> default) and appear with no <c>&lt;file&gt;</c>
    /// children — valid per the filelists spec, and dnf handles them gracefully.
    /// </summary>
    public async Task<string> BuildFilelistsAsync(string orgId, CancellationToken ct)
    {
        var rows = await LoadLocalRowsAsync(orgId, ct);

        int packagesWithNoFiles = rows.Count(r => string.IsNullOrEmpty(r.FilesJson) || r.FilesJson == "[]");
        if (packagesWithNoFiles > 0)
        {
            _logger.LogInformation(
                "RPM filelists rebuild: {Count} package(s) in org {OrgId} have no stored file list — " +
                "their filelists entries will be empty. Re-publish to populate file data.",
                packagesWithNoFiles, orgId);
        }

        var fl = FilelistsNs;

        var doc = new XDocument(
            new XDeclaration("1.0", "UTF-8", null),
            new XElement(fl + "filelists",
                new XAttribute("packages", rows.Count),
                rows.Select(r => RenderFilelistPackage(r, fl))));

        using var sw = new Utf8StringWriter();
        doc.Save(sw, SaveOptions.None);
        return sw.ToString();
    }

    /// <summary>
    /// Builds the <c>other.xml</c> document for one tenant. Each package gets a
    /// <c>&lt;package&gt;</c> element with changelog entries extracted from the stored
    /// <c>changelogs_json</c> column. Packages with no changelog (empty JSON array or
    /// missing field) appear with no <c>&lt;changelog&gt;</c> children — spec-valid.
    /// </summary>
    public async Task<string> BuildOtherAsync(string orgId, CancellationToken ct)
    {
        var rows = await LoadLocalRowsAsync(orgId, ct);

        var other = OtherNs;

        var doc = new XDocument(
            new XDeclaration("1.0", "UTF-8", null),
            new XElement(other + "otherdata",
                new XAttribute("packages", rows.Count),
                rows.Select(r => RenderOtherPackage(r, other))));

        using var sw = new Utf8StringWriter();
        doc.Save(sw, SaveOptions.None);
        return sw.ToString();
    }

    /// <summary>
    /// Builds a combined, gzip-compressed <c>primary.xml.gz</c> for merged upstream mode: every
    /// locally published RPM under the tenant, unioned with the upstream repo's packages parsed
    /// from <paramref name="upstreamPrimaryGz"/>. Local packages shadow upstream on filename
    /// (NEVRA) collision so a published version always wins. Upstream <c>&lt;location href&gt;</c>
    /// values are rewritten to the flat <c>packages/{file}</c> form so dnf routes every download
    /// back through Dependably — a registry hit for local artefacts, a proxy fetch for upstream
    /// ones — rather than hitting the mirror directly.
    ///
    /// Serializes and gzip-compresses in one streamed pass (<see cref="SaveGzipped"/>) instead of
    /// building an intermediate UTF-16 string and a separate pre-gzip byte array — for a large
    /// upstream repo the unioned document itself can be tens of megabytes, so this avoids doubling
    /// that peak on the way out.
    /// </summary>
    public async Task<byte[]> BuildMergedPrimaryGzAsync(string orgId, byte[] upstreamPrimaryGz, CancellationToken ct)
    {
        var localRows = await LoadLocalRowsAsync(orgId, ct);

        var common = CommonNs;
        var rpm = RpmNs;

        var localFilenames = new HashSet<string>(
            localRows.Select(r => r.Filename ?? "").Where(f => f.Length > 0),
            StringComparer.OrdinalIgnoreCase);

        var localElements = localRows.Select(r => RenderPackage(r, common, rpm, _time.GetUtcNow()));
        var upstreamElements = ExtractUpstreamPackages(upstreamPrimaryGz, common, localFilenames);

        var all = localElements.Concat(upstreamElements).ToList();

        var doc = new XDocument(
            new XDeclaration("1.0", "UTF-8", null),
            new XElement(common + "metadata",
                new XAttribute(XNamespace.Xmlns + "rpm", rpm.NamespaceName),
                new XAttribute("packages", all.Count),
                all));

        return SaveGzipped(doc);
    }

    /// <summary>
    /// Builds a merged, gzip-compressed <c>filelists.xml.gz</c> for merged upstream mode. Local
    /// package entries are rendered from stored <c>files_json</c>; upstream filelists entries
    /// whose filenames are not shadowed by a local package are appended verbatim from
    /// <paramref name="upstreamFilelistsGz"/>. See <see cref="BuildMergedPrimaryGzAsync"/> for why
    /// this serializes directly to gzip bytes rather than an intermediate string.
    /// </summary>
    public async Task<byte[]> BuildMergedFilelistsGzAsync(string orgId, byte[] upstreamFilelistsGz, CancellationToken ct)
    {
        var localRows = await LoadLocalRowsAsync(orgId, ct);

        var fl = FilelistsNs;

        var localFilenames = new HashSet<string>(
            localRows.Select(r => r.Filename ?? "").Where(f => f.Length > 0),
            StringComparer.OrdinalIgnoreCase);

        var localElements = localRows.Select(r => RenderFilelistPackage(r, fl));
        var upstreamElements = ExtractUpstreamFilelistsPackages(upstreamFilelistsGz, fl, localFilenames);
        var all = localElements.Concat(upstreamElements).ToList();

        var doc = new XDocument(
            new XDeclaration("1.0", "UTF-8", null),
            new XElement(fl + "filelists",
                new XAttribute("packages", all.Count),
                all));

        return SaveGzipped(doc);
    }

    private async Task<List<RpmPrimaryRow>> LoadLocalRowsAsync(string orgId, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // Uploaded RPMs: sourced from package_versions (origin='uploaded') joined through packages.
        // xtenant: filtered by p.org_id = @orgId.
        // Proxy RPMs: sourced from cache_artifact joined via tenant_artifact_access for this org,
        // with rpm_metadata linked via owner_kind='cache_artifact'. Excludes uploaded rows from
        // this arm to prevent double-counting artefacts present in both planes during the P3
        // transition.
        // xtenant: tenant_artifact_access.org_id = @orgId scopes the global cache_artifact rows.
        var rows = (await conn.QueryAsync<RpmPrimaryRow>(
            """
            SELECT pv.id AS GateId,
                   'package_version' AS GatePlane,
                   pv.manual_block_state AS ManualBlockState,
                   pv.deprecated AS Deprecated,
                   pv.published_at AS PublishedAt,
                   pv.vuln_checked_at AS VulnCheckedAt,
                   -- CASE, not a bare EXISTS: Postgres types EXISTS as boolean while the
                   -- cache-plane arm below supplies an integer literal, and a UNION cannot
                   -- match the two. SQLite accepts either, so the mismatch is invisible there.
                   CASE WHEN EXISTS (SELECT 1 FROM package_version_vulns pvv
                           JOIN vulnerabilities v ON v.id = pvv.vuln_id
                           WHERE pvv.package_version_id = pv.id
                             AND v.osv_id LIKE 'MAL-%') THEN 1 ELSE 0 END AS IsMalicious,
                   pv.origin AS Origin,
                   pv.provenance_status AS ProvenanceStatus,
                   pv.revoked_at AS RevokedAt,
                   p.purl_name AS PurlName,
                   pv.version  AS Version,
                   pv.checksum_sha256 AS Sha256,
                   pv.size_bytes AS SizeBytes,
                   pv.blob_key AS BlobKey,
                   pv.filename AS Filename,
                   rm.rpm_name AS Name,
                   rm.arch     AS Arch,
                   rm.epoch    AS Epoch,
                   rm.rpm_version AS RpmVersion,
                   rm.rpm_release AS RpmRelease,
                   rm.summary  AS Summary,
                   rm.description AS Description,
                   rm.build_host AS BuildHost,
                   rm.build_time AS BuildTime,
                   rm.installed_size AS InstalledSize,
                   rm.archive_size   AS ArchiveSize,
                   rm.rpm_license    AS License,
                   rm.packager       AS Packager,
                   rm.url            AS Url,
                   rm.rpm_group      AS RpmGroup,
                   rm.source_rpm     AS SourceRpm,
                   rm.header_start   AS HeaderStart,
                   rm.header_end     AS HeaderEnd,
                   rm.files_json     AS FilesJson,
                   rm.changelogs_json AS ChangelogsJson
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            JOIN rpm_metadata rm ON rm.package_version_id = pv.id
                                 AND rm.owner_kind = 'package_version'
            WHERE p.org_id = @orgId AND p.ecosystem = 'rpm'
              AND pv.origin = 'uploaded'
            UNION ALL
            SELECT ca.id AS GateId,
                   'cache_artifact' AS GatePlane,
                   taa.manual_block_state AS ManualBlockState,
                   ca.deprecated AS Deprecated,
                   ca.published_at AS PublishedAt,
                   ca.vuln_checked_at AS VulnCheckedAt,
                   0 AS IsMalicious,
                   'proxy' AS Origin,
                   ca.provenance_status AS ProvenanceStatus,
                   ca.revoked_at AS RevokedAt,
                   ca.name AS PurlName,
                   ca.version AS Version,
                   COALESCE(taa.content_hash, ca.content_hash) AS Sha256,
                   COALESCE(taa.size_bytes, ca.size_bytes) AS SizeBytes,
                   COALESCE(taa.blob_key, ca.blob_key) AS BlobKey,
                   ca.filename AS Filename,
                   rm.rpm_name AS Name,
                   rm.arch     AS Arch,
                   rm.epoch    AS Epoch,
                   rm.rpm_version AS RpmVersion,
                   rm.rpm_release AS RpmRelease,
                   rm.summary  AS Summary,
                   rm.description AS Description,
                   rm.build_host AS BuildHost,
                   rm.build_time AS BuildTime,
                   rm.installed_size AS InstalledSize,
                   rm.archive_size   AS ArchiveSize,
                   rm.rpm_license    AS License,
                   rm.packager       AS Packager,
                   rm.url            AS Url,
                   rm.rpm_group      AS RpmGroup,
                   rm.source_rpm     AS SourceRpm,
                   rm.header_start   AS HeaderStart,
                   rm.header_end     AS HeaderEnd,
                   rm.files_json     AS FilesJson,
                   rm.changelogs_json AS ChangelogsJson
            FROM cache_artifact ca
            JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
                                            AND taa.org_id = @orgId
            JOIN rpm_metadata rm ON rm.cache_artifact_id = ca.id
                                 AND rm.owner_kind = 'cache_artifact'
            WHERE ca.ecosystem = 'rpm'
            ORDER BY PurlName, Sha256 DESC
            """,
            new { orgId })).ToList();

        return await FilterServableAsync(orgId, rows, ct);
    }

    /// <summary>
    /// Drops the packages this tenant's download gate would refuse, so repodata never advertises
    /// an RPM <c>GET /rpm/packages/{file}</c> answers 403 for. dnf resolves dependencies out of
    /// this document and commits to what it finds, so a listed-but-refused package fails a
    /// transaction after resolution rather than being routed around.
    ///
    /// Applied here rather than at each builder because all five documents — primary, filelists,
    /// other, and the two merged variants — read this one row set, and the <c>packages="N"</c>
    /// counts are computed from it. Filtering at the source keeps the count and the element list
    /// describing the same set by construction, which a per-builder filter would have to
    /// re-establish five times.
    ///
    /// A missing settings row withholds everything rather than filtering nothing: absent input
    /// must not read as "no policy configured", which on a gate is an allow decision.
    /// </summary>
    private async Task<List<RpmPrimaryRow>> FilterServableAsync(
        string orgId, List<RpmPrimaryRow> rows, CancellationToken ct)
    {
        if (rows.Count == 0)
        {
            return rows;
        }

        var settings = await _orgs.GetSettingsAsync(orgId, ct);
        if (settings is null)
        {
            return [];
        }

        // Two batched loads for the whole repository, not one per package: this document lists
        // every RPM the tenant holds, so a per-coordinate signal lookup would scale with the
        // catalogue on every rebuild.
        var pvIds = rows.Where(r => r.GatePlane == "package_version").Select(r => r.GateId).Distinct().ToList();
        var caIds = rows.Where(r => r.GatePlane == "cache_artifact").Select(r => r.GateId).Distinct().ToList();

        var pvSignals = pvIds.Count > 0
            ? await _vulns.GetGateSignalsBatchAsync(pvIds, ct)
            : new Dictionary<string, VulnGateSignals>();
        var caSignals = caIds.Count > 0
            ? await _vulns.GetGateSignalsBatchForCacheArtifactsAsync(caIds, ct)
            : new Dictionary<string, VulnGateSignals>();

        var policy = new BlockPolicy(
            MinReleaseAgeHours: settings.MinReleaseAgeHours,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance,
            MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance,
            BlockInstallScriptsMode: settings.BlockInstallScripts,
            VerifyProvenanceMode: settings.VerifyProvenanceMode("rpm"),
            BlockRevokedMode: settings.BlockRevoked);

        var now = _time.GetUtcNow();
        return [.. rows.Where(r => BlockGateService.Evaluate(FactsOf(r, pvSignals, caSignals), policy, now).Servable)];
    }

    // Projects one repodata row into the gate's fact shape. The signals come from whichever
    // plane's table the row was read from — a cache row's per-tenant block state already arrived
    // through tenant_artifact_access, so one tenant's decision cannot reach another's document.
    private static VersionFacts FactsOf(
        RpmPrimaryRow row,
        IReadOnlyDictionary<string, VulnGateSignals> pvSignals,
        IReadOnlyDictionary<string, VulnGateSignals> caSignals)
    {
        var signals = (row.GatePlane == "package_version" ? pvSignals : caSignals).GetValueOrDefault(row.GateId);
        return new VersionFacts(
            ManualState: row.ManualBlockState,
            Deprecated: row.Deprecated,
            PublishedAt: ParseInstant(row.PublishedAt),
            Scanned: row.VulnCheckedAt is not null,
            HasMalicious: row.IsMalicious != 0 || (signals?.HasMalicious ?? false),
            HasKev: signals?.HasKev ?? false,
            MaxEpss: signals?.MaxEpss,
            MaxCvss: signals?.MaxCvss,
            Origin: row.Origin,
            ProvenanceStatus: row.ProvenanceStatus,
            RevokedAt: ParseInstant(row.RevokedAt));
    }

    // Timestamps arrive as the stored ISO text because both planes are unioned into one shape and
    // the two providers bind their column types differently. An unparseable value reads as
    // unknown, which fails the release-age hold open — the gate's own posture for a missing date.
    private static DateTimeOffset? ParseInstant(string? value) =>
        DateTimeOffset.TryParse(
            value, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
            out var parsed)
            ? parsed
            : null;

    /// <summary>
    /// Decompresses the upstream <c>primary.xml.gz</c> and returns its <c>&lt;package&gt;</c>
    /// elements verbatim — preserving upstream sizes, checksums, and dependency metadata — with
    /// two adjustments: entries whose filename is in <paramref name="shadowed"/> are dropped
    /// (a local version supersedes them), and each <c>&lt;location&gt;</c> href is rewritten to
    /// the flat <c>packages/{file}</c> route (any <c>xml:base</c> stripped) so dnf fetches
    /// through Dependably rather than the mirror.
    /// </summary>
    private static List<XElement> ExtractUpstreamPackages(
        byte[] upstreamPrimaryGz, XNamespace common, HashSet<string> shadowed)
    {
        // Parse directly from the decompression stream — no intermediate xmlBytes byte[] copy
        // of what can be a 256 MiB decompressed document.
        using var limited = new LimitedReadStream(
            new GZipStream(new MemoryStream(upstreamPrimaryGz), CompressionMode.Decompress),
            RepodataDecompressLimits.MaxDecompressedBytes, "primary.xml.gz");
        var doc = XDocument.Load(limited);

        var result = new List<XElement>();
        // Snapshot the live Descendants query into a list before mutating the tree below
        // (Remove() during enumeration of a lazy query would throw).
        foreach (var pkg in doc.Descendants(common + "package").ToList())
        {
            if ((string?)pkg.Attribute("type") != "rpm")
            {
                continue;
            }

            string? href = (string?)pkg.Element(common + "location")?.Attribute("href");
            if (href is null)
            {
                continue;
            }

            string filename = href.Contains('/') ? href[(href.LastIndexOf('/') + 1)..] : href;
            if (shadowed.Contains(filename))
            {
                continue;
            }

            // Detach from the source doc (which is discarded once this method returns) instead
            // of cloning: LINQ to XML would otherwise silently deep-clone this element again
            // when the caller adds it to the merged document, doubling the retained package set.
            pkg.Remove();
            var location = pkg.Element(common + "location");
            location?.Attribute(XNamespace.Xml + "base")?.Remove();
            location?.SetAttributeValue("href", $"packages/{filename}");
            result.Add(pkg);
        }
        return result;
    }

    /// <summary>
    /// Decompresses the upstream <c>filelists.xml.gz</c> and returns its <c>&lt;package&gt;</c>
    /// elements, excluding any whose <c>name</c>+<c>arch</c>+<c>ver</c>+<c>rel</c> identifies a
    /// package already present in <paramref name="shadowed"/> (matched by filename convention
    /// <c>{name}-{ver}-{rel}.{arch}.rpm</c>). Elements for unshadowed packages are included verbatim.
    ///
    /// The filelists format carries no <c>&lt;location&gt;</c> element, so the shadow check
    /// reconstructs the canonical NEVRA filename from the package attributes. This matches the
    /// filename that <see cref="ExtractUpstreamPackages"/> uses for primary shadowing and that
    /// the upload handler stores as the <c>filename</c> column — upstream repos always use the
    /// canonical <c>{name}-{ver}-{rel}.{arch}.rpm</c> form, so this assumption holds for all
    /// standard RPM package filenames.
    /// </summary>
    private static List<XElement> ExtractUpstreamFilelistsPackages(
        byte[] upstreamFilelistsGz, XNamespace fl, HashSet<string> shadowed)
    {
        // Parse directly from the decompression stream — see ExtractUpstreamPackages.
        using var limited = new LimitedReadStream(
            new GZipStream(new MemoryStream(upstreamFilelistsGz), CompressionMode.Decompress),
            RepodataDecompressLimits.MaxDecompressedBytes, "filelists.xml.gz");
        var doc = XDocument.Load(limited);

        var result = new List<XElement>();
        foreach (var pkg in doc.Descendants(fl + "package").ToList())
        {
            string name = (string?)pkg.Attribute("name") ?? "";
            string arch = (string?)pkg.Attribute("arch") ?? "";
            var ver = pkg.Element(fl + "version");
            string rpmVer = (string?)ver?.Attribute("ver") ?? "";
            string rpmRel = (string?)ver?.Attribute("rel") ?? "";
            string filename = $"{name}-{rpmVer}-{rpmRel}.{arch}.rpm";
            if (!shadowed.Contains(filename))
            {
                // Detach rather than clone — see ExtractUpstreamPackages.
                pkg.Remove();
                result.Add(pkg);
            }
        }
        return result;
    }

    // XDocument.Save derives the XML declaration's `encoding` from the writer's
    // Encoding property. StringWriter is UTF-16, so saving to it emits
    // <?xml version="1.0" encoding="utf-16"?> even when XDeclaration says UTF-8 —
    // which then mismatches the UTF-8 bytes the controller sends and breaks dnf.
    private sealed class Utf8StringWriter : StringWriter
    {
        public override System.Text.Encoding Encoding => System.Text.Encoding.UTF8;
    }

    /// <summary>
    /// Builds <c>repomd.xml</c> pointing at all generated repodata documents. Takes the
    /// pre-compressed bytes for each document, computing SHA-256 and size for each entry so the
    /// document the client sees matches what they download.
    /// </summary>
    public static string BuildRepomd(
        byte[] primaryGz,
        DateTimeOffset now,
        byte[]? filelistsGz = null,
        byte[]? otherGz = null,
        IReadOnlyList<XElement>? extraEntries = null)
    {
        var repo = RepoNs;
        long revision = now.ToUnixTimeSeconds();

        var dataElements = new List<XElement>
        {
            BuildRepomdDataEntry(repo, "primary", "repodata/primary.xml.gz", primaryGz, revision),
        };

        if (filelistsGz is not null)
        {
            dataElements.Add(BuildRepomdDataEntry(repo, "filelists", "repodata/filelists.xml.gz", filelistsGz, revision));
        }

        if (otherGz is not null)
        {
            dataElements.Add(BuildRepomdDataEntry(repo, "other", "repodata/other.xml.gz", otherGz, revision));
        }

        if (extraEntries is not null)
        {
            dataElements.AddRange(extraEntries);
        }

        var doc = new XDocument(
            new XDeclaration("1.0", "UTF-8", null),
            new XElement(repo + "repomd",
                new XAttribute("revision", revision),
                dataElements));

        using var sw = new Utf8StringWriter();
        doc.Save(sw, SaveOptions.None);
        return sw.ToString();
    }

    private static XElement BuildRepomdDataEntry(XNamespace repo, string type, string href, byte[] gz, long timestamp)
    {
        string sha = Convert.ToHexString(SHA256.HashData(gz)).ToLowerInvariant();
        return new XElement(repo + "data",
            new XAttribute("type", type),
            new XElement(repo + "checksum",
                new XAttribute("type", "sha256"),
                sha),
            new XElement(repo + "location",
                new XAttribute("href", href)),
            new XElement(repo + "timestamp", timestamp),
            new XElement(repo + "size", gz.Length));
    }

    /// <summary>Gzip-compresses <paramref name="data"/> for repodata file downloads.</summary>
    public static byte[] Gzip(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
        {
            gz.Write(data, 0, data.Length);
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Serializes <paramref name="doc"/> and gzip-compresses it in one streamed pass, producing
    /// the same UTF-8-declared, indented XML content as <c>doc.Save(new Utf8StringWriter())</c>
    /// followed by <c>Gzip(Encoding.UTF8.GetBytes(...))</c> — but without ever materializing the
    /// intermediate UTF-16 string or the separate pre-gzip UTF-8 byte array. For a large merged
    /// document (local ∪ a big upstream repo) those two intermediates are each a full copy of the
    /// output, so folding serialize → encode → compress into one pass measurably lowers peak
    /// memory on the merged-repodata rebuild path.
    /// </summary>
    private static byte[] SaveGzipped(XDocument doc)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
        // UTF8Encoding(false): no BOM preamble, matching Encoding.UTF8.GetBytes(string) — the
        // declared "encoding=\"utf-8\"" in the XML prolog comes from this writer's Encoding.WebName.
        using (var writer = new StreamWriter(gz, new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false)))
        {
            doc.Save(writer, SaveOptions.None);
        }

        return ms.ToArray();
    }

    private static XElement RenderPackage(RpmPrimaryRow r, XNamespace common, XNamespace rpm, DateTimeOffset now)
    {
        return new XElement(common + "package",
            new XAttribute("type", "rpm"),
            new XElement(common + "name", r.Name),
            new XElement(common + "arch", r.Arch),
            new XElement(common + "version",
                new XAttribute("epoch", r.Epoch),
                new XAttribute("ver", r.RpmVersion),
                new XAttribute("rel", r.RpmRelease)),
            new XElement(common + "checksum",
                new XAttribute("type", "sha256"),
                new XAttribute("pkgid", "YES"),
                r.Sha256 ?? ""),
            new XElement(common + "summary", r.Summary ?? ""),
            new XElement(common + "description", r.Description ?? ""),
            new XElement(common + "packager", r.Packager ?? ""),
            new XElement(common + "url", r.Url ?? ""),
            new XElement(common + "time",
                new XAttribute("file", now.ToUnixTimeSeconds()),
                new XAttribute("build", r.BuildTime ?? 0)),
            new XElement(common + "size",
                new XAttribute("package", r.SizeBytes),
                new XAttribute("installed", r.InstalledSize),
                new XAttribute("archive", r.ArchiveSize)),
            new XElement(common + "location",
                new XAttribute("href", $"packages/{r.Filename}")),
            new XElement(common + "format",
                new XElement(rpm + "license", r.License ?? ""),
                new XElement(rpm + "vendor", ""),
                new XElement(rpm + "group", r.RpmGroup ?? ""),
                new XElement(rpm + "buildhost", r.BuildHost ?? ""),
                new XElement(rpm + "sourcerpm", r.SourceRpm ?? ""),
                new XElement(rpm + "header-range",
                    new XAttribute("start", r.HeaderStart),
                    new XAttribute("end", r.HeaderEnd))));
    }

    private static XElement RenderFilelistPackage(RpmPrimaryRow r, XNamespace fl)
    {
        var files = ParseFilesJson(r.FilesJson);

        return new XElement(fl + "package",
            new XAttribute("pkgid", r.Sha256 ?? ""),
            new XAttribute("name", r.Name),
            new XAttribute("arch", r.Arch),
            new XElement(fl + "version",
                new XAttribute("epoch", r.Epoch),
                new XAttribute("ver", r.RpmVersion),
                new XAttribute("rel", r.RpmRelease)),
            files.Select(f => RenderFileEntry(f, fl)));
    }

    private static XElement RenderFileEntry(RpmFileEntryDto f, XNamespace fl)
    {
        var el = new XElement(fl + "file", f.Path);
        if (!string.IsNullOrEmpty(f.Type) && f.Type != "file")
        {
            el.SetAttributeValue("type", f.Type);
        }
        return el;
    }

    private static XElement RenderOtherPackage(RpmPrimaryRow r, XNamespace other)
    {
        var changelogs = ParseChangelogsJson(r.ChangelogsJson);

        return new XElement(other + "package",
            new XAttribute("pkgid", r.Sha256 ?? ""),
            new XAttribute("name", r.Name),
            new XAttribute("arch", r.Arch),
            new XElement(other + "version",
                new XAttribute("epoch", r.Epoch),
                new XAttribute("ver", r.RpmVersion),
                new XAttribute("rel", r.RpmRelease)),
            changelogs.Select(c => new XElement(other + "changelog",
                new XAttribute("author", c.Author ?? ""),
                new XAttribute("date", c.Date),
                c.Text ?? "")));
    }

    // ── JSON helpers ────────────────────────────────────────────────────────────

    private static readonly JsonSerializerOptions JsonOpts =
        new() { PropertyNameCaseInsensitive = true };

    private static RpmFileEntryDto[] ParseFilesJson(string? json)
    {
        if (string.IsNullOrEmpty(json) || json == "[]")
        {
            return Array.Empty<RpmFileEntryDto>();
        }

        try
        {
            return JsonSerializer.Deserialize<RpmFileEntryDto[]>(json, JsonOpts) ?? Array.Empty<RpmFileEntryDto>();
        }
        catch
        {
            return Array.Empty<RpmFileEntryDto>();
        }
    }

    private static RpmChangelogDto[] ParseChangelogsJson(string? json)
    {
        if (string.IsNullOrEmpty(json) || json == "[]")
        {
            return Array.Empty<RpmChangelogDto>();
        }

        try
        {
            return JsonSerializer.Deserialize<RpmChangelogDto[]>(json, JsonOpts) ?? Array.Empty<RpmChangelogDto>();
        }
        catch
        {
            return Array.Empty<RpmChangelogDto>();
        }
    }

    // ── DTO records for JSON deserialization ────────────────────────────────────

    // Match the serialized shape of RpmFileEntry(string Path, string Type) and
    // RpmChangelog(string Author, int Date, string Text) from RpmHeaderParser.
    private sealed record RpmFileEntryDto(string? Path, string? Type);
    private sealed record RpmChangelogDto(string? Author, int Date, string? Text);

    // Positional record so Dapper binds via the constructor — avoids S1144/S3459 false
    // positives on per-property setters / unassigned auto-properties.
    // Integer columns bind as long, and [ExplicitConstructor] is what lets one signature serve
    // both providers — SQLite reports INTEGER as Int64, Postgres as Int32, and Dapper's default
    // positional-record binding demands an exact CLR match. See
    // DapperPositionalRecordComplianceTests.
    [method: ExplicitConstructor]
    private sealed record RpmPrimaryRow(
        // Row identity on whichever plane supplied it, used to key the batched vuln-signal load.
        string GateId,
        // Whether GateId names a package_versions row or a cache_artifact row. The two planes
        // carry their signals in different tables, so the discriminator has to survive the union.
        string GatePlane,
        string? ManualBlockState,
        string? Deprecated,
        string? PublishedAt,
        string? VulnCheckedAt,
        long IsMalicious,
        string? Origin,
        string? ProvenanceStatus,
        string? RevokedAt,
        string PurlName,
        string Version,
        string? Sha256,
        long SizeBytes,
        string BlobKey,
        string? Filename,
        string Name,
        string Arch,
        long Epoch,
        string RpmVersion,
        string RpmRelease,
        string? Summary,
        string? Description,
        string? BuildHost,
        long? BuildTime,
        long InstalledSize,
        long ArchiveSize,
        string? License,
        string? Packager,
        string? Url,
        string? RpmGroup,
        string? SourceRpm,
        long HeaderStart,
        long HeaderEnd,
        string? FilesJson,
        string? ChangelogsJson);
}
