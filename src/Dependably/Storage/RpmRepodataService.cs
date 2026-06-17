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

    public RpmRepodataService(IMetadataStore db, ILogger<RpmRepodataService> logger, TimeProvider time)
    {
        _db = db;
        _logger = logger;
        _time = time;
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
    /// Builds a combined <c>primary.xml</c> for merged upstream mode: every locally published
    /// RPM under the tenant, unioned with the upstream repo's packages parsed from
    /// <paramref name="upstreamPrimaryGz"/>. Local packages shadow upstream on filename (NEVRA)
    /// collision so a published version always wins. Upstream <c>&lt;location href&gt;</c> values
    /// are rewritten to the flat <c>packages/{file}</c> form so dnf routes every download back
    /// through Dependably — a registry hit for local artefacts, a proxy fetch for upstream ones —
    /// rather than hitting the mirror directly.
    /// </summary>
    public async Task<string> BuildMergedPrimaryAsync(string orgId, byte[] upstreamPrimaryGz, CancellationToken ct)
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

        using var sw = new Utf8StringWriter();
        doc.Save(sw, SaveOptions.None);
        return sw.ToString();
    }

    /// <summary>
    /// Builds a merged <c>filelists.xml</c> for merged upstream mode. Local package entries are
    /// rendered from stored <c>files_json</c>; upstream filelists entries whose filenames are not
    /// shadowed by a local package are appended verbatim from <paramref name="upstreamFilelistsGz"/>.
    /// </summary>
    public async Task<string> BuildMergedFilelistsAsync(string orgId, byte[] upstreamFilelistsGz, CancellationToken ct)
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

        using var sw = new Utf8StringWriter();
        doc.Save(sw, SaveOptions.None);
        return sw.ToString();
    }

    private async Task<List<RpmPrimaryRow>> LoadLocalRowsAsync(string orgId, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: explicit org_id filter on the join through packages.
        return (await conn.QueryAsync<RpmPrimaryRow>(
            """
            SELECT p.purl_name AS PurlName,
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
            WHERE p.org_id = @orgId AND p.ecosystem = 'rpm'
            ORDER BY p.purl_name, pv.created_at DESC
            """,
            new { orgId })).ToList();
    }

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
        byte[] xmlBytes;
        using (var limited = new LimitedReadStream(
            new GZipStream(new MemoryStream(upstreamPrimaryGz), CompressionMode.Decompress),
            RepodataDecompressLimits.MaxDecompressedBytes, "primary.xml.gz"))
        using (var ms = new MemoryStream())
        {
            limited.CopyTo(ms);
            xmlBytes = ms.ToArray();
        }

        var doc = XDocument.Load(new MemoryStream(xmlBytes));
        var result = new List<XElement>();
        foreach (var pkg in doc.Descendants(common + "package"))
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

            var clone = new XElement(pkg);
            var cloneLocation = clone.Element(common + "location");
            cloneLocation?.Attribute(XNamespace.Xml + "base")?.Remove();
            cloneLocation?.SetAttributeValue("href", $"packages/{filename}");
            result.Add(clone);
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
        byte[] xmlBytes;
        using (var limited = new LimitedReadStream(
            new GZipStream(new MemoryStream(upstreamFilelistsGz), CompressionMode.Decompress),
            RepodataDecompressLimits.MaxDecompressedBytes, "filelists.xml.gz"))
        using (var ms = new MemoryStream())
        {
            limited.CopyTo(ms);
            xmlBytes = ms.ToArray();
        }

        var doc = XDocument.Load(new MemoryStream(xmlBytes));
        var result = new List<XElement>();
        foreach (var pkg in doc.Descendants(fl + "package"))
        {
            string name = (string?)pkg.Attribute("name") ?? "";
            string arch = (string?)pkg.Attribute("arch") ?? "";
            var ver = pkg.Element(fl + "version");
            string rpmVer = (string?)ver?.Attribute("ver") ?? "";
            string rpmRel = (string?)ver?.Attribute("rel") ?? "";
            string filename = $"{name}-{rpmVer}-{rpmRel}.{arch}.rpm";
            if (!shadowed.Contains(filename))
            {
                result.Add(new XElement(pkg));
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
    // INTEGER columns must bind as long: SQLite returns INTEGER as Int64 and Dapper's
    // constructor binder won't narrow Int64→Int32. (Postgres INTEGER widens cleanly.)
    private sealed record RpmPrimaryRow(
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
