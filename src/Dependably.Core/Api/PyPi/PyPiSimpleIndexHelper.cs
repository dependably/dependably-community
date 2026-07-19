using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Dependably.Infrastructure;
using Dependably.Protocol;

namespace Dependably.Api.PyPiProtocol;

/// <summary>
/// Pure-static helpers for PEP 503 simple-index HTML generation, PEP 691 JSON Simple API
/// generation, and upstream rewriting. Shared by <see cref="PyPiSimpleIndexHandler"/> and
/// referenced by unit tests.
/// </summary>
public static class PyPiSimpleIndexHelper
{
    /// <summary>The PEP 691 JSON Simple API media type, negotiated via the request's Accept header.</summary>
    public const string JsonContentType = "application/vnd.pypi.simple.v1+json";

    // Serializer options for PEP 691 documents — created once and reused so every
    // serialization shares the same cached type metadata.
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    /// <summary>
    /// A single package-file entry parsed out of an upstream PEP 503 simple-index page: just
    /// the anchor text (filename) and the optional <c>sha256</c> fragment. Every other byte of
    /// the upstream response — surrounding markup, extra anchor attributes, non-anchor content
    /// such as a stray <c>&lt;script&gt;</c> tag — is discarded by the parser and never reaches
    /// the served index.
    /// </summary>
    public sealed record UpstreamSimpleIndexEntry(string Filename, string? Sha256);

    /// <summary>
    /// Parses an upstream PEP 503 simple-index page into a flat list of file entries. Only the
    /// text and <c>href</c> of well-formed <c>&lt;a href="https://…"&gt;text&lt;/a&gt;</c>
    /// anchors are extracted — nothing else about the upstream page (its surrounding markup,
    /// any other anchor attribute, or any content outside a matched anchor) is retained. The
    /// served index is always re-rendered from this parsed list by
    /// <see cref="RenderMergedSimpleIndex"/>, never by copying upstream HTML — so a hostile or
    /// compromised upstream (or a MITM'd response) cannot inject markup that reaches the
    /// client, whether inside an unmatched anchor attribute or entirely outside any anchor.
    ///
    /// The anchor's attribute run is matched inside an atomic group (<c>(?&gt;…)</c>) whose
    /// alternatives are disjoint on their first character (unquoted run vs. quoted string), so
    /// matching is linear over attacker-controlled upstream HTML — the engine can neither
    /// backtrack into an alternative nor give back iterations. The 2-second RegexTimeout stays
    /// as defence-in-depth.
    /// </summary>
    public static List<UpstreamSimpleIndexEntry> ParseUpstreamSimpleIndexLinks(string html) =>
        Regex.Matches(
                html,
                @"<a\b((?>(?:[^>""']+|""[^""]*""|'[^']*')*))>([^<]+)</a>",
                RegexOptions.None,
                PyPiConstants.RegexTimeout)
            .Select(m => m.Groups)
            .Select(TryParseEntry)
            .OfType<UpstreamSimpleIndexEntry>()
            .ToList();

    // Maps one matched anchor's captured groups to an entry, or null when the anchor's text
    // is empty or its href doesn't match the expected upstream file-link shape.
    private static UpstreamSimpleIndexEntry? TryParseEntry(GroupCollection groups)
    {
        string attrs = groups[1].Value;
        string filename = groups[2].Value.Trim();
        if (filename.Length == 0)
        {
            return null;
        }

        var hrefMatch = Regex.Match(attrs, @"href=""(https?://[^""#]+)(#[^""]*)?""", RegexOptions.None, PyPiConstants.RegexTimeout);
        if (!hrefMatch.Success)
        {
            return null;
        }

        string fragment = hrefMatch.Groups[2].Value;
        const string Sha256Prefix = "#sha256=";
        string? sha256 = fragment.StartsWith(Sha256Prefix, StringComparison.OrdinalIgnoreCase)
            ? fragment[Sha256Prefix.Length..]
            : null;
        return new UpstreamSimpleIndexEntry(filename, sha256);
    }

    /// <summary>
    /// An empty per-version file lookup, for callers rendering versions that carry their single
    /// artifact directly on the version row (synthetic proxy projections, tests).
    /// </summary>
    public static readonly ILookup<string, PackageVersionFile> NoHostedFiles =
        Array.Empty<PackageVersionFile>().ToLookup(f => f.PackageVersionId);

    /// <summary>
    /// Renders a PEP 503 simple-index HTML page for a set of locally-hosted versions.
    /// Versions blocked by the block gate (manual block, deprecated, KEV, EPSS, CVSS,
    /// release-age) are omitted so the index never advertises an artifact that returns 403.
    /// A hosted version with rows in <paramref name="hostedFiles"/> renders one anchor per
    /// distribution file (wheel + sdist + per-platform wheels); versions without file rows
    /// (synthetic proxy projections) render their single version-row artifact.
    /// </summary>
    public static string RenderLocalSimpleIndex(
        string purlName, IReadOnlyList<PackageVersion> versions, ILookup<string, PackageVersionFile> hostedFiles,
        OrgSettings settings, IReadOnlyDictionary<string, VulnGateSignals> signals, DateTimeOffset now)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine($"<html><head><title>Links for {System.Web.HttpUtility.HtmlEncode(purlName)}</title></head><body>");
        sb.AppendLine($"<h1>Links for {System.Web.HttpUtility.HtmlEncode(purlName)}</h1>");
        var seenFilenames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        AppendLocalVersions(sb, versions, hostedFiles, settings, signals, now, seenFilenames);
        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    /// <summary>
    /// Renders the served simple-index page entirely from parsed data: locally-hosted versions
    /// merged with upstream file entries (already reduced to filename + sha256 by
    /// <see cref="ParseUpstreamSimpleIndexLinks"/>). No upstream HTML is ever copied into the
    /// response — every byte of the returned document is constructed here from HTML-encoded
    /// fragments, so a hostile or compromised upstream (or a MITM'd response) cannot inject
    /// markup that reaches the client, whether inside an unmatched anchor attribute or entirely
    /// outside any anchor (e.g. a stray <c>&lt;script&gt;</c> tag in the page body).
    ///
    /// Local hosted files are rendered first, so a filename published both upstream and locally
    /// is listed once carrying the LOCAL <c>sha256</c>. This matches the download path, which
    /// resolves an uploaded file before consulting the proxy cache/upstream — advertising the
    /// upstream digest for a filename served from local storage would hand pip a hash it can
    /// never satisfy. Upstream-only (not-yet-cached) versions cannot be filtered by the block
    /// gate here because stored state does not exist for them yet.
    /// </summary>
    public static string RenderMergedSimpleIndex(
        string purlName,
        IReadOnlyList<UpstreamSimpleIndexEntry> upstreamEntries,
        IReadOnlyList<PackageVersion> localVersions,
        ILookup<string, PackageVersionFile> hostedFiles,
        OrgSettings settings,
        IReadOnlyDictionary<string, VulnGateSignals> signals,
        DateTimeOffset now)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine($"<html><head><title>Links for {System.Web.HttpUtility.HtmlEncode(purlName)}</title></head><body>");
        sb.AppendLine($"<h1>Links for {System.Web.HttpUtility.HtmlEncode(purlName)}</h1>");

        var seenFilenames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        AppendLocalVersions(sb, localVersions, hostedFiles, settings, signals, now, seenFilenames);
        AppendUpstreamEntries(sb, upstreamEntries, seenFilenames);

        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    // Renders one anchor per not-yet-seen upstream entry, skipping a duplicate anchor on the
    // same upstream page and any filename already emitted by a local hosted version (the local
    // file wins the dedupe so the advertised sha256 matches the blob the download path serves).
    private static void AppendUpstreamEntries(
        StringBuilder sb, IReadOnlyList<UpstreamSimpleIndexEntry> upstreamEntries, HashSet<string> seenFilenames)
    {
        foreach (var entry in upstreamEntries)
        {
            if (!seenFilenames.Add(entry.Filename))
            {
                continue; // duplicate anchor on the same upstream page
            }

            string href = OrgPath($"packages/{entry.Filename}");
            if (entry.Sha256 is not null)
            {
                href += $"#sha256={entry.Sha256}";
            }

            sb.AppendLine($"<a href=\"{System.Web.HttpUtility.HtmlAttributeEncode(href)}\">{System.Web.HttpUtility.HtmlEncode(entry.Filename)}</a><br/>");
        }
    }

    // Renders anchors for each locally-hosted version not hard-blocked: one anchor per hosted
    // distribution file when the version has file rows, otherwise the version row's single
    // artifact (synthetic proxy projections). Local files are emitted before upstream entries
    // in the merged index, so a filename hosted locally claims the seenFilenames slot with its
    // own sha256 before any colliding upstream entry can. The block gate and yank state are
    // per-version, so every file of a version shares them.
    private static void AppendLocalVersions(
        StringBuilder sb, IReadOnlyList<PackageVersion> localVersions,
        ILookup<string, PackageVersionFile> hostedFiles, OrgSettings settings,
        IReadOnlyDictionary<string, VulnGateSignals> signals, DateTimeOffset now, HashSet<string> seenFilenames)
    {
        foreach (var v in localVersions)
        {
            // Omit versions the download path will hard-block so they are never advertised.
            // The shared predicate mirrors BlockGateService.EvaluateAsync exactly so this
            // filter and the download gate can never diverge.
            if (BlockGateService.IsHardBlockedByStoredState(v, settings, signals.GetValueOrDefault(v.Id), now))
            {
                continue;
            }

            var files = hostedFiles[v.Id].ToList();
            if (files.Count == 0)
            {
                string filename = string.IsNullOrEmpty(v.Filename) ? v.BlobKey.Split('/').Last() : v.Filename;
                AppendFileAnchor(sb, v, filename, v.ChecksumSha256, seenFilenames);
                continue;
            }

            foreach (var file in files)
            {
                AppendFileAnchor(sb, v, file.Filename, file.ChecksumSha256, seenFilenames);
            }
        }
    }

    // Renders one file anchor with the per-file sha256 fragment and the owning version's yank
    // state, skipping filenames already listed (first writer wins; duplicates collapse). In the
    // merged index local files are appended first, so a locally-hosted filename always wins a
    // collision with an upstream entry of the same name.
    private static void AppendFileAnchor(
        StringBuilder sb, PackageVersion v, string filename, string? sha256, HashSet<string> seenFilenames)
    {
        if (!seenFilenames.Add(filename))
        {
            return;
        }

        string href = OrgPath($"packages/{filename}");
        if (sha256 is not null)
        {
            href += $"#sha256={sha256}";
        }

        string yankAttr = v.Yanked
            ? $" data-yanked=\"{System.Web.HttpUtility.HtmlAttributeEncode(v.YankReason ?? "")}\""
            : "";
        sb.AppendLine($"<a href=\"{System.Web.HttpUtility.HtmlAttributeEncode(href)}\"{yankAttr}>{System.Web.HttpUtility.HtmlEncode(filename)}</a><br/>");
    }

    /// <summary>
    /// Renders the PEP 691 JSON root index (GET /simple/): the flat list of project names,
    /// the JSON counterpart of the anchor list <see cref="PyPiSimpleIndexHandler.SimpleIndexAsync"/>
    /// renders as HTML.
    /// </summary>
    public static string RenderProjectListJson(IEnumerable<string> names)
    {
        var doc = new Dictionary<string, object?>
        {
            ["meta"] = new Dictionary<string, object?> { ["api-version"] = "1.0" },
            ["projects"] = names.Select(n => new Dictionary<string, object?> { ["name"] = n }).ToList(),
        };
        return JsonSerializer.Serialize(doc, JsonOptions);
    }

    /// <summary>
    /// Renders the PEP 691 JSON per-package index for locally-hosted versions only — the JSON
    /// counterpart of <see cref="RenderLocalSimpleIndex"/>. Shares the same block-gate filtering
    /// so a client negotiating JSON can never discover an artifact the HTML form (or the
    /// download gate) would hide.
    /// </summary>
    public static string RenderLocalSimpleIndexJson(
        string purlName, IReadOnlyList<PackageVersion> versions, ILookup<string, PackageVersionFile> hostedFiles,
        OrgSettings settings, IReadOnlyDictionary<string, VulnGateSignals> signals, DateTimeOffset now)
    {
        var seenFilenames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var files = CollectLocalJsonFiles(versions, hostedFiles, settings, signals, now, seenFilenames);
        return SerializePackageIndexJson(purlName, files);
    }

    /// <summary>
    /// Renders the PEP 691 JSON per-package index merged from locally-hosted versions plus parsed
    /// upstream file entries — the JSON counterpart of <see cref="RenderMergedSimpleIndex"/>,
    /// applying the identical merge rule.
    ///
    /// Local hosted files are collected first, so a filename published both upstream and locally
    /// is listed once carrying the LOCAL <c>sha256</c>. This matches the download path, which
    /// resolves an uploaded file before consulting the proxy cache/upstream — advertising the
    /// upstream digest for a filename served from local storage would hand pip a hash it can
    /// never satisfy. Upstream-only (not-yet-cached) versions cannot be filtered by the block
    /// gate here because stored state does not exist for them yet.
    /// </summary>
    public static string RenderMergedSimpleIndexJson(
        string purlName,
        IReadOnlyList<UpstreamSimpleIndexEntry> upstreamEntries,
        IReadOnlyList<PackageVersion> localVersions,
        ILookup<string, PackageVersionFile> hostedFiles,
        OrgSettings settings,
        IReadOnlyDictionary<string, VulnGateSignals> signals,
        DateTimeOffset now)
    {
        var seenFilenames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var files = CollectLocalJsonFiles(localVersions, hostedFiles, settings, signals, now, seenFilenames);
        foreach (var entry in upstreamEntries)
        {
            // Skips a duplicate anchor on the same upstream page and any filename already
            // emitted by a local hosted version (the local file wins the dedupe so the
            // advertised sha256 matches the blob the download path serves).
            if (!seenFilenames.Add(entry.Filename))
            {
                continue;
            }

            files.Add(BuildJsonFileEntry(entry.Filename, entry.Sha256, size: null, yanked: false, yankReason: null));
        }

        return SerializePackageIndexJson(purlName, files);
    }

    // Builds the JSON file-entry list for locally-hosted versions not hard-blocked and not
    // already present in seenFilenames: one entry per hosted distribution file when the version
    // has file rows, otherwise the version row's single artifact (synthetic proxy projections).
    // Mirrors AppendLocalVersions's filtering exactly so the HTML and JSON forms never diverge.
    private static List<Dictionary<string, object?>> CollectLocalJsonFiles(
        IReadOnlyList<PackageVersion> localVersions, ILookup<string, PackageVersionFile> hostedFiles,
        OrgSettings settings, IReadOnlyDictionary<string, VulnGateSignals> signals, DateTimeOffset now,
        HashSet<string> seenFilenames)
    {
        var result = new List<Dictionary<string, object?>>();
        foreach (var v in localVersions)
        {
            if (BlockGateService.IsHardBlockedByStoredState(v, settings, signals.GetValueOrDefault(v.Id), now))
            {
                continue;
            }

            var files = hostedFiles[v.Id].ToList();
            if (files.Count == 0)
            {
                AddSingleArtifactJsonEntry(v, seenFilenames, result);
                continue;
            }

            result.AddRange(files
                .Where(file => seenFilenames.Add(file.Filename))
                .Select(file => BuildJsonFileEntry(
                    file.Filename, file.ChecksumSha256, file.SizeBytes > 0 ? file.SizeBytes : null, v.Yanked, v.YankReason)));
        }
        return result;
    }

    // Emits the version row's single artifact when no per-file rows exist (synthetic proxy
    // projections carry exactly one artifact on the version row itself).
    private static void AddSingleArtifactJsonEntry(
        PackageVersion v, HashSet<string> seenFilenames, List<Dictionary<string, object?>> result)
    {
        string filename = string.IsNullOrEmpty(v.Filename) ? v.BlobKey.Split('/').Last() : v.Filename;
        if (seenFilenames.Add(filename))
        {
            result.Add(BuildJsonFileEntry(
                filename, v.ChecksumSha256, v.SizeBytes > 0 ? v.SizeBytes : null, v.Yanked, v.YankReason));
        }
    }

    private static Dictionary<string, object?> BuildJsonFileEntry(
        string filename, string? sha256, long? size, bool yanked, string? yankReason)
    {
        var entry = new Dictionary<string, object?>
        {
            ["filename"] = filename,
            ["url"] = OrgPath($"packages/{filename}"),
            ["hashes"] = sha256 is null
                ? new Dictionary<string, string>()
                : new Dictionary<string, string> { ["sha256"] = sha256 },
            ["yanked"] = YankedValue(yanked, yankReason),
        };
        if (size is not null)
        {
            entry["size"] = size;
        }
        return entry;
    }

    // Per PEP 592/691: false when not yanked; when yanked, a non-empty reason string, or the
    // boolean true when no reason was recorded. The `false`/`true` arms are PEP 592 wire values,
    // not redundant control-flow booleans — de-ternarying into if/else to satisfy S1125 re-trips
    // dotnet_style_prefer_conditional_expression_over_return (IDE0046, warning-as-error), the same
    // conflict class documented in .editorconfig for the S3358/IDE0046 nested-ternary case.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S1125:Boolean literals should not be redundant",
        Justification = "false/true here are PEP 592 wire values the JSON payload requires, not redundant control-flow booleans; de-ternarying to satisfy this rule re-trips IDE0046 (warning-as-error).")]
    private static object YankedValue(bool yanked, string? yankReason) =>
        !yanked ? false : yankReason is { Length: > 0 } reason ? reason : true;

    private static string SerializePackageIndexJson(string purlName, List<Dictionary<string, object?>> files)
    {
        var doc = new Dictionary<string, object?>
        {
            ["meta"] = new Dictionary<string, object?> { ["api-version"] = "1.0" },
            ["name"] = purlName,
            ["files"] = files,
        };
        return JsonSerializer.Serialize(doc, JsonOptions);
    }

    /// <summary>
    /// Computes a quoted ETag from the first 16 hex chars of the SHA-256 digest of
    /// <paramref name="bytes"/> (64 bits of entropy).
    /// </summary>
    public static string ComputeETag(byte[] bytes)
    {
        byte[] hash = SHA256.HashData(bytes);
        return "\"" + Convert.ToHexString(hash)[..PyPiConstants.ETagHexPrefixLength].ToLowerInvariant() + "\"";
    }

    /// <summary>
    /// Returns a host-relative URL for a PEP 503 href. Tenancy is host-resolved, so paths
    /// are always root-relative with no org prefix.
    /// </summary>
    public static string OrgPath(string rest) => "/" + rest;
}
