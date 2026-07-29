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
    /// One resolved file entry of a simple index, independent of wire format: what the merge rule
    /// decided should be advertised, before anything decides how to spell it. Both renderers read
    /// this and nothing else, so a rule that changes here changes in HTML and JSON at once.
    ///
    /// <paramref name="SizeBytes"/> is JSON-only (PEP 691 optional; PEP 503 HTML has no vehicle
    /// for it) and <paramref name="Yanked"/>/<paramref name="YankReason"/> are spelled differently
    /// per format (a <c>data-yanked</c> attribute vs. PEP 592's <c>reason | true | false</c>).
    /// Those are format differences, not merge differences — which is exactly the distinction this
    /// type exists to keep visible.
    /// </summary>
    public sealed record SimpleIndexFileEntry(
        string Filename, string? Sha256, long? SizeBytes, bool Yanked, string? YankReason);

    /// <summary>
    /// The one merge rule, applied once. Resolves the set of files a simple index should
    /// advertise for a package: locally-hosted versions first, then upstream entries that no local
    /// file already claimed.
    ///
    /// - Versions the download path would hard-block (manual block, deprecated, KEV, EPSS, CVSS,
    ///   release-age) are omitted, so the index never advertises an artifact that returns 403. The
    ///   shared predicate mirrors <c>BlockGateService.EvaluateAsync</c>, so this filter and the
    ///   download gate cannot diverge. Upstream-only (not-yet-cached) entries cannot be filtered
    ///   here — no stored state exists for them yet.
    /// - A hosted version with rows in <paramref name="hostedFiles"/> contributes one entry per
    ///   distribution file (wheel + sdist + per-platform wheels); a version without file rows
    ///   (synthetic proxy projection) contributes its single version-row artifact.
    /// - Filenames dedupe case-insensitively, first writer wins. Local files are collected before
    ///   upstream entries, so a filename published both places is listed once carrying the LOCAL
    ///   sha256 — matching the download path, which resolves an uploaded file before consulting
    ///   the proxy cache. Advertising the upstream digest for a filename served from local storage
    ///   would hand pip a hash it can never satisfy.
    /// </summary>
    public static List<SimpleIndexFileEntry> CollectSimpleIndexEntries(
        IReadOnlyList<PackageVersion> localVersions,
        ILookup<string, PackageVersionFile> hostedFiles,
        OrgSettings settings,
        IReadOnlyDictionary<string, VulnGateSignals> signals,
        DateTimeOffset now,
        IReadOnlyList<UpstreamSimpleIndexEntry> upstreamEntries)
    {
        var seenFilenames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var entries = new List<SimpleIndexFileEntry>();

        foreach (var v in localVersions)
        {
            if (BlockGateService.IsHardBlockedByStoredState(v, settings, signals.GetValueOrDefault(v.Id), now))
            {
                continue;
            }

            var files = hostedFiles[v.Id].ToList();
            if (files.Count == 0)
            {
                // Synthetic proxy projections carry exactly one artifact on the version row itself.
                string filename = string.IsNullOrEmpty(v.Filename) ? v.BlobKey.Split('/').Last() : v.Filename;
                AddEntry(entries, seenFilenames, new SimpleIndexFileEntry(
                    filename, v.ChecksumSha256, Positive(v.SizeBytes), v.Yanked, v.YankReason));
                continue;
            }

            // The block gate and yank state are per-version, so every file of a version shares them.
            foreach (var file in files)
            {
                AddEntry(entries, seenFilenames, new SimpleIndexFileEntry(
                    file.Filename, file.ChecksumSha256, Positive(file.SizeBytes), v.Yanked, v.YankReason));
            }
        }

        foreach (var upstream in upstreamEntries)
        {
            // Skips a duplicate anchor on the same upstream page as well as any filename a local
            // hosted file already claimed.
            AddEntry(entries, seenFilenames, new SimpleIndexFileEntry(
                upstream.Filename, upstream.Sha256, SizeBytes: null, Yanked: false, YankReason: null));
        }

        return entries;
    }

    private static void AddEntry(
        List<SimpleIndexFileEntry> entries, HashSet<string> seenFilenames, SimpleIndexFileEntry entry)
    {
        if (seenFilenames.Add(entry.Filename))
        {
            entries.Add(entry);
        }
    }

    // A recorded size of 0 means "not recorded", not "an empty file" — omitted rather than
    // advertised as zero.
    private static long? Positive(long sizeBytes) => sizeBytes > 0 ? sizeBytes : null;

    /// <summary>
    /// Renders a PEP 503 simple-index HTML page for a set of locally-hosted versions.
    /// </summary>
    public static string RenderLocalSimpleIndex(
        string purlName, IReadOnlyList<PackageVersion> versions, ILookup<string, PackageVersionFile> hostedFiles,
        OrgSettings settings, IReadOnlyDictionary<string, VulnGateSignals> signals, DateTimeOffset now) =>
        RenderSimpleIndexHtml(purlName, CollectSimpleIndexEntries(
            versions, hostedFiles, settings, signals, now, []));

    /// <summary>
    /// Renders the served simple-index page entirely from parsed data: locally-hosted versions
    /// merged with upstream file entries (already reduced to filename + sha256 by
    /// <see cref="ParseUpstreamSimpleIndexLinks"/>). No upstream HTML is ever copied into the
    /// response — every byte of the returned document is constructed here from HTML-encoded
    /// fragments, so a hostile or compromised upstream (or a MITM'd response) cannot inject
    /// markup that reaches the client, whether inside an unmatched anchor attribute or entirely
    /// outside any anchor (e.g. a stray <c>&lt;script&gt;</c> tag in the page body).
    /// </summary>
    public static string RenderMergedSimpleIndex(
        string purlName,
        IReadOnlyList<UpstreamSimpleIndexEntry> upstreamEntries,
        IReadOnlyList<PackageVersion> localVersions,
        ILookup<string, PackageVersionFile> hostedFiles,
        OrgSettings settings,
        IReadOnlyDictionary<string, VulnGateSignals> signals,
        DateTimeOffset now) =>
        RenderSimpleIndexHtml(purlName, CollectSimpleIndexEntries(
            localVersions, hostedFiles, settings, signals, now, upstreamEntries));

    // The PEP 503 rendering of a merged entry list. Every value is HTML-encoded here; nothing
    // upstream-supplied reaches the response un-encoded.
    private static string RenderSimpleIndexHtml(string purlName, List<SimpleIndexFileEntry> entries)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine($"<html><head><title>Links for {System.Web.HttpUtility.HtmlEncode(purlName)}</title></head><body>");
        sb.AppendLine($"<h1>Links for {System.Web.HttpUtility.HtmlEncode(purlName)}</h1>");

        foreach (var entry in entries)
        {
            string href = OrgPath($"packages/{entry.Filename}");
            if (entry.Sha256 is not null)
            {
                href += $"#sha256={entry.Sha256}";
            }

            string yankAttr = entry.Yanked
                ? $" data-yanked=\"{System.Web.HttpUtility.HtmlAttributeEncode(entry.YankReason ?? "")}\""
                : "";
            sb.AppendLine($"<a href=\"{System.Web.HttpUtility.HtmlAttributeEncode(href)}\"{yankAttr}>{System.Web.HttpUtility.HtmlEncode(entry.Filename)}</a><br/>");
        }

        sb.AppendLine("</body></html>");
        return sb.ToString();
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
    /// counterpart of <see cref="RenderLocalSimpleIndex"/>, off the same entry list, so a client
    /// negotiating JSON can never discover an artifact the HTML form (or the download gate) hides.
    /// </summary>
    public static string RenderLocalSimpleIndexJson(
        string purlName, IReadOnlyList<PackageVersion> versions, ILookup<string, PackageVersionFile> hostedFiles,
        OrgSettings settings, IReadOnlyDictionary<string, VulnGateSignals> signals, DateTimeOffset now) =>
        RenderSimpleIndexJson(purlName, CollectSimpleIndexEntries(
            versions, hostedFiles, settings, signals, now, []));

    /// <summary>
    /// Renders the PEP 691 JSON per-package index merged from locally-hosted versions plus parsed
    /// upstream file entries — the JSON counterpart of <see cref="RenderMergedSimpleIndex"/>, off
    /// the same entry list rather than a second implementation of the same merge rule.
    /// </summary>
    public static string RenderMergedSimpleIndexJson(
        string purlName,
        IReadOnlyList<UpstreamSimpleIndexEntry> upstreamEntries,
        IReadOnlyList<PackageVersion> localVersions,
        ILookup<string, PackageVersionFile> hostedFiles,
        OrgSettings settings,
        IReadOnlyDictionary<string, VulnGateSignals> signals,
        DateTimeOffset now) =>
        RenderSimpleIndexJson(purlName, CollectSimpleIndexEntries(
            localVersions, hostedFiles, settings, signals, now, upstreamEntries));

    // The PEP 691 rendering of a merged entry list.
    private static string RenderSimpleIndexJson(string purlName, List<SimpleIndexFileEntry> entries)
        => SerializePackageIndexJson(purlName, entries.Select(BuildJsonFileEntry).ToList());

    private static Dictionary<string, object?> BuildJsonFileEntry(SimpleIndexFileEntry entry)
    {
        var json = new Dictionary<string, object?>
        {
            ["filename"] = entry.Filename,
            ["url"] = OrgPath($"packages/{entry.Filename}"),
            ["hashes"] = entry.Sha256 is null
                ? new Dictionary<string, string>()
                : new Dictionary<string, string> { ["sha256"] = entry.Sha256 },
            ["yanked"] = YankedValue(entry.Yanked, entry.YankReason),
        };
        if (entry.SizeBytes is not null)
        {
            json["size"] = entry.SizeBytes;
        }
        return json;
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
