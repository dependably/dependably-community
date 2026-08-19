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

    /// <summary>
    /// The Accept this instance sends when fetching an upstream simple index. JSON is preferred
    /// because only the PEP 691 representation carries the PEP 700 <c>upload-time</c> the
    /// release-age arm needs to decide an entry nobody has fetched; HTML stays acceptable at a low
    /// q-value so an upstream that speaks only PEP 503 still answers rather than 406-ing.
    ///
    /// Every consumer of an upstream simple index sends this same value. Two consumers sending
    /// different Accepts for one URL would be two single-flight keys and two TTL-cache entries —
    /// invisible on a standard instance, where the upstream body cache is off by default and both
    /// already forward, but a doubling of simple-index traffic in edge mode, where that cache is
    /// on and absorbing exactly this load is the node's purpose.
    /// </summary>
    public const string UpstreamAccept = JsonContentType + ", text/html;q=0.01";

    /// <summary>
    /// Parses an upstream simple-index body in whichever representation the upstream actually
    /// returned, chosen by its declared content type rather than by what we asked for — an
    /// upstream is free to ignore the Accept, and several do.
    ///
    /// A body that declares the PEP 691 media type but does not parse is treated as an unusable
    /// upstream (the exception propagates to the caller's per-source catch, which moves to the
    /// next upstream and then to local-only), never as an upstream advertising nothing. Rendering
    /// an empty index from a malformed response would read to a client as "this package has no
    /// files", which is a far worse answer than falling back.
    /// </summary>
    public static List<UpstreamSimpleIndexEntry> ParseUpstreamSimpleIndex(string? contentType, string body) =>
        contentType is not null && contentType.Contains(JsonContentType, StringComparison.OrdinalIgnoreCase)
            ? ParseUpstreamSimpleIndexJson(body)
            : ParseUpstreamSimpleIndexLinks(body);

    // Serializer options for PEP 691 documents — created once and reused so every
    // serialization shares the same cached type metadata.
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    /// <summary>
    /// A single package-file entry parsed out of an upstream simple index, in either
    /// representation. Every other byte of the upstream response — surrounding markup, extra
    /// anchor attributes, unrecognised JSON members, non-anchor content such as a stray
    /// <c>&lt;script&gt;</c> tag — is discarded by the parser and never reaches the served index.
    ///
    /// PEP 503 HTML can only supply <paramref name="Filename"/>, <paramref name="Sha256"/> and
    /// <paramref name="Url"/>; the remaining fields arrive only from the PEP 691 JSON
    /// representation and stay null/false against an HTML upstream. That difference is load
    /// bearing: <paramref name="UploadTime"/> is what lets the release-age arm decide an entry
    /// nobody has fetched, so an HTML-only upstream leaves those entries undecidable and the arm
    /// fails open on them.
    /// </summary>
    public sealed record UpstreamSimpleIndexEntry(
        string Filename,
        string? Sha256,
        string? Url = null,
        DateTimeOffset? UploadTime = null,
        long? SizeBytes = null,
        bool Yanked = false,
        string? YankReason = null);

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
        return new UpstreamSimpleIndexEntry(filename, sha256, Url: hrefMatch.Groups[1].Value);
    }

    /// <summary>
    /// Parses an upstream PEP 691 JSON simple-index document into the same entry list the HTML
    /// parser produces, carrying the two facts HTML cannot express: PEP 700 <c>upload-time</c>,
    /// which is what makes the release-age arm decidable for a file nobody has fetched, and
    /// PEP 592 <c>yanked</c>.
    ///
    /// Upstream documents are semi-trusted, so every member degrades independently: a malformed
    /// or absent field yields null rather than throwing, and a file entry with no usable filename
    /// is dropped rather than failing the whole document. A body that is not a JSON object at all
    /// throws <see cref="JsonException"/> for the caller to treat as an unusable upstream —
    /// distinct from a well-formed document that happens to advertise nothing.
    /// </summary>
    public static List<UpstreamSimpleIndexEntry> ParseUpstreamSimpleIndexJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Object
            || !doc.RootElement.TryGetProperty("files", out var files)
            || files.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var entries = new List<UpstreamSimpleIndexEntry>();
        foreach (var file in files.EnumerateArray())
        {
            if (file.ValueKind == JsonValueKind.Object && TryParseJsonEntry(file) is { } entry)
            {
                entries.Add(entry);
            }
        }

        return entries;
    }

    // Maps one PEP 691 files[] member to an entry, or null when it carries no usable filename.
    private static UpstreamSimpleIndexEntry? TryParseJsonEntry(JsonElement file)
    {
        if (JsonString(file, "filename") is not { Length: > 0 } filename)
        {
            return null;
        }

        var (yanked, yankReason) = ParseJsonYanked(file);
        return new UpstreamSimpleIndexEntry(
            filename,
            Sha256: file.TryGetProperty("hashes", out var hashes) && hashes.ValueKind == JsonValueKind.Object
                ? JsonString(hashes, "sha256")
                : null,
            Url: JsonString(file, "url"),
            UploadTime: JsonString(file, "upload-time") is { } raw
                && DateTimeOffset.TryParse(raw, null, System.Globalization.DateTimeStyles.RoundtripKind, out var ts)
                    ? ts
                    : null,
            SizeBytes: file.TryGetProperty("size", out var size)
                && size.ValueKind == JsonValueKind.Number
                && size.TryGetInt64(out long bytes)
                    ? bytes
                    : null,
            Yanked: yanked,
            YankReason: yankReason);
    }

    // PEP 592/691 spell one yank three ways in a single member: `false`, `true`, or a non-empty
    // reason string. The legacy /pypi/{name}/json API instead pairs a boolean `yanked` with a
    // separate `yanked_reason`, which is why this cannot reuse LicenseExtractor.FromPyPiJsonFile —
    // that reader accepts only the boolean form, so against this document every string-form yank
    // (the common spelling on pypi.org) would read as not-yanked.
    private static (bool Yanked, string? Reason) ParseJsonYanked(JsonElement file)
    {
        if (!file.TryGetProperty("yanked", out var yanked))
        {
            return (false, null);
        }

        return yanked.ValueKind switch
        {
            JsonValueKind.True => (true, null),
            JsonValueKind.String => yanked.GetString() is { Length: > 0 } reason
                ? (true, reason)
                : (true, null),
            _ => (false, null),
        };
    }

    // Reads a string member, or null when absent or not a string — upstream documents are
    // semi-trusted, so a wrong-typed member must degrade rather than throw.
    private static string? JsonString(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

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
        string Filename, string? Sha256, long? SizeBytes, bool Yanked, string? YankReason,
        DateTimeOffset? UploadTime = null);

    /// <summary>
    /// The one merge rule, applied once. Resolves the set of files a simple index should
    /// advertise for a package: locally-hosted versions first, then upstream entries that no local
    /// file already claimed.
    ///
    /// - Versions the download path would hard-block (manual block, deprecated, KEV, EPSS, CVSS,
    ///   release-age) are omitted, so the index never advertises an artifact that returns 403. The
    ///   shared predicate mirrors <c>BlockGateService.EvaluateAsync</c>, so this filter and the
    ///   download gate cannot diverge.
    /// - A blocked version's filenames are still CLAIMED, so the upstream merge below cannot
    ///   re-advertise what the gate just removed. Blocking has to suppress a filename rather than
    ///   merely decline to emit it: a later merge step is free to re-add anything left unclaimed,
    ///   and for a proxied package the same filename is upstream almost by definition.
    /// - Upstream-only entries are gated too, on the facts an upstream index can carry: PEP 700
    ///   <c>upload-time</c> feeds the release-age arm and PEP 592 <c>yanked</c> the deprecation
    ///   arm. The rest of the gate needs an artifact nobody has fetched, so those arms stay a
    ///   first-fetch concern — see <c>VersionFacts.ForUpstreamOnly</c>.
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
            bool blocked = BlockGateService.IsHardBlockedByStoredState(
                v, settings, signals.GetValueOrDefault(v.Id), now);

            var files = hostedFiles[v.Id].ToList();
            if (files.Count == 0)
            {
                // Synthetic proxy projections carry exactly one artifact on the version row itself.
                string filename = string.IsNullOrEmpty(v.Filename) ? v.BlobKey.Split('/').Last() : v.Filename;
                AddEntry(entries, seenFilenames, blocked, new SimpleIndexFileEntry(
                    filename, v.ChecksumSha256, Positive(v.SizeBytes), v.Yanked, v.YankReason,
                    UploadTimeOf(v, v.CreatedAt)));
                continue;
            }

            // The block gate and yank state are per-version, so every file of a version shares them.
            foreach (var file in files)
            {
                AddEntry(entries, seenFilenames, blocked, new SimpleIndexFileEntry(
                    file.Filename, file.ChecksumSha256, Positive(file.SizeBytes), v.Yanked, v.YankReason,
                    UploadTimeOf(v, file.CreatedAt)));
            }
        }

        var policy = BlockPolicyFrom(settings);
        foreach (var upstream in upstreamEntries)
        {
            // Gated on the facts an upstream index carries, then deduped: this skips a duplicate
            // entry on the same upstream page as well as any filename a local version claimed —
            // whether that version was advertised or blocked.
            var facts = VersionFacts.ForUpstreamOnly(
                deprecated: upstream.Yanked ? upstream.YankReason ?? "Yanked" : null,
                publishedAt: upstream.UploadTime);

            AddEntry(entries, seenFilenames, !BlockGateService.Evaluate(facts, policy, now).Servable,
                new SimpleIndexFileEntry(
                    upstream.Filename, upstream.Sha256, upstream.SizeBytes,
                    upstream.Yanked, upstream.YankReason, upstream.UploadTime));
        }

        return entries;
    }

    // The PEP 700 upload-time to advertise for a locally-known file. A proxy projection carries
    // the upstream's own publish timestamp, which is the fact a downstream instance needs to
    // apply its own release-age hold; an uploaded version has no upstream timestamp (published_at
    // is NULL by construction for origin='uploaded') and its local ingest time IS when it was
    // published to this index, which is exactly what PEP 700 asks for.
    private static DateTimeOffset? UploadTimeOf(PackageVersion version, DateTimeOffset localCreatedAt) =>
        version.PublishedAt ?? localCreatedAt;

    // The tenant policy the upstream-entry arms read. Only the release-age and deprecation modes
    // can act on an unfetched coordinate, but the whole policy is projected rather than those two
    // fields, so a future arm that becomes decidable from index metadata needs no change here.
    private static BlockPolicy BlockPolicyFrom(OrgSettings settings) =>
        new(MinReleaseAgeHours: settings.MinReleaseAgeHours,
            BlockDeprecatedMode: settings.BlockDeprecated,
            BlockMaliciousMode: settings.BlockMalicious,
            BlockKevMode: settings.BlockKev,
            MaxEpssTolerance: settings.MaxEpssTolerance,
            MaxOsvScoreTolerance: settings.MaxOsvScoreTolerance,
            BlockInstallScriptsMode: settings.BlockInstallScripts,
            BlockRevokedMode: settings.BlockRevoked);

    // Claims a filename, and advertises it unless the gate blocked it. The claim happens either
    // way: a blocked filename must stay claimed so no later merge step can re-add it, which is the
    // difference between a filter that removes an entry and one that merely skips emitting it.
    private static void AddEntry(
        List<SimpleIndexFileEntry> entries, HashSet<string> seenFilenames, bool blocked,
        SimpleIndexFileEntry entry)
    {
        if (seenFilenames.Add(entry.Filename) && !blocked)
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

        // PEP 700 upload-time, emitted so this index composes: a downstream dependably or edge
        // node negotiating JSON from here needs it to apply its own release-age hold to entries
        // it has not fetched. Omitted rather than nulled when unknown — PEP 700 makes the member
        // optional, and a null would assert an upload time we do not have.
        if (entry.UploadTime is { } uploadTime)
        {
            json["upload-time"] = uploadTime.ToUtcIsoPrecise();
        }
        return json;
    }

    // Per PEP 592/691: false when not yanked; when yanked, a non-empty reason string, or the
    // boolean true when no reason was recorded. The `false`/`true` arms are PEP 592 wire values,
    // not redundant control-flow booleans — de-ternarying into if/else to satisfy S1125 re-trips
    // dotnet_style_prefer_conditional_expression_over_return (IDE0046, warning-as-error), the same
    // conflict class documented in .editorconfig for the S3358/IDE0046 nested-ternary case.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S1125:Boolean literals should not be redundant",
        Justification = "false/true here are PEP 592 wire values the JSON payload requires, not redundant " +
            "control-flow booleans; de-ternarying to satisfy this rule re-trips IDE0046 (warning-as-error).")]
    private static object YankedValue(bool yanked, string? yankReason) =>
        !yanked ? false : yankReason is { Length: > 0 } reason ? reason : true;

    // api-version stays 1.0 even though the file entries carry the PEP 700 `size` and
    // `upload-time` members. Declaring 1.1 would also assert the project-level `versions` member
    // that PEP 700 requires at that version and this document does not emit — a false capability
    // claim is worse than an extra optional member, and PEP 691 already requires clients to
    // ignore members they do not recognise.
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
