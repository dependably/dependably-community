using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Dependably.Infrastructure;
using Dependably.Protocol;

namespace Dependably.Api.PyPiProtocol;

/// <summary>
/// Pure-static helpers for PEP 503 simple-index HTML generation and upstream rewriting.
/// Shared by <see cref="PyPiSimpleIndexHandler"/> and referenced by unit tests.
/// </summary>
public static class PyPiSimpleIndexHelper
{
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
    public static List<UpstreamSimpleIndexEntry> ParseUpstreamSimpleIndexLinks(string html)
    {
        var entries = new List<UpstreamSimpleIndexEntry>();
        foreach (Match m in Regex.Matches(
            html,
            @"<a\b((?>(?:[^>""']+|""[^""]*""|'[^']*')*))>([^<]+)</a>",
            RegexOptions.None,
            PyPiConstants.RegexTimeout))
        {
            string attrs = m.Groups[1].Value;
            string filename = m.Groups[2].Value.Trim();
            if (filename.Length == 0)
            {
                continue;
            }

            var hrefMatch = Regex.Match(attrs, @"href=""(https?://[^""#]+)(#[^""]*)?""", RegexOptions.None, PyPiConstants.RegexTimeout);
            if (!hrefMatch.Success)
            {
                continue;
            }

            string fragment = hrefMatch.Groups[2].Value;
            const string Sha256Prefix = "#sha256=";
            string? sha256 = fragment.StartsWith(Sha256Prefix, StringComparison.OrdinalIgnoreCase)
                ? fragment[Sha256Prefix.Length..]
                : null;
            entries.Add(new UpstreamSimpleIndexEntry(filename, sha256));
        }

        return entries;
    }

    /// <summary>
    /// Renders a PEP 503 simple-index HTML page for a set of locally-hosted versions.
    /// Versions blocked by the block gate (manual block, deprecated, KEV, EPSS, CVSS,
    /// release-age) are omitted so the index never advertises an artifact that returns 403.
    /// </summary>
    public static string RenderLocalSimpleIndex(
        string purlName, IReadOnlyList<PackageVersion> versions, OrgSettings settings,
        IReadOnlyDictionary<string, VulnGateSignals> signals, DateTimeOffset now)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine($"<html><head><title>Links for {System.Web.HttpUtility.HtmlEncode(purlName)}</title></head><body>");
        sb.AppendLine($"<h1>Links for {System.Web.HttpUtility.HtmlEncode(purlName)}</h1>");
        foreach (var v in versions)
        {
            // Omit versions the download path will hard-block so the index never advertises
            // an artifact that returns 403. The shared predicate mirrors BlockGateService.EvaluateAsync
            // exactly: manual-block, deprecated (block_all/block only), release-age, malicious,
            // KEV, EPSS, and CVSS arms. block_new is intentionally excluded — it only fires on
            // first-fetch, and already-cached deprecated versions still serve under that mode.
            if (BlockGateService.IsHardBlockedByStoredState(v, settings, signals.GetValueOrDefault(v.Id), now))
            {
                continue;
            }

            string filename = string.IsNullOrEmpty(v.Filename) ? v.BlobKey.Split('/').Last() : v.Filename;
            string href = OrgPath($"packages/{filename}");
            if (v.ChecksumSha256 is not null)
            {
                href += $"#sha256={v.ChecksumSha256}";
            }

            string yankAttr = v.Yanked
                ? $" data-yanked=\"{System.Web.HttpUtility.HtmlAttributeEncode(v.YankReason ?? "")}\"" : "";

            sb.AppendLine($"<a href=\"{System.Web.HttpUtility.HtmlAttributeEncode(href)}\"{yankAttr}>{System.Web.HttpUtility.HtmlEncode(filename)}</a><br/>");
        }
        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    /// <summary>
    /// Renders the served simple-index page entirely from parsed data: upstream file entries
    /// (already reduced to filename + sha256 by <see cref="ParseUpstreamSimpleIndexLinks"/>)
    /// merged with locally-hosted versions. No upstream HTML is ever copied into the response
    /// — every byte of the returned document is constructed here from HTML-encoded fragments,
    /// so a hostile or compromised upstream (or a MITM'd response) cannot inject markup that
    /// reaches the client, whether inside an unmatched anchor attribute or entirely outside any
    /// anchor (e.g. a stray <c>&lt;script&gt;</c> tag in the page body). Filenames already
    /// present in the upstream entries are skipped when rendering local versions, so a name
    /// published both upstream and locally is listed once. Upstream-only (not-yet-cached)
    /// versions cannot be filtered by the block gate here because stored state does not exist
    /// for them yet.
    /// </summary>
    public static string RenderMergedSimpleIndex(
        string purlName,
        IReadOnlyList<UpstreamSimpleIndexEntry> upstreamEntries,
        IReadOnlyList<PackageVersion> localVersions,
        OrgSettings settings,
        IReadOnlyDictionary<string, VulnGateSignals> signals,
        DateTimeOffset now)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine($"<html><head><title>Links for {System.Web.HttpUtility.HtmlEncode(purlName)}</title></head><body>");
        sb.AppendLine($"<h1>Links for {System.Web.HttpUtility.HtmlEncode(purlName)}</h1>");

        var seenFilenames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

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

        foreach (var v in localVersions)
        {
            // Omit versions the download path will hard-block so they are never advertised.
            // The shared predicate mirrors BlockGateService.EvaluateAsync exactly so this
            // filter and the download gate can never diverge.
            if (BlockGateService.IsHardBlockedByStoredState(v, settings, signals.GetValueOrDefault(v.Id), now))
            {
                continue;
            }

            string filename = string.IsNullOrEmpty(v.Filename) ? v.BlobKey.Split('/').Last() : v.Filename;
            if (!seenFilenames.Add(filename))
            {
                continue; // already listed from the upstream entries
            }

            string href = OrgPath($"packages/{filename}");
            if (v.ChecksumSha256 is not null)
            {
                href += $"#sha256={v.ChecksumSha256}";
            }

            string yankAttr = v.Yanked
                ? $" data-yanked=\"{System.Web.HttpUtility.HtmlAttributeEncode(v.YankReason ?? "")}\""
                : "";
            sb.AppendLine($"<a href=\"{System.Web.HttpUtility.HtmlAttributeEncode(href)}\"{yankAttr}>{System.Web.HttpUtility.HtmlEncode(filename)}</a><br/>");
        }

        sb.AppendLine("</body></html>");
        return sb.ToString();
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
