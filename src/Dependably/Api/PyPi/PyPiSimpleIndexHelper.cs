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
    /// Rewrites an upstream PEP 503 simple-index page so every anchor points at the local
    /// <c>/packages/{file}</c> proxy route, stripping the metadata-sidecar attributes pip
    /// would otherwise chase upstream. The anchor's attribute run is matched inside an
    /// atomic group (<c>(?&gt;…)</c>) whose alternatives are disjoint on their first
    /// character (unquoted run vs. quoted string), so matching is linear over
    /// attacker-controlled upstream HTML — the engine can neither backtrack into an
    /// alternative nor give back iterations. The 2-second RegexTimeout stays as
    /// defence-in-depth.
    /// </summary>
    public static string RewriteUpstreamSimpleIndexHtml(string html)
    {
        html = Regex.Replace(html, @"\s*data-(?:dist-info-metadata|core-metadata)=""[^""]*""", "", RegexOptions.None, PyPiConstants.RegexTimeout);
        return Regex.Replace(
            html,
            @"<a\b((?>(?:[^>""']+|""[^""]*""|'[^']*')*))>([^<]+)</a>",
            m =>
            {
                string attrs = m.Groups[1].Value;
                string filename = m.Groups[2].Value.Trim();
                var hrefMatch = Regex.Match(attrs, @"href=""(https?://[^""#]+)(#[^""]*)?""", RegexOptions.None, PyPiConstants.RegexTimeout);
                if (!hrefMatch.Success)
                {
                    return m.Value;
                }

                string fragment = hrefMatch.Groups[2].Value;
                // filename/fragment come from upstream HTML — encode before re-emitting.
                return $"<a href=\"{System.Web.HttpUtility.HtmlAttributeEncode(OrgPath($"packages/{filename}{fragment}"))}\">{System.Web.HttpUtility.HtmlEncode(filename)}</a>";
            },
            RegexOptions.None,
            PyPiConstants.RegexTimeout);
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

            string filename = v.BlobKey.Split('/').Last();
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
    /// Splices local-only filenames into the upstream index so mixed-origin namespaces
    /// expose private versions alongside upstream. Filenames already present in the
    /// upstream HTML are skipped to avoid duplicates. Upstream-only (not-yet-cached) versions
    /// cannot be filtered here because stored state does not exist for them.
    /// </summary>
    public static string MergeLocalVersionsIntoUpstreamIndex(
        string upstreamHtml, IReadOnlyList<PackageVersion> localVersions,
        OrgSettings settings, IReadOnlyDictionary<string, VulnGateSignals> signals,
        DateTimeOffset now)
    {
        if (localVersions.Count == 0)
        {
            return upstreamHtml;
        }

        var sb = new StringBuilder();
        foreach (var v in localVersions)
        {
            // Omit versions the download path will hard-block so they are never advertised.
            // The shared predicate mirrors BlockGateService.EvaluateAsync exactly so this
            // filter and the download gate can never diverge.
            if (BlockGateService.IsHardBlockedByStoredState(v, settings, signals.GetValueOrDefault(v.Id), now))
            {
                continue;
            }

            string filename = v.BlobKey.Split('/').Last();
            if (upstreamHtml.Contains($">{filename}<", StringComparison.Ordinal))
            {
                continue;
            }

            string href = OrgPath($"packages/{filename}");
            if (v.ChecksumSha256 is not null)
            {
                href += $"#sha256={v.ChecksumSha256}";
            }

            string yankAttr = v.Yanked
                ? $" data-yanked=\"{System.Web.HttpUtility.HtmlAttributeEncode(v.YankReason ?? "")}\""
                : "";
            sb.Append($"<a href=\"{System.Web.HttpUtility.HtmlAttributeEncode(href)}\"{yankAttr}>{System.Web.HttpUtility.HtmlEncode(filename)}</a><br/>");
        }
        if (sb.Length == 0)
        {
            return upstreamHtml;
        }

        int bodyClose = upstreamHtml.LastIndexOf("</body>", StringComparison.OrdinalIgnoreCase);
        return bodyClose < 0
            ? upstreamHtml + sb
            : upstreamHtml[..bodyClose] + sb + upstreamHtml[bodyClose..];
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
