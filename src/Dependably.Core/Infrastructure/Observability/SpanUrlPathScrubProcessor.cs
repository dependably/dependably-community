using System.Diagnostics;
using Dependably.Security;
using OpenTelemetry;

namespace Dependably.Infrastructure.Observability;

/// <summary>
/// OpenTelemetry processor that masks email local-parts in the URL-bearing tags the ASP.NET
/// Core and HttpClient instrumentations stamp on a span (<c>url.path</c>, <c>url.full</c>,
/// <c>http.target</c>, <c>http.url</c>). Runs at <see cref="OnEnd"/> — after the framework has
/// set the tags — and only rewrites when an email is actually present, so non-PII paths are
/// untouched.
///
/// Defence-in-depth alongside <see cref="RequestPathScrubbingEnricher"/>: routes keep
/// identifiers out of the path, but the span estate exports off-box (OTLP) and must not carry
/// a raw address if a future route ever embeds one.
/// </summary>
public sealed class SpanUrlPathScrubProcessor : BaseProcessor<Activity>
{
    private static readonly string[] PathTags =
        ["url.path", "url.full", "http.target", "http.url"];

    public override void OnEnd(Activity activity)
    {
        foreach (string tag in PathTags)
        {
            if (activity.GetTagItem(tag) is string value && LogPathScrubber.ContainsEmail(value))
            {
                activity.SetTag(tag, LogPathScrubber.Scrub(value));
            }
        }
    }
}
