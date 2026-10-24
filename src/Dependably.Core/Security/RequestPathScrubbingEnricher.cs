using System.Text.RegularExpressions;
using Serilog.Core;
using Serilog.Events;

namespace Dependably.Security;

/// <summary>
/// Masks the local-part of any email address embedded in a string, keeping the domain —
/// the same discipline the mail jobs apply via <c>ExtractDomain</c> so PII (the local part)
/// never reaches structured logs, trace spans, or the aggregators/tracing backends they feed.
/// <c>alice@customer.example</c> becomes <c>***@customer.example</c>. Both the literal <c>@</c>
/// and its percent-encoded form <c>%40</c> are recognised, so a URL-encoded path segment is
/// masked too.
///
/// The matcher runs under a wall-clock match timeout and fails closed: a value it cannot finish
/// scanning in time is replaced whole by <see cref="RedactedValue"/>. The deadline counts
/// elapsed time, not CPU time, so a thread descheduled mid-match (GC pause, CPU contention) can
/// hit it on an ordinary path; the result is over-redaction, never a leak. Production uses
/// <see cref="Default"/>; the constructor lets a caller choose another bound.
/// </summary>
public sealed class LogPathScrubber
{
    /// <summary>The match timeout <see cref="Default"/> runs under.</summary>
    public static readonly TimeSpan DefaultMatchTimeout = TimeSpan.FromMilliseconds(100);

    /// <summary>What a value becomes when the matcher cannot prove it email-free in time.</summary>
    public const string RedactedValue = "[REDACTED-PATH]";

    /// <summary>The scrubber the log enricher and span processor use unless given another.</summary>
    public static LogPathScrubber Default { get; } = new(DefaultMatchTimeout);

    // Local-part, then '@' or '%40', then a dotted domain. Anchored on neither end so it
    // matches an address wherever it sits inside a request path or URL.
    private const string EmailPattern =
        @"[A-Za-z0-9._%+\-]+(?:@|%40)(?<domain>[A-Za-z0-9.\-]+\.[A-Za-z]{2,})";

    private readonly Regex _emailPattern;

    /// <param name="matchTimeout">
    /// Wall-clock bound on one scrub. Must be positive: <see cref="Regex.InfiniteMatchTimeout"/>
    /// is negative and rejected here, because an unbounded matcher has no fail-closed path.
    /// </param>
    public LogPathScrubber(TimeSpan matchTimeout)
    {
        if (matchTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(matchTimeout), matchTimeout,
                "The email matcher needs a positive, finite match timeout.");
        }

        _emailPattern = new Regex(
            EmailPattern,
            RegexOptions.Compiled | RegexOptions.CultureInvariant,
            matchTimeout);
    }

    /// <summary>The wall-clock bound this scrubber's matcher runs under.</summary>
    public TimeSpan MatchTimeout => _emailPattern.MatchTimeout;

    /// <summary>Cheap gate: is there anything email-shaped worth scrubbing?</summary>
    public static bool ContainsEmail(string? value) =>
        !string.IsNullOrEmpty(value)
        && (value.Contains('@', StringComparison.Ordinal)
            || value.Contains("%40", StringComparison.OrdinalIgnoreCase));

    /// <summary>Returns <paramref name="value"/> with every email local-part masked to <c>***</c>.</summary>
    public string Scrub(string value)
    {
        if (!ContainsEmail(value))
        {
            return value;
        }

        try
        {
            return _emailPattern.Replace(value, "***@${domain}");
        }
        catch (RegexMatchTimeoutException)
        {
            // Defence-in-depth must never let a pathological input through unmasked. If the
            // matcher times out we cannot prove the value is email-free, so redact it whole.
            return RedactedValue;
        }
    }
}

/// <summary>
/// Serilog enricher that masks email addresses in the <c>RequestPath</c> property that
/// <c>UseSerilogRequestLogging</c> attaches to every request-completion event (and that the
/// request scope pushes onto ambient events). Rewriting the property fixes both the structured
/// field and the rendered message, because the sink renders <c>{RequestPath}</c> from the
/// property after enrichment.
///
/// This is defence-in-depth: routes deliberately keep identifiers out of the path, but a future
/// route that embeds one must not silently reopen the PII-in-logs leak.
/// </summary>
public sealed class RequestPathScrubbingEnricher : ILogEventEnricher
{
    private const string RequestPathProperty = "RequestPath";

    private readonly LogPathScrubber _scrubber;

    public RequestPathScrubbingEnricher()
        : this(LogPathScrubber.Default)
    {
    }

    public RequestPathScrubbingEnricher(LogPathScrubber scrubber)
    {
        _scrubber = scrubber;
    }

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        if (logEvent.Properties.TryGetValue(RequestPathProperty, out var value)
            && value is ScalarValue { Value: string path }
            && LogPathScrubber.ContainsEmail(path))
        {
            logEvent.AddOrUpdateProperty(
                propertyFactory.CreateProperty(RequestPathProperty, _scrubber.Scrub(path)));
        }
    }
}
