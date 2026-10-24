using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Serilog.Events;
using Serilog.Parsing;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// Guards the PII-in-logs leak: an email carried in the request path (or any string) must be
/// masked to <c>***@domain</c> before Serilog renders the request-completion event, so the
/// address never reaches the console/OTLP log estate outside the DB's retention controls.
///
/// The enricher rewrites the <c>RequestPath</c> property, which fixes both the structured field
/// and the rendered <c>{RequestPath}</c> message. Non-PII paths are left untouched so the
/// request log stays useful (no over-redaction). Masked-form assertions run with a generous
/// match timeout (see <see cref="TestScrubbers"/>); the fail-closed timeout path is pinned on its own.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RequestPathScrubbingEnricherTests
{
    private sealed class CapturingFactory : Serilog.Core.ILogEventPropertyFactory
    {
        public LogEventProperty CreateProperty(string name, object? value, bool destructureObjects = false)
            => new(name, new ScalarValue(value));
    }

    private static LogEvent BuildRequestEvent(string requestPath)
    {
        var template = new MessageTemplateParser().Parse(
            "HTTP {RequestMethod} {RequestPath} responded {StatusCode}");
        var props = new[]
        {
            new LogEventProperty("RequestMethod", new ScalarValue("PATCH")),
            new LogEventProperty("RequestPath", new ScalarValue(requestPath)),
            new LogEventProperty("StatusCode", new ScalarValue(204)),
        };
        return new LogEvent(TestTime.KnownNow, LogEventLevel.Information, exception: null, template, props);
    }

    private static string RequestPathValue(LogEvent evt) =>
        ((ScalarValue)evt.Properties["RequestPath"]).Value as string ?? "";

    [Theory]
    [InlineData("/api/v1/system/users/alice@customer.example/account-status",
                "/api/v1/system/users/***@customer.example/account-status")]
    // URL-encoded '@' (as the SPA would encode it) is masked too.
    [InlineData("/api/v1/system/users/alice%40customer.example/password-reset",
                "/api/v1/system/users/***@customer.example/password-reset")]
    // Email anywhere in the path, mixed-case local part.
    [InlineData("/foo/Bob.Smith+tag@Example.CO.UK/bar",
                "/foo/***@Example.CO.UK/bar")]
    public void Enrich_MasksEmailLocalPartInRequestPath(string rawPath, string expected)
    {
        var evt = BuildRequestEvent(rawPath);

        new RequestPathScrubbingEnricher(TestScrubbers.Generous).Enrich(evt, new CapturingFactory());

        string scrubbed = RequestPathValue(evt);
        Assert.Equal(expected, scrubbed);
        // The whole point: no @-bearing local-part survives, in the property or the message.
        Assert.DoesNotContain("alice@", scrubbed);
        Assert.DoesNotContain("alice%40", scrubbed);
        Assert.DoesNotContain("Bob.Smith", scrubbed);
        Assert.DoesNotContain("alice", evt.RenderMessage());
    }

    [Theory]
    // Adversarial twin: ordinary operational paths must render verbatim — no over-redaction.
    [InlineData("/api/v1/system/users/account-status")]
    [InlineData("/api/v1/system/tenants")]
    [InlineData("/npm/@scope/pkg/-/pkg-1.0.0.tgz")]
    [InlineData("/simple/requests/")]
    [InlineData("/v2/library/nginx/manifests/latest")]
    public void Enrich_LeavesNonEmailPathsUntouched(string path)
    {
        var evt = BuildRequestEvent(path);

        new RequestPathScrubbingEnricher(TestScrubbers.Generous).Enrich(evt, new CapturingFactory());

        Assert.Equal(path, RequestPathValue(evt));
    }

    [Fact]
    public void Enrich_NoRequestPathProperty_NoOp()
    {
        var template = new MessageTemplateParser().Parse("something happened");
        var evt = new LogEvent(TestTime.KnownNow, LogEventLevel.Information, exception: null,
            template, [new LogEventProperty("Other", new ScalarValue("value"))]);

        new RequestPathScrubbingEnricher(TestScrubbers.Generous).Enrich(evt, new CapturingFactory());

        Assert.False(evt.Properties.ContainsKey("RequestPath"));
        Assert.Equal("value", ((ScalarValue)evt.Properties["Other"]).Value);
    }

    [Theory]
    [InlineData("/users/a@b.co", true)]
    [InlineData("/users/a%40b.co", true)]
    [InlineData("/users/plain", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void ContainsEmail_Detects(string? value, bool expected)
        => Assert.Equal(expected, LogPathScrubber.ContainsEmail(value));

    [Fact]
    public void Scrub_KeepsDomain_MasksLocalPartOnly()
    {
        Assert.Equal("***@customer.example",
            TestScrubbers.Generous.Scrub("alice@customer.example"));
    }

    [Fact]
    public void Enrich_MatcherTimesOut_RedactsRequestPathWhole()
    {
        var evt = BuildRequestEvent(TestScrubbers.SlowToScan);

        new RequestPathScrubbingEnricher(TestScrubbers.Instant).Enrich(evt, new CapturingFactory());

        Assert.Equal(LogPathScrubber.RedactedValue, RequestPathValue(evt));
        Assert.DoesNotContain("alice", evt.RenderMessage());
    }

    [Fact]
    public void Scrub_MatcherTimesOut_RedactsWhole()
    {
        string scrubbed = TestScrubbers.Instant.Scrub(TestScrubbers.SlowToScan);

        Assert.Equal(LogPathScrubber.RedactedValue, scrubbed);
    }

    [Fact]
    public void Enrich_ProductionScrubber_NeverEmitsTheEmail()
    {
        // The parameterless constructor is the wiring Serilog uses. Whether its matcher finishes
        // inside the default deadline depends on scheduling, so this asserts the property that
        // holds either way: the path is masked or redacted whole, and the local part never survives.
        var evt = BuildRequestEvent("/api/v1/system/users/alice@customer.example/account-status");

        new RequestPathScrubbingEnricher().Enrich(evt, new CapturingFactory());

        Assert.Contains(RequestPathValue(evt), new[]
        {
            "/api/v1/system/users/***@customer.example/account-status",
            LogPathScrubber.RedactedValue,
        });
        Assert.DoesNotContain("alice", evt.RenderMessage());
    }

    [Fact]
    public void Default_RunsUnderTheProductionMatchTimeout()
    {
        Assert.Equal(TimeSpan.FromMilliseconds(100), LogPathScrubber.DefaultMatchTimeout);
        Assert.Equal(LogPathScrubber.DefaultMatchTimeout, LogPathScrubber.Default.MatchTimeout);
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(-1L)]
    public void Constructor_RejectsNonPositiveTimeout(long ticks)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new LogPathScrubber(TimeSpan.FromTicks(ticks)));
    }

    [Fact]
    public void Constructor_RejectsInfiniteTimeout()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new LogPathScrubber(System.Text.RegularExpressions.Regex.InfiniteMatchTimeout));
    }
}
