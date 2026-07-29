using Dependably.Infrastructure.Siem;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Both SIEM sinks carry audit events off the instance — actor ids and the typed payload, i.e.
/// personal data, and for the webhook the bearer credential rides the same request. These pin the
/// transport posture: secure by default on both, with the insecure option reachable only by an
/// explicit operator choice that is either announced (syslog) or opted into (webhook).
///
/// The two differ deliberately. A syslog operator has already picked a transport by name, so a
/// plaintext one warns and proceeds. A URL's scheme is a character easy to get wrong with a
/// correct value right next to it, so that one refuses at construction — before any event flows.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SiemTransportSecurityTests
{
    private static IConfiguration Cfg(params (string Key, string? Value)[] pairs) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(pairs.ToDictionary(p => p.Key, p => p.Value))
            .Build();

    // ── Syslog ───────────────────────────────────────────────────────────────

    [Fact]
    public void Syslog_DefaultTransport_IsTls()
    {
        var sut = new SyslogSiemForwarder(Cfg(("SIEM_SYSLOG_HOST", "siem.example.com")));

        Assert.Equal("syslog/tls", sut.Name);
    }

    [Theory]
    [InlineData("udp")]
    [InlineData("tcp")]
    public void Syslog_AnExplicitPlaintextTransport_IsHonouredButWarned(string proto)
    {
        var logger = new CapturingLogger<SyslogSiemForwarder>();

        var sut = new SyslogSiemForwarder(
            Cfg(("SIEM_SYSLOG_HOST", "siem.example.com"), ("SIEM_SYSLOG_PROTO", proto)), logger);

        // Honoured: an operator who names a transport gets it.
        Assert.Equal($"syslog/{proto}", sut.Name);
        // ...and the exposure is named at startup rather than left to an audit.
        string warning = Assert.Single(logger.Warnings);
        Assert.Contains("cleartext", warning, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("siem.example.com", warning);
    }

    [Fact]
    public void Syslog_Tls_WarnsAboutNothing()
    {
        var logger = new CapturingLogger<SyslogSiemForwarder>();

        _ = new SyslogSiemForwarder(
            Cfg(("SIEM_SYSLOG_HOST", "siem.example.com"), ("SIEM_SYSLOG_PROTO", "tls")), logger);

        Assert.Empty(logger.Warnings);
    }

    // ── Webhook ──────────────────────────────────────────────────────────────

    [Fact]
    public void Webhook_HttpUrl_IsRefusedAtConstruction()
    {
        using var http = new HttpClient();

        var ex = Assert.Throws<InvalidOperationException>(() =>
            new WebhookSiemForwarder(http, Cfg(("SIEM_WEBHOOK_URL", "http://collector.example.com/in"))));

        // The message has to tell the operator both what is exposed and how to proceed anyway.
        Assert.Contains("https", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("SIEM_WEBHOOK_ALLOW_INSECURE", ex.Message);
    }

    [Fact]
    public void Webhook_HttpsUrl_IsAccepted()
    {
        using var http = new HttpClient();

        var sut = new WebhookSiemForwarder(http, Cfg(("SIEM_WEBHOOK_URL", "https://collector.example.com/in")));

        Assert.Equal("webhook", sut.Name);
    }

    [Theory]
    [InlineData("true")]
    [InlineData("TRUE")]
    [InlineData("1")]
    [InlineData("yes")]
    public void Webhook_HttpUrl_IsAllowedWhenExplicitlyOptedIn(string optIn)
    {
        using var http = new HttpClient();

        var sut = new WebhookSiemForwarder(http, Cfg(
            ("SIEM_WEBHOOK_URL", "http://127.0.0.1:9200/in"),
            ("SIEM_WEBHOOK_ALLOW_INSECURE", optIn)));

        Assert.Equal("webhook", sut.Name);
    }

    /// <summary>
    /// The opt-out must be an opt-out, not "any value present". A stray
    /// <c>SIEM_WEBHOOK_ALLOW_INSECURE=false</c> — the spelling an operator uses to say NO — must
    /// not read as consent.
    /// </summary>
    [Theory]
    [InlineData("false")]
    [InlineData("0")]
    [InlineData("")]
    public void Webhook_HttpUrl_StaysRefusedForANonAffirmativeOptOut(string value)
    {
        using var http = new HttpClient();

        Assert.Throws<InvalidOperationException>(() =>
            new WebhookSiemForwarder(http, Cfg(
                ("SIEM_WEBHOOK_URL", "http://collector.example.com/in"),
                ("SIEM_WEBHOOK_ALLOW_INSECURE", value))));
    }

    // ── Harness ──────────────────────────────────────────────────────────────

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<string> Warnings { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning)
            {
                Warnings.Add(formatter(state, exception));
            }
        }
    }
}
