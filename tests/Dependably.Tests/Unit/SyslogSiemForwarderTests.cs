using Dependably.Infrastructure.Siem;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class SyslogSiemForwarderTests
{
    private static SiemEvent Sample(string action = "login.success", string? detail = null) => new(
        Id: "e1", Action: action, Scope: "tenant", OrgId: "org-acme",
        ActorId: "u-1", Ecosystem: "npm", Purl: "pkg:npm/lodash@1.0.0",
        Detail: detail,
        CreatedAt: new DateTimeOffset(2026, 5, 9, 12, 30, 45, 123, TimeSpan.Zero));

    private static IConfiguration Cfg(IDictionary<string, string?> overrides) =>
        new ConfigurationBuilder().AddInMemoryCollection(overrides).Build();

    [Fact]
    public void Constructor_RequiresHost()
    {
        var cfg = Cfg(new Dictionary<string, string?>());
        Assert.Throws<InvalidOperationException>(() => new SyslogSiemForwarder(cfg));
    }

    [Fact]
    public void Constructor_RejectsUnknownProto()
    {
        var cfg = Cfg(new Dictionary<string, string?>
        {
            ["SIEM_SYSLOG_HOST"] = "siem.example.com",
            ["SIEM_SYSLOG_PROTO"] = "websocket"
        });
        Assert.Throws<InvalidOperationException>(() => new SyslogSiemForwarder(cfg));
    }

    [Fact]
    public void Constructor_RejectsUnknownFormat()
    {
        var cfg = Cfg(new Dictionary<string, string?>
        {
            ["SIEM_SYSLOG_HOST"] = "siem.example.com",
            ["SIEM_SYSLOG_FORMAT"] = "yaml"
        });
        Assert.Throws<InvalidOperationException>(() => new SyslogSiemForwarder(cfg));
    }

    [Fact]
    public void FormatCef_StructureMatchesSiemController()
    {
        var line = SyslogSiemForwarder.FormatCef(Sample());
        // Header: CEF:0|Dependably|dependably|1.0|<sig>|<name>|<sev>|<ext>
        Assert.StartsWith("CEF:0|Dependably|dependably|1.0|", line);
        Assert.Contains("|login.success|Login Success|3|", line);
        Assert.Contains("rt=20260509123045.123Z", line);
        Assert.Contains("suid=u-1", line);
        Assert.Contains("cs1=org-acme", line);
        Assert.Contains("cs2=npm", line);
        Assert.Contains("cs3=pkg:npm/lodash@1.0.0", line);
    }

    [Fact]
    public void FormatCef_EscapesPipesEqualsAndNewlines()
    {
        var ev = Sample(detail: "msg with | pipe and = equals\nand newline");
        var line = SyslogSiemForwarder.FormatCef(ev);
        Assert.Contains("\\|", line);
        Assert.Contains("\\=", line);
        Assert.Contains("\\n", line);
        Assert.DoesNotContain("\n", line.Replace("\\n", ""));  // raw newline only at end
    }

    [Fact]
    public void FormatCef_LockoutMapsToSeverity7()
    {
        var line = SyslogSiemForwarder.FormatCef(Sample(action: "lockout.triggered"));
        Assert.Contains("|Account Lockout|7|", line);
    }

    [Fact]
    public void FormatRfc5424_ContainsPriorityTimestampAndStructuredData()
    {
        var line = SyslogSiemForwarder.FormatRfc5424(Sample());
        Assert.StartsWith("<134>1 ", line);                       // local0(16)*8 + info(6) = 134
        Assert.Contains("2026-05-09T12:30:45.123+00:00", line);
        Assert.Contains("[dependably@0", line);
        Assert.Contains("org=\"org-acme\"", line);
        Assert.Contains("ecosystem=\"npm\"", line);
        Assert.Contains("purl=\"pkg:npm/lodash@1.0.0\"", line);
    }

    [Fact]
    public void FormatRfc5424_EscapesQuotesAndBackslashesInSd()
    {
        var ev = Sample() with { OrgId = "org\"with]quotes\\" };
        var line = SyslogSiemForwarder.FormatRfc5424(ev);
        Assert.Contains("org=\"org\\\"with\\]quotes\\\\\"", line);
    }
}
