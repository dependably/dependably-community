using System.Text.Json;
using Dependably.Tests.Infrastructure;
using Elastic.CommonSchema.Serilog;
using Serilog.Events;
using Serilog.Parsing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Verifies the ECS (Elastic Common Schema) formatter used by AddDependablyLogging.
/// Core guarantee: log.level is always present in the output, at every Serilog level —
/// unlike the built-in compact formatter which omits it for Information events.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EcsLogFormatterTests
{
    private static LogEvent BuildEvent(LogEventLevel level, string messageTemplate = "Test message")
    {
        var parser = new MessageTemplateParser();
        var template = parser.Parse(messageTemplate);
        return new LogEvent(TestTime.KnownNow, level, null, template, []);
    }

    private static string Format(LogEvent logEvent)
    {
        var formatter = new EcsTextFormatter();
        using var sw = new StringWriter();
        formatter.Format(logEvent, sw);
        return sw.ToString();
    }

    [Fact]
    public void InformationEvent_OutputParsesAsJsonObject()
    {
        string output = Format(BuildEvent(LogEventLevel.Information));

        using var doc = JsonDocument.Parse(output);
        Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
    }

    [Fact]
    public void InformationEvent_LogLevelIsAlwaysPresent()
    {
        string output = Format(BuildEvent(LogEventLevel.Information));

        using var doc = JsonDocument.Parse(output);
        Assert.Equal("Information", doc.RootElement.GetProperty("log.level").GetString());
    }

    [Fact]
    public void WarningEvent_LogLevelIsWarning()
    {
        string output = Format(BuildEvent(LogEventLevel.Warning));

        using var doc = JsonDocument.Parse(output);
        Assert.Equal("Warning", doc.RootElement.GetProperty("log.level").GetString());
    }
}
