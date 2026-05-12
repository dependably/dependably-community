using Dependably.Security;
using Serilog.Core;
using Serilog.Events;
using Serilog.Parsing;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// The enricher is the load-bearing piece of the structured-logging redaction policy: it
/// rewrites Authorization, Cookie, password, token, secret, and jwt_secret property values
/// to "[REDACTED]" before Serilog renders them.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SensitivePropertyEnricherTests
{
    private static LogEvent BuildEvent(IReadOnlyDictionary<string, object?> properties)
    {
        var template = new MessageTemplateParser().Parse("test");
        var props = properties.Select(kv =>
            new LogEventProperty(kv.Key, new ScalarValue(kv.Value))).ToArray();
        return new LogEvent(DateTimeOffset.UtcNow, LogEventLevel.Information, exception: null,
            template, props);
    }

    private sealed class CapturingFactory : ILogEventPropertyFactory
    {
        public LogEventProperty CreateProperty(string name, object? value, bool destructureObjects = false)
            => new(name, new ScalarValue(value));
    }

    [Theory]
    [InlineData("password")]
    [InlineData("token")]
    [InlineData("secret")]
    [InlineData("authorization")]
    [InlineData("cookie")]
    [InlineData("jwt_secret")]
    public void Enrich_ReplacesSensitiveValueWithRedacted(string key)
    {
        var evt = BuildEvent(new Dictionary<string, object?> { [key] = "the-real-thing" });
        new SensitivePropertyEnricher().Enrich(evt, new CapturingFactory());

        var actual = evt.Properties[key];
        Assert.Equal("\"[REDACTED]\"", actual.ToString());
    }

    [Fact]
    public void Enrich_LeavesNonSensitivePropertiesUntouched()
    {
        var evt = BuildEvent(new Dictionary<string, object?>
        {
            ["org"] = "acme",
            ["user_id"] = "u-1",
            ["password"] = "secret-value",
        });
        new SensitivePropertyEnricher().Enrich(evt, new CapturingFactory());

        Assert.Equal("\"acme\"", evt.Properties["org"].ToString());
        Assert.Equal("\"u-1\"", evt.Properties["user_id"].ToString());
        Assert.Equal("\"[REDACTED]\"", evt.Properties["password"].ToString());
    }

    [Fact]
    public void Enrich_NoSensitiveKeysPresent_NoOp()
    {
        var evt = BuildEvent(new Dictionary<string, object?> { ["foo"] = "bar" });
        new SensitivePropertyEnricher().Enrich(evt, new CapturingFactory());
        Assert.Equal("\"bar\"", evt.Properties["foo"].ToString());
    }

    [Fact]
    public void TryDestructure_DefersToSerilog_ReturnsFalse()
    {
        // The destructuring policy is intentionally a no-op — redaction happens in the
        // enricher. This pins the behaviour so a future "let's destructure here" change
        // is flagged.
        var policy = new LogSanitizingDestructuringPolicy();
        var handled = policy.TryDestructure("anything", new ValueFactory(), out var result);
        Assert.False(handled);
        Assert.Null(result);
    }

    private sealed class ValueFactory : ILogEventPropertyValueFactory
    {
        public LogEventPropertyValue CreatePropertyValue(object? value, bool destructureObjects = false)
            => new ScalarValue(value);
    }
}
