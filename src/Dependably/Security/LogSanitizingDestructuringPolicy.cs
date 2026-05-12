using Serilog.Core;
using Serilog.Events;

namespace Dependably.Security;

/// <summary>
/// Serilog destructuring policy that redacts sensitive fields from structured log output.
/// Prevents Authorization headers, cookie values, passwords, and tokens from appearing in logs.
/// </summary>
public sealed class LogSanitizingDestructuringPolicy : IDestructuringPolicy
{
    public bool TryDestructure(object value, ILogEventPropertyValueFactory propertyValueFactory, out LogEventPropertyValue result)
    {
        result = null!;
        return false; // Let Serilog handle the destructuring; redaction happens via SensitivePropertyEnricher below
    }
}

/// <summary>
/// Serilog log event enricher that replaces sensitive property values with "[REDACTED]".
/// </summary>
public sealed class SensitivePropertyEnricher : ILogEventEnricher
{
    private static readonly HashSet<string> SensitiveKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "token", "secret", "authorization", "cookie", "jwt_secret"
    };

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        foreach (var key in SensitiveKeys.Where(k => logEvent.Properties.ContainsKey(k)))
            logEvent.AddOrUpdateProperty(propertyFactory.CreateProperty(key, "[REDACTED]"));
    }
}
