using System.Reflection;
using Serilog.Core;
using Serilog.Events;

namespace Dependably.Security;

/// <summary>
/// Single classifier for sensitive log property names, shared by the top-level
/// <see cref="SensitivePropertyEnricher"/> and the nested-object
/// <see cref="LogSanitizingDestructuringPolicy"/>. A name is sensitive when it contains
/// any credential-bearing keyword (case-insensitive substring match) and is not on the
/// allowlist of known-safe operational identifiers. Matching is substring-based so
/// variants like <c>InviteLink</c>, <c>RawToken</c>, <c>ApiKey</c>, or
/// <c>ConnectionString</c> are caught without enumerating every spelling; the allowlist
/// keeps the substring net from swallowing operational fields (blob/storage keys are
/// SHA-derived storage paths, token ids are DB surrogate identifiers — redacting them
/// would blind cache-eviction, retention, and orphan-reconciliation logs).
/// </summary>
public static class SensitiveLogKeys
{
    private static readonly string[] Keywords =
    [
        "password", "token", "secret", "authorization", "cookie", "bearer",
        "apikey", "api_key", "api-key", "key", "link",
        "connection_string", "connectionstring", "credential",
    ];

    private static readonly HashSet<string> SafeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "key", "keys", "blobkey", "versionkey", "keyprefix", "tieredkey",
        "cachekey", "partitionkey", "rowkey", "idempotencykey",
        "tokenid", "tokencount",
    };

    public static bool IsSensitive(string name) =>
        !string.IsNullOrEmpty(name)
        && !SafeNames.Contains(name)
        && Keywords.Any(k => name.Contains(k, StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// Serilog destructuring policy that redacts sensitive members of destructured
/// (<c>{@Object}</c>) values. The enricher only sees top-level property names; without
/// this policy a destructured object carrying a <c>Password</c> or <c>Token</c> member
/// would render its value verbatim inside the structure.
/// </summary>
public sealed class LogSanitizingDestructuringPolicy : IDestructuringPolicy
{
    public bool TryDestructure(object value, ILogEventPropertyValueFactory propertyValueFactory, out LogEventPropertyValue result)
    {
        result = null!;
        var type = value.GetType();

        if (ShouldSkipType(value, type))
        {
            return false;
        }

        var props = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);
        if (props.Length == 0)
        {
            return false;
        }

        result = new StructureValue(
            BuildPropertyList(value, props, propertyValueFactory),
            IsAnonymousType(type) ? null : type.Name);
        return true;
    }

    // Returns true for types whose properties need no redaction: scalars, collections,
    // and framework/platform types. Anonymous types (null namespace, CompilerGenerated) are
    // NOT skipped — they are a common path by which sensitive values reach the logger.
    private static bool ShouldSkipType(object value, Type type)
    {
        if (value is string || type.IsPrimitive || type.IsEnum || value is System.Collections.IEnumerable)
        {
            return true;
        }

        string? ns = type.Namespace;
        return (ns is null || ns.StartsWith("System", StringComparison.Ordinal) || ns.StartsWith("Microsoft", StringComparison.Ordinal))
            && !IsAnonymousType(type);
    }

    // Builds the redacted property list: sensitive properties become the "[REDACTED]"
    // placeholder, and non-sensitive properties are recursively destructured by Serilog.
    private static List<LogEventProperty> BuildPropertyList(
        object value, PropertyInfo[] props, ILogEventPropertyValueFactory propertyValueFactory)
    {
        var members = new List<LogEventProperty>(props.Length);
        foreach (var prop in props)
        {
            if (!prop.CanRead || prop.GetIndexParameters().Length > 0)
            {
                continue;
            }

            if (SensitiveLogKeys.IsSensitive(prop.Name))
            {
                members.Add(new LogEventProperty(prop.Name, new ScalarValue("[REDACTED]")));
                continue;
            }

            object? memberValue;
            try
            {
                memberValue = prop.GetValue(value);
            }
            catch (TargetInvocationException)
            {
                memberValue = null;
            }

            members.Add(new LogEventProperty(prop.Name, propertyValueFactory.CreatePropertyValue(memberValue, destructureObjects: true)));
        }

        return members;
    }

    private static bool IsAnonymousType(Type type) =>
        type.IsDefined(typeof(System.Runtime.CompilerServices.CompilerGeneratedAttribute), inherit: false)
        && type.Name.Contains("AnonymousType", StringComparison.Ordinal);
}

/// <summary>
/// Serilog log event enricher that replaces sensitive top-level property values with
/// "[REDACTED]". Name matching is delegated to <see cref="SensitiveLogKeys"/>.
/// </summary>
public sealed class SensitivePropertyEnricher : ILogEventEnricher
{
    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        foreach (string key in logEvent.Properties.Keys.Where(SensitiveLogKeys.IsSensitive).ToList())
        {
            logEvent.AddOrUpdateProperty(propertyFactory.CreateProperty(key, "[REDACTED]"));
        }
    }
}
