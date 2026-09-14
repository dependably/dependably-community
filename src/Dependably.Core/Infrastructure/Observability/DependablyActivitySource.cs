using System.Diagnostics;

namespace Dependably.Infrastructure.Observability;

/// <summary>
/// Single <see cref="ActivitySource"/> for every custom dependably span. The
/// OpenTelemetry SDK subscribes to this source by name in
/// <see cref="Program.ConfigureOpenTelemetry"/> via
/// <c>.WithTracing(t =&gt; t.AddSource(DependablyActivitySource.SourceName))</c>.
///
/// Span name and attribute conventions live in
/// <c>dependably-community.spec/specs/design/DESIGN-observability-taxonomy.md#span-attributes</c>.
/// </summary>
public static class DependablyActivitySource
{
    public const string SourceName = "dependably";

    public static readonly ActivitySource Source = new(SourceName);
}
