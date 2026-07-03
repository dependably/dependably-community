using System.Collections.Concurrent;
using Serilog.Core;
using Serilog.Events;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Serilog sink that records rendered log messages for assertion. Registered on a
/// <see cref="DependablyFactory"/> via <see cref="DependablyFactory.LogSink"/>; the production
/// pipeline's <c>ReadFrom.Services</c> wires it into the real logger.
/// </summary>
public sealed class CapturingLogSink : ILogEventSink
{
    private readonly ConcurrentQueue<(LogEventLevel Level, string Message)> _events = new();

    public void Emit(LogEvent logEvent) =>
        _events.Enqueue((logEvent.Level, logEvent.RenderMessage()));

    /// <summary>True when any captured event at or above <paramref name="minLevel"/> contains the substring.</summary>
    public bool Contains(string substring, LogEventLevel minLevel = LogEventLevel.Information) =>
        _events.Any(e => e.Level >= minLevel
                         && e.Message.Contains(substring, StringComparison.Ordinal));
}
