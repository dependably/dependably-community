using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// <see cref="ILogger{T}"/> that keeps every entry for assertion: the level, the rendered message,
/// and each structured property value rendered as a string, so a test can check both what the line
/// says and that no property carries a value it must not.
/// </summary>
public sealed class RecordingLogger<T> : ILogger<T>
{
    private readonly ConcurrentQueue<Entry> _entries = new();

    /// <summary>One logged entry.</summary>
    public sealed record Entry(LogLevel Level, string Message, IReadOnlyList<string> PropertyValues)
    {
        /// <summary>The message and every property value, for "never contains" checks.</summary>
        public string AllText => Message + "\n" + string.Join("\n", PropertyValues);
    }

    /// <summary>Every entry logged so far, in order.</summary>
    public IReadOnlyList<Entry> Entries => _entries.ToArray();

    /// <summary>Entries at <see cref="LogLevel.Warning"/> or above.</summary>
    public IReadOnlyList<Entry> Warnings => Entries.Where(e => e.Level >= LogLevel.Warning).ToList();

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        var values = state is IEnumerable<KeyValuePair<string, object?>> pairs
            ? pairs.Select(p => p.Value?.ToString() ?? "").ToList()
            : [];
        _entries.Enqueue(new Entry(logLevel, formatter(state, exception), values));
    }
}
