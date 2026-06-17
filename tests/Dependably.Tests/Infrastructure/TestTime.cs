using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Canonical frozen clock for tests. <see cref="KnownNow"/> is a whole-second UTC instant —
/// repositories persist second-granularity <c>yyyy-MM-ddTHH:mm:ssZ</c> strings, so a
/// sub-second component would make exact round-trip asserts fail. Tests that advance time
/// create their own <see cref="FakeTimeProvider"/> via <see cref="Frozen"/> and call
/// <c>Advance</c>/<c>SetUtcNow</c> on it.
/// </summary>
public static class TestTime
{
    public static readonly DateTimeOffset KnownNow = new(2026, 6, 15, 12, 0, 0, TimeSpan.Zero);

    public static FakeTimeProvider Frozen() => new(KnownNow);

    public static FakeTimeProvider Frozen(DateTimeOffset instant) => new(instant);
}
