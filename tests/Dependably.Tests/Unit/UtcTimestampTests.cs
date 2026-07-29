using Dependably.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// The canonical-format contract. Each case here is a shape that reached a timestamp column
/// before normalization was centralized: a non-UTC offset formatted against a pattern whose
/// trailing <c>Z</c> is a literal, and an offset-less instant read as server-local time.
/// </summary>
public class UtcTimestampTests
{
    [Fact]
    public void ConvertsNonUtcOffsetToUtcRatherThanRelabellingIt()
    {
        // 14:00+02:00 is 12:00Z. Formatting the pattern inline would emit "14:00:00Z".
        var plusTwo = new DateTimeOffset(2026, 7, 25, 14, 0, 0, TimeSpan.FromHours(2));

        Assert.Equal("2026-07-25T12:00:00Z", plusTwo.ToUtcIso());
    }

    [Fact]
    public void ConvertsNegativeOffsetToUtc()
    {
        var minusFour = new DateTimeOffset(2026, 7, 25, 8, 0, 0, TimeSpan.FromHours(-4));

        Assert.Equal("2026-07-25T12:00:00Z", minusFour.ToUtcIso());
    }

    [Fact]
    public void LeavesAlreadyUtcInstantsUnchanged()
    {
        var utc = new DateTimeOffset(2026, 7, 25, 12, 0, 0, TimeSpan.Zero);

        Assert.Equal("2026-07-25T12:00:00Z", utc.ToUtcIso());
    }

    [Fact]
    public void NullOptionalInstantStaysNull()
    {
        DateTimeOffset? absent = null;

        Assert.Null(absent.ToUtcIsoOrNull());
    }

    [Fact]
    public void NormalizesClientSuppliedOffsetToUtc()
    {
        Assert.True(UtcTimestamp.TryNormalize("2026-07-25T14:00:00+02:00", out string normalized));
        Assert.Equal("2026-07-25T12:00:00Z", normalized);
    }

    [Fact]
    public void ReadsAnOffsetLessClientValueAsUtcNotServerLocal()
    {
        // Without AssumeUniversal this parses as server-local time, so the stored instant
        // would depend on the host's timezone — the same request would store a different
        // instant on a UTC host and on a UTC+2 host.
        Assert.True(UtcTimestamp.TryNormalize("2026-07-25T12:00:00", out string normalized));
        Assert.Equal("2026-07-25T12:00:00Z", normalized);
    }

    [Fact]
    public void NormalizedValuesOrderLexicographicallyByInstant()
    {
        // The ordering the banner window comparison depends on: the later instant must sort
        // later as text, even though its wall-clock text ("09:00") reads earlier.
        Assert.True(UtcTimestamp.TryNormalize("2026-07-25T09:00:00-05:00", out string later));
        Assert.True(UtcTimestamp.TryNormalize("2026-07-25T12:00:00Z", out string earlier));

        Assert.Equal("2026-07-25T14:00:00Z", later);
        Assert.True(string.CompareOrdinal(later, earlier) > 0);
    }

    [Fact]
    public void RejectsUnparseableInput()
    {
        Assert.False(UtcTimestamp.TryNormalize("not-a-timestamp", out string normalized));
        Assert.Equal(string.Empty, normalized);

        Assert.False(UtcTimestamp.TryNormalize(null, out _));
    }
}
