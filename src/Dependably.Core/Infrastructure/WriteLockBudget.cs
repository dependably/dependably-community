namespace Dependably.Infrastructure;

/// <summary>
/// Sizes a repeated bulk-write batch by how long the previous one held the database write lock,
/// rather than by a fixed row count. A fixed count that holds the lock for tens of milliseconds on
/// an idle host holds it for seconds on a CPU-starved one, and every other writer's
/// retry loop is held up behind it for seconds, and fails once it reaches the command timeout. The batch shrinks as fast as it must when a commit runs
/// long and grows back gradually when commits are quick, always inside
/// [<see cref="MinRows"/>, <see cref="MaxRows"/>].
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S3604:Member initializer values should not be redundant",
    Justification = "The members are initialized from primary-constructor parameters; the rule misreads that as a "
                    + "redundant initializer.")]
internal sealed class WriteLockBudget(int initialRows, int minRows, int maxRows)
{
    /// <summary>The lock-held time a batch is sized to, a hold other writers wait out in well under a second.</summary>
    public static readonly TimeSpan Target = TimeSpan.FromMilliseconds(250);

    private const double MaxGrowth = 1.5;
    private const double MaxShrink = 0.1;

    public int MinRows { get; } = minRows;

    public int MaxRows { get; } = maxRows;

    /// <summary>Rows the next batch may write.</summary>
    public int Rows { get; private set; } = Math.Clamp(initialRows, minRows, maxRows);

    /// <summary>
    /// Records how long the batch just committed held the write lock (first write to commit) and
    /// resizes the next one so it lands near <see cref="Target"/>.
    /// </summary>
    public void Record(TimeSpan held)
    {
        double ratio = held <= TimeSpan.Zero ? MaxGrowth : Target / held;
        double scale = Math.Clamp(ratio, MaxShrink, MaxGrowth);
        Rows = Math.Clamp((int)(Rows * scale), MinRows, MaxRows);
    }
}
