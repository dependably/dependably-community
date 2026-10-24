using Microsoft.Extensions.Logging;

namespace Dependably.Infrastructure;

public sealed partial class SchemaInitializer
{
    /// <summary>
    /// Wall-clock budget for the boot's convergence work inside the migration lock: the constraint
    /// retrofits (canonical-timestamp CHECKs and column CHECK / foreign-key constraints), then the
    /// alias-index reconcile and the alias-donor sweep, which receive whatever the retrofits left.
    /// The migration lock a peer replica polls gives up after <c>MigrationLockMaxWait</c>
    /// (10 minutes), and the numeric widening that runs earlier in the same boot can spend about
    /// 3 minutes of lock retries on a blocked table, so 3 minutes here plus 3 minutes there leaves
    /// roughly 4 minutes of margin for the rest of the boot. Once spent, every remaining retrofit
    /// step is deferred to the next boot and the alias sweeps to their next scheduled run.
    /// </summary>
    internal static readonly TimeSpan DefaultRetrofitPassBudget = TimeSpan.FromMinutes(3);

    /// <summary>
    /// Cap on one <c>VALIDATE CONSTRAINT</c> scan, enforced with the session <c>statement_timeout</c>
    /// and further limited by what remains of the pass budget. A scan that exceeds it is cancelled
    /// by the server and the constraint stays <c>NOT VALID</c> until the next boot.
    /// </summary>
    internal static readonly TimeSpan DefaultValidateStatementTimeout = TimeSpan.FromSeconds(60);

    // Test seams: production always runs the defaults.
    internal TimeSpan RetrofitPassBudget { get; init; } = DefaultRetrofitPassBudget;

    internal TimeSpan ValidateStatementTimeout { get; init; } = DefaultValidateStatementTimeout;

    /// <summary>
    /// State shared by both retrofits within one boot: a single deadline on the injected
    /// <see cref="TimeProvider"/>, the set of tables whose lock could not be taken (so a locked table
    /// costs one retry budget however many constraints it carries), and the count of steps deferred
    /// to the next boot, reported once.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Minor Code Smell", "S3604:Member initializer values should not be redundant",
        Justification = "The members are initialized from primary-constructor parameters; the rule misreads that as a "
                        + "redundant initializer.")]
    internal sealed class RetrofitPass(TimeProvider time, TimeSpan budget)
    {
        private readonly long _started = time.GetTimestamp();
        private readonly HashSet<string> _skippedTables = new(StringComparer.Ordinal);

        public int Deferred { get; private set; }

        public TimeSpan Remaining
        {
            get
            {
                var left = budget - time.GetElapsedTime(_started);
                return left > TimeSpan.Zero ? left : TimeSpan.Zero;
            }
        }

        public bool Expired => Remaining == TimeSpan.Zero;

        public bool ShouldDefer(IReadOnlyList<string> tables) =>
            Expired || tables.Any(_skippedTables.Contains);

        public void Defer(IReadOnlyList<string> tables, bool lockExhausted)
        {
            Deferred++;
            if (lockExhausted)
            {
                foreach (string table in tables)
                {
                    _skippedTables.Add(table);
                }
            }
        }

        public void LogSummary(ILogger logger)
        {
            if (Deferred > 0)
            {
                logger.LogWarning(
                    "{Deferred} constraint retrofit step(s) were deferred to the next boot because the {Budget} " +
                    "retrofit budget was spent or a table stayed locked. New writes are still checked by every " +
                    "constraint that was added; nothing here blocks startup.",
                    Deferred, budget);
            }
        }
    }

    internal enum LockRetryOutcome
    {
        Ran,
        LockExhausted,
        DeadlineReached,
    }
}
