using System.Collections.Concurrent;
using Dependably.Infrastructure;
using Microsoft.Extensions.Logging;

namespace Dependably.Tests.Integration;

/// <summary>
/// Drives the deployment shape that races schema application: several replicas calling
/// <see cref="SchemaInitializer.InitializeAsync"/> at the same moment against ONE live Postgres,
/// as a green task set launching or an autoscaling scale-out does.
///
/// Every step of the apply is check-then-act — <c>CREATE TABLE IF NOT EXISTS</c>, the additive
/// column probes, and <c>RunOnceAsync</c>'s read of the <c>_applied_migrations</c> ledger before it
/// runs the migration body. Unserialized, every replica reads the pre-migration state, every
/// replica runs the body, and the losers' ledger <c>INSERT</c> violates the <c>name</c> primary key.
/// That exception leaves <c>CoreStartupService.StartAsync</c>, so it is a failed host start.
///
/// The assertions are the two properties the advisory lock buys: every one-time migration body runs
/// exactly once across all replicas (counted from the initializer's own "applying" log, shared by
/// every replica), and no replica's startup throws.
///
/// Tagged <c>Category=SchemaPostgres</c> like the rest of the live-Postgres suite: it runs in the
/// dedicated <c>schema-integrity</c> CI job, which attaches a postgres service and sets
/// <c>TEST_POSTGRES_CONNECTION</c>. SQLite cannot stand in — it is single-writer and guarded by
/// <c>InstanceLock</c> instead, which is why the lock under test is Postgres-only.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class PostgresConcurrentSchemaInitTests
{
    // Enough concurrency to overlap reliably without exhausting the connection pool.
    private const int Replicas = 6;

    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests. " +
            "CI sets it from the postgres service; locally start a docker postgres and export it.");

    [Fact]
    public async Task ConcurrentReplicaStartups_ApplyEachOneTimeMigrationExactlyOnce()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        var store = pg.Store;

        // One counter shared by every replica: it accumulates how many of them actually executed
        // each migration body, which is the property under test.
        var applies = new MigrationApplyCounter();

        // Released only once all replicas are parked on it, so they contend for real rather than
        // trickling in one after another.
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var replicas = Enumerable.Range(0, Replicas)
            .Select(_ => new SchemaInitializer(store, applies))
            .Select(initializer => Task.Run(async () =>
            {
                await start.Task;
                await initializer.InitializeAsync();
            }))
            .ToArray();

        start.SetResult();

        var failures = new List<string>();
        foreach (var replica in replicas)
        {
            var ex = await Record.ExceptionAsync(() => replica);
            if (ex is not null)
            {
                failures.Add($"{ex.GetType().Name}: {ex.Message}");
            }
        }

        Assert.True(
            failures.Count == 0,
            $"{failures.Count} of {Replicas} concurrent startups failed:{Environment.NewLine}"
            + string.Join(Environment.NewLine, failures));

        // A fresh database is missing every one-time migration, so the winner must have applied
        // some — an empty counter would mean the assertion below proves nothing.
        Assert.NotEmpty(applies.Counts);

        var reRun = applies.Counts
            .Where(entry => entry.Value != 1)
            .Select(entry => $"{entry.Key} applied {entry.Value}x")
            .Order(StringComparer.Ordinal)
            .ToList();

        Assert.True(
            reRun.Count == 0,
            $"{reRun.Count} one-time migration(s) ran on more than one replica:{Environment.NewLine}"
            + string.Join(Environment.NewLine, reRun));
    }

    /// <summary>
    /// Counts, per migration name, how many replicas reached the point of executing its body.
    /// <c>SchemaInitializer</c> logs "applying" immediately before it runs a migration and only
    /// <c>LogDebug</c>s a skip when the ledger already records it, so this is a direct count of body
    /// executions rather than a proxy for one.
    /// </summary>
    private sealed class MigrationApplyCounter : ILogger<SchemaInitializer>
    {
        private readonly ConcurrentDictionary<string, int> _counts = new(StringComparer.Ordinal);

        public IReadOnlyDictionary<string, int> Counts => _counts;

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (state is not IReadOnlyList<KeyValuePair<string, object?>> properties)
            {
                return;
            }

            string? template = Property(properties, "{OriginalFormat}");
            string? migration = Property(properties, "Migration");
            if (migration is null
                || template is null
                || !template.Contains("applying", StringComparison.Ordinal))
            {
                return;
            }

            _counts.AddOrUpdate(migration, 1, (_, count) => count + 1);
        }

        private static string? Property(
            IReadOnlyList<KeyValuePair<string, object?>> properties, string name)
        {
            foreach (var property in properties)
            {
                if (string.Equals(property.Key, name, StringComparison.Ordinal))
                {
                    return property.Value?.ToString();
                }
            }

            return null;
        }
    }
}
