namespace Dependably.Tests.Integration;

/// <summary>
/// The broker behind <c>Category=RedisLive</c>. CI's <c>redis-smoke</c> job sets
/// <c>TEST_REDIS_CONNECTION</c> from its redis service; locally, start a throwaway
/// <c>redis:7-alpine</c> and export it (e.g. <c>127.0.0.1:6379</c>).
///
/// <para>An unset variable fails the test rather than skipping it. A skipped live test reads as
/// green, and a job whose broker wiring broke would then report a pass while exercising nothing.
/// The category is excluded from every other test job's filter, so it only runs where a broker
/// exists.</para>
///
/// <para>Point it at a disposable instance only: the host-boot test persists the Data Protection
/// key ring under the unprefixed <c>DataProtection-Keys</c> key, as production does.</para>
/// </summary>
internal static class LiveRedis
{
    internal const string Category = "RedisLive";

    internal static string ConnectionString
    {
        get
        {
            string? value = Environment.GetEnvironmentVariable("TEST_REDIS_CONNECTION");
            return !string.IsNullOrWhiteSpace(value)
                ? value
                : throw new InvalidOperationException(
                    "TEST_REDIS_CONNECTION must be set to run Category=RedisLive tests. CI sets it from "
                    + "the redis service in the redis-smoke job; locally start a throwaway redis:7-alpine "
                    + "and export it (e.g. TEST_REDIS_CONNECTION=127.0.0.1:6379).");
        }
    }

    /// <summary>A key prefix no other test or run shares, so concurrent runs never cross-evict.</summary>
    internal static string UniquePrefix(string label) => $"redislive-{label}-{Guid.NewGuid():N}:";

    /// <summary>
    /// Polls <paramref name="condition"/> on the real clock until it holds or
    /// <paramref name="budget"/> elapses. Delivery over a real broker is asynchronous, so the
    /// tests wait on the observable effect rather than a fixed sleep.
    /// </summary>
    internal static Task<bool> UntilAsync(Func<bool> condition, TimeSpan budget) =>
        UntilAsync(() => Task.FromResult(condition()), budget);

    /// <inheritdoc cref="UntilAsync(Func{bool}, TimeSpan)"/>
    internal static async Task<bool> UntilAsync(Func<Task<bool>> condition, TimeSpan budget)
    {
        long start = TimeProvider.System.GetTimestamp();
        while (!await condition())
        {
            if (TimeProvider.System.GetElapsedTime(start) > budget)
            {
                return await condition();
            }

            await Task.Delay(TimeSpan.FromMilliseconds(25), TimeProvider.System, CancellationToken.None);
        }

        return true;
    }
}

/// <summary>
/// Serialises the live-Redis classes against each other and against every other collection. They
/// share one broker and, for the host-boot test, a process-wide Data Protection key; running them
/// alone also keeps a loaded runner from stretching delivery past the poll budgets.
/// </summary>
[CollectionDefinition("LiveRedis", DisableParallelization = true)]
public sealed class LiveRedisCollection;
