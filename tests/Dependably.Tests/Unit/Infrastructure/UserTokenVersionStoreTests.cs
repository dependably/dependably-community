using System.Data;
using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Caching.Memory;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class UserTokenVersionStoreTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public UserTokenVersionStoreTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private async Task<string> SeedUserAsync()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"tv-{Guid.NewGuid():N}");
        return await UserSeeder.InsertAsync(_fixture.Store, orgId, $"u-{Guid.NewGuid():N}@x.test");
    }

    private async Task<long> ReadTokenVersionAsync(string userId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM users WHERE id = @id", new { id = userId });
    }

    private async Task BumpTokenVersionAsync(string userId)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE users SET token_version = token_version + 1 WHERE id = @id",
            new { id = userId });
    }

    [Fact]
    public async Task GetCurrentVersionAsync_CachesFoundValue()
    {
        using var memCache = new MemoryCache(new MemoryCacheOptions());
        var store = new UserTokenVersionStore(_fixture.Store, memCache);
        string userId = await SeedUserAsync();

        long first = (await store.GetCurrentVersionAsync(userId))!.Value;

        // Bump the DB directly (no Invalidate) — the cached value must still be served.
        await BumpTokenVersionAsync(userId);
        long cached = (await store.GetCurrentVersionAsync(userId))!.Value;

        Assert.Equal(first, cached);
    }

    [Fact]
    public async Task Invalidate_ForcesReReadOfBumpedVersion()
    {
        using var memCache = new MemoryCache(new MemoryCacheOptions());
        var store = new UserTokenVersionStore(_fixture.Store, memCache);
        string userId = await SeedUserAsync();

        long before = (await store.GetCurrentVersionAsync(userId))!.Value;
        await BumpTokenVersionAsync(userId);
        store.Invalidate(userId);

        Assert.Equal(before + 1, (await store.GetCurrentVersionAsync(userId))!.Value);
    }

    [Fact]
    public async Task GetCurrentVersionAsync_ReturnsNull_ForMissingUser_AndDoesNotCache()
    {
        using var memCache = new MemoryCache(new MemoryCacheOptions());
        var store = new UserTokenVersionStore(_fixture.Store, memCache);

        Assert.Null(await store.GetCurrentVersionAsync($"ghost-{Guid.NewGuid():N}"));
    }

    [Fact]
    public async Task MissingUserLookup_DoesNotRetainItsFillGuard()
    {
        // Not-cached terminal branch: a cache MISS mints a per-user generation guard before the DB
        // read, but a missing user row (version == null) is intentionally never cached, so the
        // guard is never tied to a cache entry. This lookup runs on every JWT request, so a deleted
        // user's id would otherwise leak one CancellationTokenSource forever — the terminal branch
        // must retire the just-minted guard.
        using var memCache = new MemoryCache(new MemoryCacheOptions());
        var store = new UserTokenVersionStore(_fixture.Store, memCache);

        Assert.Null(await store.GetCurrentVersionAsync($"ghost-{Guid.NewGuid():N}"));

        // Synchronous retire on the terminal branch — no cache entry, so no eviction callback to
        // await. On the pre-fix code the guard leaks and this reads 1.
        Assert.Equal(0, store.FillGuardCount);
    }

    [Fact]
    public async Task InvalidateThatRacesAnInFlightFill_DoesNotCacheThePreBumpVersion()
    {
        // Invalidate-then-fill race: request T1 reads the pre-bump version from the DB, then a
        // concurrent credential change commits the bump and calls Invalidate (evicting the key).
        // T1 then completes its fill. On the buggy code T1 caches the stale pre-bump value AFTER
        // the eviction, so OnTokenValidated keeps honouring already-killed sessions for a TTL.
        //
        // The hooked store fires the bump+Invalidate exactly between T1's DB read and its cache
        // write — the precise interleaving the finding describes. This test fails on the old code
        // (stale value survives in the cache) and passes on the guard-token fix.
        using var memCache = new MemoryCache(new MemoryCacheOptions());
        string userId = await SeedUserAsync();
        long before = await ReadTokenVersionAsync(userId);

        UserTokenVersionStore? store = null;
        var hooked = new AfterReadHookMetadataStore(_fixture.Store);
        store = new UserTokenVersionStore(hooked, memCache);

        // Runs once, in the window between the DB read returning the pre-bump value and the fill's
        // cache write: commit the version bump and invalidate, mimicking the racing password change.
        hooked.AfterScalarRead = async () =>
        {
            await BumpTokenVersionAsync(userId);
            store!.Invalidate(userId);
        };

        // T1's fill: reads the pre-bump value, then the hook bumps+invalidates, then T1 writes.
        long t1 = (await store.GetCurrentVersionAsync(userId))!.Value;
        Assert.Equal(before, t1); // T1 legitimately read the pre-bump value

        // The killer assertion: a subsequent lookup must observe the bumped version, not a stale
        // cached pre-bump value left behind by T1's post-eviction write.
        long observed = (await store.GetCurrentVersionAsync(userId))!.Value;
        Assert.Equal(before + 1, observed);
    }

    // ── Test seam: fires a one-shot hook after each scalar read, before the caller sees it ──

    private sealed class AfterReadHookMetadataStore(IMetadataStore inner) : IMetadataStore
    {
        public Func<Task>? AfterScalarRead { get; set; }

        public DbProvider Provider => inner.Provider;

        public async Task<DbConnection> OpenAsync(CancellationToken ct = default)
        {
            var conn = await inner.OpenAsync(ct);
            return new HookConnection(conn, this);
        }

        private async Task FireOnceAsync()
        {
            var hook = AfterScalarRead;
            if (hook is null)
            {
                return;
            }

            AfterScalarRead = null; // one-shot: later re-reads must not re-trigger the race
            await hook();
        }

        private sealed class HookConnection(DbConnection inner, AfterReadHookMetadataStore owner) : DbConnection
        {
            public DbConnection Inner => inner;

            internal Task FireOnceAsync() => owner.FireOnceAsync();

            [AllowNull]
            public override string ConnectionString
            {
                get => inner.ConnectionString;
                set => inner.ConnectionString = value;
            }

            public override string Database => inner.Database;
            public override string DataSource => inner.DataSource;
            public override string ServerVersion => inner.ServerVersion;
            public override ConnectionState State => inner.State;

            public override void ChangeDatabase(string databaseName) => inner.ChangeDatabase(databaseName);
            public override void Close() => inner.Close();
            public override void Open() => inner.Open();
            public override Task OpenAsync(CancellationToken ct) => inner.OpenAsync(ct);

            protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel) =>
                inner.BeginTransaction(isolationLevel);

            protected override DbCommand CreateDbCommand() => new HookCommand(inner.CreateCommand(), this);

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    inner.Dispose();
                }

                base.Dispose(disposing);
            }

            public override async ValueTask DisposeAsync()
            {
                await inner.DisposeAsync();
                await base.DisposeAsync();
                GC.SuppressFinalize(this);
            }
        }

        private sealed class HookCommand(DbCommand inner, HookConnection owner) : DbCommand
        {
            [AllowNull]
            public override string CommandText
            {
                get => inner.CommandText;
                set => inner.CommandText = value;
            }

            public override int CommandTimeout
            {
                get => inner.CommandTimeout;
                set => inner.CommandTimeout = value;
            }

            public override CommandType CommandType
            {
                get => inner.CommandType;
                set => inner.CommandType = value;
            }

            public override bool DesignTimeVisible
            {
                get => inner.DesignTimeVisible;
                set => inner.DesignTimeVisible = value;
            }

            public override UpdateRowSource UpdatedRowSource
            {
                get => inner.UpdatedRowSource;
                set => inner.UpdatedRowSource = value;
            }

            protected override DbConnection? DbConnection
            {
                get => owner;
                set { /* the inner command keeps its real connection */ }
            }

            protected override DbParameterCollection DbParameterCollection => inner.Parameters;

            protected override DbTransaction? DbTransaction
            {
                get => inner.Transaction;
                set => inner.Transaction = value;
            }

            public override void Cancel() => inner.Cancel();
            public override int ExecuteNonQuery() => inner.ExecuteNonQuery();
            public override object? ExecuteScalar() => inner.ExecuteScalar();
            public override void Prepare() => inner.Prepare();

            protected override DbParameter CreateDbParameter() => inner.CreateParameter();

            protected override DbDataReader ExecuteDbDataReader(CommandBehavior behavior) =>
                inner.ExecuteReader(behavior);

            protected override Task<DbDataReader> ExecuteDbDataReaderAsync(
                CommandBehavior behavior, CancellationToken ct) =>
                inner.ExecuteReaderAsync(behavior, ct);

            public override Task<int> ExecuteNonQueryAsync(CancellationToken ct) =>
                inner.ExecuteNonQueryAsync(ct);

            public override async Task<object?> ExecuteScalarAsync(CancellationToken ct)
            {
                object? result = await inner.ExecuteScalarAsync(ct);
                await owner.FireOnceAsync();
                return result;
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    inner.Dispose();
                }

                base.Dispose(disposing);
            }
        }
    }
}
