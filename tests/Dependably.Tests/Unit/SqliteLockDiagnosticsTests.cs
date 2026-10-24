using Dapper;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

public sealed class SqliteLockDiagnosticsTests
{
    [Fact]
    public async Task Report_NamesTheOwnerAndTablesOfAWriteTransactionHeldOpen()
    {
        await using var store = new TestMetadataStore();
        await using (var setup = await store.OpenAsync())
        {
            await setup.ExecuteAsync("CREATE TABLE widget (id INTEGER PRIMARY KEY, name TEXT)");
        }

        await using var holder = await store.OpenAsync();
        await using var tx = await holder.BeginTransactionAsync();
        await holder.ExecuteAsync("INSERT INTO widget (name) VALUES ('a')", transaction: tx);

        string whileOpen = store.LockDiagnostics.Report(TimeSpan.Zero);
        Assert.Contains("OPEN WRITE TRANSACTION", whileOpen);
        Assert.Contains("tables widget", whileOpen);
        Assert.Contains(nameof(Report_NamesTheOwnerAndTablesOfAWriteTransactionHeldOpen), whileOpen);

        await Task.Delay(SqliteLockDiagnostics.HoldThreshold + TimeSpan.FromMilliseconds(100)); // now-ok: the hold must outlast the real-time threshold being tested.
        await tx.CommitAsync();

        string afterCommit = store.LockDiagnostics.Report(TimeSpan.Zero);
        Assert.Contains("no connection is inside a transaction right now", afterCommit);
        var (duration, owner, tables) = Assert.Single(store.LockDiagnostics.Longest(5));
        Assert.True(duration >= SqliteLockDiagnostics.HoldThreshold);
        Assert.Equal("widget", tables);
        Assert.Contains(nameof(Report_NamesTheOwnerAndTablesOfAWriteTransactionHeldOpen), owner);
    }

    [Fact]
    public async Task Report_IgnoresWritesThatCommitQuickly()
    {
        await using var store = new TestMetadataStore();
        await using var conn = await store.OpenAsync();
        await conn.ExecuteAsync("CREATE TABLE widget (id INTEGER PRIMARY KEY, name TEXT)");
        await conn.ExecuteAsync("INSERT INTO widget (name) VALUES ('a')");

        Assert.Empty(store.LockDiagnostics.Longest(5));
        Assert.True(store.LockDiagnostics.WriteTransactionCount >= 1);
    }
}
