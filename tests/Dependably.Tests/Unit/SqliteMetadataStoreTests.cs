using System.Data;
using Dapper;
using Dependably.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit;

public class SqliteMetadataStoreTests
{
    private static SqliteMetadataStore CreateStore()
    {
        var connStr = $"Data Source=sqlite_meta_test_{Guid.NewGuid():N};Mode=Memory;Cache=Shared";
        return new SqliteMetadataStore(connStr);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void Provider_ReturnsSqlite()
    {
        var store = CreateStore();
        Assert.Equal(DbProvider.Sqlite, store.Provider);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public async Task OpenAsync_ReturnsOpenConnection_WithForeignKeysEnabled()
    {
        var store = CreateStore();
        await using var conn = await store.OpenAsync();

        Assert.Equal(ConnectionState.Open, conn.State);

        var fkEnabled = await conn.QuerySingleAsync<long>("PRAGMA foreign_keys");
        Assert.Equal(1L, fkEnabled);
    }
}
