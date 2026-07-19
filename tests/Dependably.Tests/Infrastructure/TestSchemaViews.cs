using System.Data.Common;
using Dapper;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Drops the read-model views so a test can reshape a table they read from.
///
/// SQLite validates every view against the schema on any DDL, and Postgres refuses to alter a column
/// a view depends on — so a table cannot be recreated, or a column dropped, while a view still
/// references it. Production never hits this because <c>SchemaInitializer</c> drops the views before
/// anything reshapes a table and recreates them at the end. A test doing its own schema surgery has
/// to follow the same order, and this is how it says so.
/// </summary>
internal static class TestSchemaViews
{
    internal static async Task DropAsync(DbConnection conn)
    {
        foreach (string view in new[] { "artifact_inventory", "artifact_license", "org_storage_bytes" })
        {
            // rawsql: the name comes from a local compile-time constant array.
            await conn.ExecuteAsync($"DROP VIEW IF EXISTS {view}");
        }
    }
}
