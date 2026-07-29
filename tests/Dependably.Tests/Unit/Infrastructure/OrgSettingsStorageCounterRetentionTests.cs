using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// <c>org_settings.storage_used_bytes</c> is dormant capacity, not a live counter: every quota check
/// derives a tenant's stored bytes from the <c>org_storage_bytes</c> view. The column is nonetheless
/// declared and re-added on upgrade, because the preceding release still increments it and blue-green
/// runs both slots against one database for the whole cutover window — a slot whose quota UPDATE
/// names a column this schema removed fails for the length of the overlap.
///
/// These pin the expand step of that expand/migrate/contract sequence on SQLite: the column exists on
/// a fresh install, comes back on a database that lost it, and stays omittable from an INSERT.
/// <c>SchemaBackwardCompatibilityComplianceTests</c> pins the declaration itself against the previous
/// release tag; this pins the runtime shape the older slot actually binds to.
/// </summary>
[Trait("Category", "Schema")]
public sealed class OrgSettingsStorageCounterRetentionTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();
    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task FreshInstall_DeclaresTheCounter_NotNullAndDefaultedToZero()
    {
        await using var conn = await _db.OpenAsync();
        var (notNull, defaultValue) = await conn.QuerySingleOrDefaultAsync<(long NotNull, string? Default)>(
            """
            SELECT "notnull" AS "NotNull", dflt_value AS "Default"
            FROM pragma_table_info('org_settings') WHERE name = 'storage_used_bytes'
            """);

        Assert.Equal(1, notNull);
        Assert.Equal("0", defaultValue);
    }

    [Fact]
    public async Task DatabaseMissingTheCounter_GetsItBackOnTheNextBoot()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("ALTER TABLE org_settings DROP COLUMN storage_used_bytes");
            Assert.Equal(0, await CounterColumnCountAsync(conn));
        }

        await new SchemaInitializer(_db).InitializeAsync();

        await using (var conn = await _db.OpenAsync())
        {
            Assert.Equal(1, await CounterColumnCountAsync(conn));
        }
    }

    /// <summary>
    /// The previous release's quota UPDATE reads the counter and writes it back. Omitting the column
    /// from an INSERT must therefore leave it a number, not NULL, or that slot's
    /// <c>storage_used_bytes + n</c> arithmetic silently produces NULL.
    /// </summary>
    [Fact]
    public async Task CounterIsOmittableFromAnInsert_AndLandsAtZero()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org-counter', 'counter')");
        await conn.ExecuteAsync("INSERT INTO org_settings (org_id) VALUES ('org-counter')");

        long value = await conn.ExecuteScalarAsync<long>(
            "SELECT storage_used_bytes FROM org_settings WHERE org_id = @orgId",
            new { orgId = "org-counter" });
        Assert.Equal(0, value);
    }

    private static Task<long> CounterColumnCountAsync(System.Data.Common.DbConnection conn) =>
        conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM pragma_table_info('org_settings') WHERE name = 'storage_used_bytes'");
}
