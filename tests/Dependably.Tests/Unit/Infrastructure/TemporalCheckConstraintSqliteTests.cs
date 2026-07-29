using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Data.Sqlite;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Proves the fresh-install SQLite CHECK constraint (declared in the <c>CREATE TABLE</c> block of
/// <c>Schema.sql</c>, never retrofitted onto an existing database — see
/// <c>SchemaInitializer.TemporalColumnNaming.cs</c>) actually rejects a bad-shaped INSERT and
/// accepts every canonical shape, against a real (in-memory) SQLite engine rather than only the
/// static schema-file text <c>TemporalCheckConstraintComplianceTests</c> checks.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TemporalCheckConstraintSqliteTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    public static IEnumerable<object[]> AcceptedShapes()
    {
        yield return ["2026-03-04T05:06:07Z"];
        yield return ["2026-03-04T05:06:07.123Z"];
        yield return ["2026-03-04T05:06:07.123456Z"];
    }

    public static IEnumerable<object[]> RejectedShapes()
    {
        yield return ["2026-03-04 05:06:07+02:00"];
        yield return ["2026-03-04T05:06:07.0000000+00:00"];
        yield return [""];
        yield return ["not a date"];
        yield return ["20260304050607"];
    }

    [Theory]
    [MemberData(nameof(AcceptedShapes))]
    public async Task NullableColumn_AcceptsEveryCanonicalShape(string value)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, last_login_at) " +
            "VALUES (@id, 'o1', @email, 'h', @value)",
            new { id = Guid.NewGuid().ToString("N"), email = $"{Guid.NewGuid():N}@x.com", value });

        string stored = await conn.QuerySingleAsync<string>(
            "SELECT last_login_at FROM users WHERE last_login_at = @value", new { value });
        Assert.Equal(value, stored);
    }

    [Theory]
    [MemberData(nameof(RejectedShapes))]
    public async Task NullableColumn_RejectsEveryObservedBadShape(string value)
    {
        await using var conn = await _db.OpenAsync();
        var ex = await Assert.ThrowsAsync<SqliteException>(() => conn.ExecuteAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, last_login_at) " +
            "VALUES (@id, 'o1', @email, 'h', @value)",
            new { id = Guid.NewGuid().ToString("N"), email = $"{Guid.NewGuid():N}@x.com", value }));

        Assert.Contains("CHECK constraint failed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task NullableColumn_PermitsNull()
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO users (id, tenant_id, email, password_hash, last_login_at) " +
            "VALUES (@id, 'o1', @email, 'h', NULL)",
            new { id = Guid.NewGuid().ToString("N"), email = $"{Guid.NewGuid():N}@x.com" });
    }

    [Theory]
    [MemberData(nameof(RejectedShapes))]
    public async Task NotNullColumn_RejectsEveryObservedBadShape(string value)
    {
        // orgs.created_at is NOT NULL with a DEFAULT; an explicit bad-shaped value still has to
        // clear the same CHECK the nullable columns do.
        await using var conn = await _db.OpenAsync();
        var ex = await Assert.ThrowsAsync<SqliteException>(() => conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug, created_at) VALUES (@id, @slug, @value)",
            new { id = Guid.NewGuid().ToString("N"), slug = Guid.NewGuid().ToString("N"), value }));

        Assert.Contains("CHECK constraint failed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
