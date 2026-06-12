using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Data.Sqlite;

namespace Dependably.Tests.Unit;

/// <summary>
/// Schema migration: <c>auditor</c> must be a permitted value of <c>users.role</c> and
/// <c>invites.role</c> on both fresh and existing databases. The Capabilities matrix maps
/// the role to a capability set; without this constraint expansion the row insert fails
/// at the database layer.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuditorRoleMigrationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task FreshSchema_AcceptsAuditorRoleOnUsersInsert()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme')");

        await conn.ExecuteAsync("""
            INSERT INTO users (id, tenant_id, email, password_hash, role)
            VALUES ('u1', 'o1', 'a@example.com', '', 'auditor')
            """);

        string? role = await conn.ExecuteScalarAsync<string>(
            "SELECT role FROM users WHERE id = 'u1'");
        Assert.Equal("auditor", role);
    }

    [Fact]
    public async Task FreshSchema_AcceptsAuditorRoleOnInvitesInsert()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1','acme')");
        await conn.ExecuteAsync("""
            INSERT INTO users (id, tenant_id, email, password_hash, role)
            VALUES ('u1', 'o1', 'a@example.com', '', 'owner')
            """);

        await conn.ExecuteAsync("""
            INSERT INTO invites (id, org_id, email, role, token_hash, created_by, expires_at)
            VALUES ('i1', 'o1', 'b@example.com', 'auditor', 'h1', 'u1',
                    datetime('now','+7 days'))
            """);

        string? role = await conn.ExecuteScalarAsync<string>(
            "SELECT role FROM invites WHERE id = 'i1'");
        Assert.Equal("auditor", role);
    }

    [Fact]
    public async Task LegacySchemaWithOldCheck_MigratedInPlace_AcceptsAuditor()
    {
        // Simulate a database that pre-dates this migration: drop + recreate the relevant
        // tables with the OLD CHECK constraint, then re-run the schema initializer and
        // assert the migration removed the constraint.
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync("DROP TABLE IF EXISTS invites");
            await setup.ExecuteAsync("DROP TABLE IF EXISTS users");
            await setup.ExecuteAsync("""
                CREATE TABLE users (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT,
                    email TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('member','admin','owner'))
                )
                """);
            await setup.ExecuteAsync("""
                CREATE TABLE invites (
                    id TEXT PRIMARY KEY,
                    org_id TEXT,
                    email TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('member','admin','owner')),
                    token_hash TEXT NOT NULL,
                    created_by TEXT,
                    created_at TEXT,
                    expires_at TEXT,
                    accepted_at TEXT
                )
                """);
            // Mark the migration as not yet applied so re-init runs it.
            await setup.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = 'expand_role_check_with_auditor'");

            // Sanity: legacy CHECK rejects 'auditor'.
            var ex = await Assert.ThrowsAsync<SqliteException>(() => setup.ExecuteAsync("""
                INSERT INTO users (id, email, password_hash, role)
                VALUES ('u-legacy','a@example.com','','auditor')
                """));
            Assert.Contains("CHECK", ex.Message);
        }

        // Re-run initializer; the one-time migration should rewrite the CHECK.
        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        await verify.ExecuteAsync("""
            INSERT INTO users (id, email, password_hash, role)
            VALUES ('u-after','b@example.com','','auditor')
            """);
        string? role = await verify.ExecuteScalarAsync<string>(
            "SELECT role FROM users WHERE id = 'u-after'");
        Assert.Equal("auditor", role);
    }
}
