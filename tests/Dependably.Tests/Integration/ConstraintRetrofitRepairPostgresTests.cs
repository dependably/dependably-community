using Dapper;
using Dependably.Infrastructure;
using static Dependably.Tests.Integration.ConstraintRetrofitLockBoundPostgresTests;

namespace Dependably.Tests.Integration;

/// <summary>
/// What the column-constraint retrofit does with legacy rows that break a constraint it adds. A
/// <c>NOT VALID</c> CHECK is still checked on every UPDATE of a row, so a violating row it leaves in
/// place rejects every later write to that row: the warning has to name the rows and say so. A
/// vocabulary column whose stray value carries no security meaning is repaired to its declared
/// default instead, an orphaned member-removal attribution is nulled the way removing the member
/// would have, and a same-named foreign key whose definition drifted is replaced rather than counted
/// as present.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class ConstraintRetrofitRepairPostgresTests
{
    [Fact]
    public async Task ViolatingRowInAPolicyColumn_IsLeft_AndTheWarningNamesTheRowsAndTheConsequence()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        string schema = await SchemaSqlAsync();
        var log = new CapturingLogger();

        const string name = "org_settings_verify_sbom_signatures_check";
        await using var conn = await pg.Store.OpenAsync();
        await conn.ExecuteAsync(
            $"""
            INSERT INTO orgs (id, slug) VALUES ('org-ok', 'acme'), ('org-bad', 'beta');
            INSERT INTO org_settings (org_id) VALUES ('org-ok'), ('org-bad');
            ALTER TABLE org_settings DROP CONSTRAINT {name};
            UPDATE org_settings SET verify_sbom_signatures = 'enforce' WHERE org_id = 'org-bad';
            """);

        await new SchemaInitializer(pg.Store, log).RetrofitColumnConstraintsAsync(conn, schema);

        Assert.False(await ValidatedAsync(conn, name));
        Assert.Equal("enforce", await conn.ExecuteScalarAsync<string>(
            "SELECT verify_sbom_signatures FROM org_settings WHERE org_id = 'org-bad'"));
        string warning = Assert.Single(log.Warnings, m => m.Contains(name, StringComparison.Ordinal));
        Assert.Contains("org_settings.verify_sbom_signatures", warning, StringComparison.Ordinal);
        Assert.Contains("1 existing row", warning, StringComparison.Ordinal);
        Assert.Contains("org-bad", warning, StringComparison.Ordinal);
        Assert.DoesNotContain("org-ok", warning, StringComparison.Ordinal);
        Assert.Contains("reject every UPDATE", warning, StringComparison.Ordinal);

        // The consequence the warning states is real: the violating row refuses an unrelated UPDATE.
        var update = await Record.ExceptionAsync(() => conn.ExecuteAsync(
            "UPDATE org_settings SET anonymous_pull = 1 WHERE org_id = 'org-bad'"));
        Assert.Contains("23514", update?.Message ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public async Task OutOfVocabularyValueInARepairableColumn_IsSetToTheDefault_AndTheConstraintValidates()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        string schema = await SchemaSqlAsync();
        var log = new CapturingLogger();

        const string name = "project_documents_tool_version_explicit_unknown_check";
        await using var conn = await pg.Store.OpenAsync();
        await conn.ExecuteAsync(
            $"""
            INSERT INTO orgs (id, slug) VALUES ('o1', 'acme');
            ALTER TABLE project_documents DROP CONSTRAINT {name};
            SET session_replication_role = replica;
            INSERT INTO project_documents
                (id, org_id, project_version_id, doc_type, format, sha256, blob_key, tool_version_explicit_unknown)
            VALUES ('doc-set', 'o1', 'pv1', 'sbom', 'cyclonedx-json', 'aa', 'k1', 1),
                   ('doc-stray', 'o1', 'pv2', 'sbom', 'cyclonedx-json', 'bb', 'k2', 7);
            RESET session_replication_role;
            """);

        await new SchemaInitializer(pg.Store, log).RetrofitColumnConstraintsAsync(conn, schema);

        Assert.True(await ValidatedAsync(conn, name));
        var values = (await conn.QueryAsync<(string Id, int Value)>(
            "SELECT id, tool_version_explicit_unknown FROM project_documents ORDER BY id")).ToList();
        Assert.Equal([("doc-set", 1), ("doc-stray", 0)], values);
        Assert.Contains(log.Warnings, m => m.Contains("project_documents.tool_version_explicit_unknown", StringComparison.Ordinal)
            && m.Contains("Repaired 1 row", StringComparison.Ordinal));
    }

    [Fact]
    public async Task OrphanedCreatedBy_IsNulled_AndTheForeignKeyValidates()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        string schema = await SchemaSqlAsync();
        var log = new CapturingLogger();

        const string name = "license_allowlist_created_by_fkey";
        await using var conn = await pg.Store.OpenAsync();
        await conn.ExecuteAsync(
            $"""
            INSERT INTO orgs (id, slug) VALUES ('o1', 'acme');
            INSERT INTO users (id, tenant_id, email, password_hash) VALUES ('u-live', 'o1', 'a@example.com', 'x');
            ALTER TABLE license_allowlist DROP CONSTRAINT {name};
            INSERT INTO license_allowlist (id, org_id, license_spdx, created_by)
            VALUES ('al-live', 'o1', 'MIT', 'u-live'),
                   ('al-orphan', 'o1', 'Apache-2.0', 'u-removed'),
                   ('al-none', 'o1', 'BSD-3-Clause', NULL);
            """);

        await new SchemaInitializer(pg.Store, log).RetrofitColumnConstraintsAsync(conn, schema);

        Assert.True(await ValidatedAsync(conn, name));
        var rows = (await conn.QueryAsync<(string Id, string? CreatedBy)>(
            "SELECT id, created_by FROM license_allowlist ORDER BY id")).ToList();
        Assert.Equal([("al-live", "u-live"), ("al-none", null), ("al-orphan", null)], rows);
        Assert.Contains(log.Warnings, m => m.Contains("license_allowlist.created_by", StringComparison.Ordinal)
            && m.Contains("Cleared 1 ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task OrphanInAColumnMemberRemovalDoesNotNull_IsLeftAndNamed()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        string schema = await SchemaSqlAsync();
        var log = new CapturingLogger();

        const string name = "license_allowlist_org_id_fkey";
        await using var conn = await pg.Store.OpenAsync();
        await conn.ExecuteAsync(
            $"""
            ALTER TABLE license_allowlist DROP CONSTRAINT {name};
            INSERT INTO license_allowlist (id, org_id, license_spdx) VALUES ('al-1', 'org-gone', 'MIT');
            """);

        await new SchemaInitializer(pg.Store, log).RetrofitColumnConstraintsAsync(conn, schema);

        Assert.False(await ValidatedAsync(conn, name));
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM license_allowlist"));
        string warning = Assert.Single(log.Warnings, m => m.Contains(name, StringComparison.Ordinal));
        Assert.Contains("1 existing row", warning, StringComparison.Ordinal);
        Assert.Contains("al-1", warning, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SameNamedForeignKeyWithADifferentOnDelete_IsReplaced()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        string schema = await SchemaSqlAsync();
        var log = new CapturingLogger();

        const string name = "license_allowlist_org_id_fkey";
        await using var conn = await pg.Store.OpenAsync();
        await conn.ExecuteAsync(
            $"""
            ALTER TABLE license_allowlist DROP CONSTRAINT {name};
            ALTER TABLE license_allowlist ADD CONSTRAINT {name} FOREIGN KEY (org_id) REFERENCES orgs(id);
            """);
        Assert.Equal("a", await OnDeleteAsync(conn, name));

        await new SchemaInitializer(pg.Store, log).RetrofitColumnConstraintsAsync(conn, schema);

        Assert.Equal("c", await OnDeleteAsync(conn, name));
        Assert.True(await ValidatedAsync(conn, name));
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM pg_constraint WHERE conrelid = 'license_allowlist'::regclass AND contype = 'f' "
            + "AND conkey = ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid = 'license_allowlist'::regclass AND attname = 'org_id')]"));

        // Converged: the next boot finds nothing to replace.
        var second = new CapturingLogger();
        await new SchemaInitializer(pg.Store, second).RetrofitColumnConstraintsAsync(conn, schema);
        Assert.Empty(second.Warnings);
    }

    private static Task<string?> OnDeleteAsync(System.Data.Common.DbConnection conn, string name) =>
        conn.ExecuteScalarAsync<string?>(
            "SELECT confdeltype::text FROM pg_constraint WHERE conname = @name", new { name });
}
