using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// A parent delete finds its cascading children by the foreign-key column alone. Neither SQLite nor
/// Postgres indexes a foreign key by itself, and a partial index (<c>WHERE owner_kind = …</c>) does
/// not count: the cascade's lookup carries no <c>owner_kind</c> predicate, so the planner cannot
/// prove the partial index covers it and scans the whole child table instead — once per deleted
/// <c>package_versions</c> or <c>cache_artifact</c> row. Every cascading foreign key on the OCI scan
/// tables must therefore lead some index that has no WHERE clause.
/// </summary>
[Trait("Category", "Schema")]
public sealed class OciScanCascadeIndexTests : IAsyncLifetime
{
    private static readonly string[] Tables =
        ["oci_scan_jobs", "oci_scan_coverage", "oci_image_components", "oci_component_vulns"];

    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();
    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task EveryCascadingForeignKey_LeadsAFullIndex()
    {
        await using var conn = await _db.OpenAsync();
        var missing = new List<string>();
        foreach (string table in Tables)
        {
            var cascading = (await conn.QueryAsync<string>(
                """
                SELECT "from" FROM pragma_foreign_key_list(@table) WHERE on_delete = 'CASCADE'
                """, new { table })).ToList();
            Assert.NotEmpty(cascading);

            var leading = (await conn.QueryAsync<string>(
                """
                SELECT ii.name
                FROM pragma_index_list(@table) il
                JOIN pragma_index_info(il.name) ii
                WHERE il.partial = 0 AND ii.seqno = 0
                """, new { table })).ToHashSet(StringComparer.Ordinal);

            missing.AddRange(cascading.Where(c => !leading.Contains(c)).Select(c => $"{table}.{c}"));
        }

        Assert.True(missing.Count == 0,
            "Cascading foreign keys with no full index leading on them: " + string.Join(", ", missing));
    }
}
