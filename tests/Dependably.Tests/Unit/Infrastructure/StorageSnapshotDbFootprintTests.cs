using System.Text.RegularExpressions;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Usage;
using Dependably.Tests.Compliance;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// <c>storage_snapshot.db_row_count</c> sums a fixed list of tables. A table in that list with no
/// <c>org_id</c> would either fail the capture or, worse, attribute rows no org owns, so each one is
/// checked against both schema files; and the list the capture SQL actually counts is checked
/// against <see cref="StorageSnapshotRepository.DbFootprintTables"/>, so the documented list is the
/// counted one.
/// </summary>
[Trait("Category", "Unit")]
public sealed partial class StorageSnapshotDbFootprintTests
{
    [GeneratedRegex(@"SELECT org_id, COUNT\(\*\) AS n FROM (?<table>\w+) GROUP BY org_id")]
    private static partial Regex FootprintArmRegex();

    [Fact]
    public void Every_footprint_table_declares_org_id_in_both_schema_files()
    {
        string root = SchemaTestPaths.SourceRoot();
        var sqlite = SchemaSqlParser.ParseTables(File.ReadAllText(SchemaTestPaths.SqliteSchema(root)));
        var postgres = SchemaSqlParser.ParseTables(File.ReadAllText(SchemaTestPaths.PostgresSchema(root)));

        var missing = new List<string>();
        foreach (string table in StorageSnapshotRepository.DbFootprintTables)
        {
            if (!sqlite.TryGetValue(table, out var sqliteColumns) || !sqliteColumns.Contains("org_id", StringComparer.OrdinalIgnoreCase))
            {
                missing.Add($"Schema.sql: {table}");
            }

            if (!postgres.TryGetValue(table, out var pgColumns) || !pgColumns.Contains("org_id", StringComparer.OrdinalIgnoreCase))
            {
                missing.Add($"Schema.pg.sql: {table}");
            }
        }

        Assert.True(missing.Count == 0,
            "db_row_count may only count tables that declare org_id; these do not: " + string.Join(", ", missing));
    }

    [Fact]
    public void The_capture_counts_exactly_the_documented_tables()
    {
        var counted = FootprintArmRegex().Matches(StorageSnapshotRepository.CaptureSql)
            .Select(m => m.Groups["table"].Value)
            .ToList();

        Assert.Equal(counted.Count, counted.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(
            StorageSnapshotRepository.DbFootprintTables.OrderBy(t => t, StringComparer.Ordinal),
            counted.OrderBy(t => t, StringComparer.Ordinal));
    }

    [Fact]
    public void The_list_is_not_empty_and_has_no_duplicates()
    {
        Assert.NotEmpty(StorageSnapshotRepository.DbFootprintTables);
        Assert.Equal(
            StorageSnapshotRepository.DbFootprintTables.Count,
            StorageSnapshotRepository.DbFootprintTables.Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void The_capture_names_every_accepted_manifest_media_type()
    {
        foreach (string mediaType in Dependably.Protocol.OciManifestParser.AcceptedMediaTypes)
        {
            Assert.Contains("'" + mediaType + "'", StorageSnapshotRepository.CaptureSql, StringComparison.Ordinal);
        }
    }
}
