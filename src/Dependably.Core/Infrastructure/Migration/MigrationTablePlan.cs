using System.Data.Common;
using Dapper;

namespace Dependably.Infrastructure.Migration;

/// <summary>
/// The ordered table list a SQLite → Postgres copy walks, derived from the live source database
/// rather than from a literal list in code. Tables come from <c>sqlite_master</c> and the ordering
/// comes from the real foreign keys reported by <c>pragma_foreign_key_list</c>, so a table added to
/// <c>Schema.sql</c> (or by an additive migration) is picked up the moment it exists in the
/// database — there is no list to forget to update.
///
/// <para>Parents sort before children, which is what lets the copy run against a Postgres that is
/// enforcing foreign keys. A cycle cannot be topologically ordered; the unplaceable tables are
/// appended in name order and <see cref="HasCycle"/> is set, so the caller warns loudly instead of
/// silently emitting a partial plan.</para>
/// </summary>
public sealed class MigrationTablePlan
{
    /// <summary>
    /// Tables that physically exist but are not part of the logical data set.
    /// <c>_applied_migrations</c> is the target's own migration ledger — it is written by the
    /// target's <c>SchemaInitializer</c> run, and copying the source's ledger over it would
    /// duplicate rows and misreport which migrations that database has actually seen.
    /// <c>sqlite_sequence</c> is a SQLite engine table with no Postgres counterpart; the Postgres
    /// side of that concern is the identity sequences, reset explicitly after the copy.
    /// </summary>
    public static readonly IReadOnlySet<string> ExcludedTables =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "_applied_migrations", "sqlite_sequence" };

    /// <summary>
    /// Tables a bare <c>SchemaInitializer</c> run populates on its own, with no operator data
    /// involved (the SPDX licence catalogue and its seed-revision marker). Rows here do not make a
    /// target "already in use", so the pre-flight refusal ignores them — otherwise every freshly
    /// initialised Postgres would look occupied. Asserted against a freshly initialised database by
    /// the migration plan tests, so a new seeder that starts writing somewhere else fails the gate
    /// instead of silently widening this set.
    /// </summary>
    public static readonly IReadOnlySet<string> SeedPopulatedTables =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "spdx_license", "instance_settings" };

    private MigrationTablePlan(IReadOnlyList<string> tables, bool hasCycle)
    {
        Tables = tables;
        HasCycle = hasCycle;
    }

    /// <summary>Tables in dependency order: every parent precedes every child that references it.</summary>
    public IReadOnlyList<string> Tables { get; }

    /// <summary>
    /// True when the foreign-key graph contains a cycle, so <see cref="Tables"/> could not be fully
    /// ordered. The copy can still be attempted, but a cycle means some child may precede its parent.
    /// </summary>
    public bool HasCycle { get; }

    /// <summary>
    /// Reads the table set and the foreign-key graph out of an open SQLite connection and returns
    /// them topologically sorted, parents first.
    /// </summary>
    public static Task<MigrationTablePlan> DiscoverAsync(DbConnection sqlite, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(sqlite);

        return DiscoverCoreAsync(sqlite, ct);
    }

    private static async Task<MigrationTablePlan> DiscoverCoreAsync(DbConnection sqlite, CancellationToken ct)
    {
        var tables = await LoadTableNamesAsync(sqlite, ct);
        var (children, indegree) = await BuildForeignKeyGraphAsync(sqlite, tables, ct);
        var (ordered, cycle) = TopologicalSort(tables, children, indegree);

        return new MigrationTablePlan(ordered, cycle);
    }

    /// <summary>The migratable table set, alphabetised with the excluded tables already dropped.</summary>
    private static async Task<List<string>> LoadTableNamesAsync(DbConnection sqlite, CancellationToken ct)
    {
        // xtenant: whole-database migration — this reads the SQLite catalogue, which has no tenant column.
        var tables = (await sqlite.QueryAsync<string>(
                new CommandDefinition(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
                    cancellationToken: ct)))
            .Where(t => !ExcludedTables.Contains(t))
            .OrderBy(t => t, StringComparer.Ordinal)
            .ToList();

        return tables;
    }

    /// <summary>
    /// Reads each table's foreign keys and returns the parent → children adjacency map plus each
    /// table's indegree (the count of distinct parents it references), the two structures the
    /// Kahn's-algorithm sort in <see cref="TopologicalSort"/> consumes.
    /// </summary>
    private static async Task<(
        Dictionary<string, SortedSet<string>> Children,
        Dictionary<string, int> Indegree)> BuildForeignKeyGraphAsync(
        DbConnection sqlite, List<string> tables, CancellationToken ct)
    {
        var known = new HashSet<string>(tables, StringComparer.OrdinalIgnoreCase);

        // parent -> children. A self-reference is dropped: it can only be satisfied within the one
        // table the single-table copy already writes as a unit.
        var children = new Dictionary<string, SortedSet<string>>(StringComparer.OrdinalIgnoreCase);
        var indegree = tables.ToDictionary(t => t, _ => 0, StringComparer.OrdinalIgnoreCase);

        foreach (string table in tables)
        {
            var parents = await LoadForeignKeyParentsAsync(sqlite, table, known, ct);
            foreach (string parent in parents)
            {
                if (!children.TryGetValue(parent, out var set))
                {
                    children[parent] = set = new SortedSet<string>(StringComparer.Ordinal);
                }

                if (set.Add(table))
                {
                    indegree[table]++;
                }
            }
        }

        return (children, indegree);
    }

    /// <summary>The distinct, known, non-self parent tables one table's foreign keys reference.</summary>
    private static async Task<List<string>> LoadForeignKeyParentsAsync(
        DbConnection sqlite, string table, HashSet<string> known, CancellationToken ct)
    {
        // The pragma_* table-valued functions declare no column types, and
        // Microsoft.Data.Sqlite surfaces those untyped columns as byte[] rather than string.
        // CAST(... AS TEXT) pins the value to text so Dapper materialises a string.
        // xtenant: catalogue introspection of the foreign-key graph; not a tenant-scoped read.
        return (await sqlite.QueryAsync<string>(
                new CommandDefinition(
                    "SELECT CAST(\"table\" AS TEXT) FROM pragma_foreign_key_list(@table)",
                    new { table },
                    cancellationToken: ct)))
            .Where(p => p is not null
                        && known.Contains(p)
                        && !string.Equals(p, table, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>
    /// Kahn's algorithm over the foreign-key graph, parents first. Ties break in ordinal name order
    /// so the plan is deterministic. Tables left unplaced when <c>ready</c> runs dry sit on a cycle;
    /// they are appended in name order and <see cref="HasCycle"/> is reported true.
    /// </summary>
    private static (List<string> Ordered, bool Cycle) TopologicalSort(
        List<string> tables,
        Dictionary<string, SortedSet<string>> children,
        Dictionary<string, int> indegree)
    {
        var ordered = new List<string>(tables.Count);
        var ready = new SortedSet<string>(
            indegree.Where(kv => kv.Value == 0).Select(kv => kv.Key),
            StringComparer.Ordinal);

        while (ready.Count > 0)
        {
            string next = ready.Min!;
            ready.Remove(next);
            ordered.Add(next);

            if (!children.TryGetValue(next, out var dependents))
            {
                continue;
            }

            foreach (string child in dependents)
            {
                if (--indegree[child] == 0)
                {
                    ready.Add(child);
                }
            }
        }

        bool cycle = ordered.Count != tables.Count;
        if (cycle)
        {
            var placed = new HashSet<string>(ordered, StringComparer.OrdinalIgnoreCase);
            ordered.AddRange(tables.Where(t => !placed.Contains(t)));
        }

        return (ordered, cycle);
    }
}
