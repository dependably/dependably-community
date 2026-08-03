namespace Dependably.Tests.Compliance;

/// <summary>Locates the live source tree (not embedded resources) so the static schema checks can
/// read both provider files regardless of which one the running provider would load. The one
/// shared <c>Infrastructure/schema/</c> directory and the <c>SchemaInitializer.cs</c> migration
/// source live in exactly one source root; each is discovered across <see cref="SourceRoots.All"/>
/// so the schema gates survive the assembly split, and an accidental second copy fails loudly.
///
/// Path discovery is the half of the old parser file that is genuinely test-only: it walks the
/// checkout. The parsing half is production code (<c>Dependably.Infrastructure.SchemaSqlParser</c>),
/// shared with the canonical-timestamp CHECK retrofit so the gates and the retrofit read the schema
/// through one implementation.</summary>
internal static class SchemaTestPaths
{
    /// <summary>
    /// The source root owning the schema DDL. <see cref="SourceRoot"/> preserves the historical
    /// call shape (the gates combine it with the relative schema/initializer paths below), while
    /// resolving to whichever root actually holds <c>Infrastructure/schema/</c>.
    /// </summary>
    public static string SourceRoot() => SchemaDirOwningRoot();

    // The single root that contains Infrastructure/schema/. Exactly one must — a future duplicate
    // schema directory across roots is a correctness hazard and fails here rather than silently.
    private static string SchemaDirOwningRoot() => SingleOwningRoot(
        root => Directory.Exists(Path.Combine(root, "Infrastructure", "schema")),
        "Infrastructure/schema/");

    // The single root that contains the SchemaInitializer migration source.
    private static string SchemaInitializerOwningRoot() => SingleOwningRoot(
        root => File.Exists(Path.Combine(root, "Infrastructure", "SchemaInitializer.cs")),
        "Infrastructure/SchemaInitializer.cs");

    private static string SingleOwningRoot(Func<string, bool> predicate, string what)
    {
        var matches = SourceRoots.All().Where(predicate).ToList();
        return matches.Count switch
        {
            1 => matches[0],
            0 => throw new DirectoryNotFoundException(
                $"No source root under src/ contains {what}."),
            _ => throw new InvalidOperationException(
                $"{matches.Count} source roots contain {what} (expected exactly one): "
                + string.Join(", ", matches)),
        };
    }

    // SchemaInitializer is a partial class split across SchemaInitializer.cs and its
    // SchemaInitializer.*.cs companions (e.g. .ColumnMigrations.cs, .OwnerPlane.cs, .Reshapes.cs)
    // — the additive-migration array can live in any of them, so callers must scan every file.
    public static IReadOnlyList<string> SchemaInitializerFiles() =>
        Directory.GetFiles(
            Path.Combine(SchemaInitializerOwningRoot(), "Infrastructure"),
            "SchemaInitializer*.cs");

    public static string SqliteSchema(string srcRoot) => Path.Combine(srcRoot, "Infrastructure", "schema", "Schema.sql");
    public static string PostgresSchema(string srcRoot) => Path.Combine(srcRoot, "Infrastructure", "schema", "Schema.pg.sql");
}
