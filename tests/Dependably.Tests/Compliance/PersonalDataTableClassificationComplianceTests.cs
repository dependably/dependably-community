using Dependably.Infrastructure;
using Dependably.Infrastructure.Privacy;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: every table in <c>Schema.sql</c> that declares a personal-data-shaped column
/// (<c>user_id</c>, <c>actor_id</c>, <c>created_by</c>, <c>decided_by</c>, <c>email</c>,
/// <c>email_hash</c>, <c>email_snapshot</c>, <c>nameid</c>, <c>source_ip</c>, <c>user_agent</c>)
/// must be classified in <see cref="PersonalDataTables"/> as either exported to the data subject
/// (<see cref="PersonalDataTables.Included"/>) or deliberately excluded with a reason
/// (<see cref="PersonalDataTables.ExcludedWithReason"/>).
///
/// <para>
/// This is the durable half of the GDPR Art. 15/20 data-subject-export work: it converts the
/// personal-data inventory from a document that silently rots into a build gate, so a new schema
/// table carrying user-identifying data cannot ship without a conscious "is this the subject's
/// personal data?" decision. It is the same static-scan shape as
/// <see cref="OrgIdFilteringComplianceTests"/> and <see cref="BlobKeyConstructionComplianceTests"/>,
/// and — like those — carries a scanner self-test so the gate cannot go green-but-blind.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed class PersonalDataTableClassificationComplianceTests
{
    private readonly ITestOutputHelper _output;
    public PersonalDataTableClassificationComplianceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void EverySchemaTableWithAPersonalDataColumn_IsClassified()
    {
        var flagged = SchemaTablesWithPersonalDataColumns();

        // Green-but-blind guard: the parser returning nothing (or the column set being emptied)
        // would make this gate vacuous. Pin a floor well below the real count.
        Assert.True(flagged.Count >= 15,
            $"only {flagged.Count} personal-data-shaped tables found — the schema parser or the " +
            "column set likely regressed, which would make this gate vacuous.");

        var unclassified = flagged.Keys
            .Where(t => !PersonalDataTables.Included.Contains(t)
                        && !PersonalDataTables.ExcludedWithReason.ContainsKey(t))
            .OrderBy(t => t, StringComparer.Ordinal)
            .ToList();

        if (unclassified.Count > 0)
        {
            foreach (string t in unclassified)
            {
                _output.WriteLine(
                    $"{t}: declares personal-data column(s) [{string.Join(", ", flagged[t])}] but is " +
                    "absent from PersonalDataTables. Add it to Included (and project it in " +
                    "PersonalDataExportRepository) or to ExcludedWithReason with a reason.");
            }

            Assert.Fail(
                $"{unclassified.Count} schema table(s) carry personal data but are unclassified: " +
                $"{string.Join(", ", unclassified)}. See test output.");
        }
    }

    /// <summary>Every excluded reason is non-empty — an empty reason defeats the point of the gate.</summary>
    [Fact]
    public void ExcludedTables_AllCarryANonEmptyReason()
    {
        var empty = PersonalDataTables.ExcludedWithReason
            .Where(kv => string.IsNullOrWhiteSpace(kv.Value))
            .Select(kv => kv.Key)
            .ToList();

        Assert.True(empty.Count == 0, $"excluded tables with an empty reason: {string.Join(", ", empty)}");
    }

    /// <summary>A table is never simultaneously exported and excluded.</summary>
    [Fact]
    public void Included_And_Excluded_DoNotOverlap()
    {
        var overlap = PersonalDataTables.Included
            .Where(PersonalDataTables.ExcludedWithReason.ContainsKey)
            .ToList();

        Assert.True(overlap.Count == 0, $"tables classified as BOTH included and excluded: {string.Join(", ", overlap)}");
    }

    /// <summary>
    /// Neither classification list names a table that no longer exists in the schema — a dropped or
    /// renamed table would otherwise leave a dead entry protecting nothing.
    /// </summary>
    [Fact]
    public void ClassifiedTables_AllExistInTheSchema()
    {
        string schema = File.ReadAllText(SchemaTestPaths.SqliteSchema(SchemaTestPaths.SourceRoot()));
        var known = new HashSet<string>(SchemaSqlParser.CreatedTableNames(schema), StringComparer.OrdinalIgnoreCase);

        var missing = PersonalDataTables.Included
            .Concat(PersonalDataTables.ExcludedWithReason.Keys)
            .Where(t => !known.Contains(t))
            .OrderBy(t => t, StringComparer.Ordinal)
            .ToList();

        Assert.True(missing.Count == 0, $"classified table(s) that no longer exist in Schema.sql: {string.Join(", ", missing)}");
    }

    /// <summary>
    /// Anchors: the eleven tables the export must cover are all present in <see cref="PersonalDataTables.Included"/>.
    /// Named explicitly so dropping one from the export fails here with a readable reason rather than
    /// thinning the set silently.
    /// </summary>
    [Fact]
    public void Included_CoversTheKnownSubjectDataTables()
    {
        foreach (string table in new[]
                 {
                     "users", "user_tokens", "password_reset_tokens", "external_identities",
                     "mfa_trusted_devices", "banner_dismissals", "invites", "audit_log",
                     "activity", "audit_event", "login_attempts",
                 })
        {
            Assert.Contains(table, PersonalDataTables.Included);
        }
    }

    // ── In-schema annotations ──────────────────────────────────────────────────

    /// <summary>
    /// Every classified table carries a <c>-- personal-data: included|excluded — reason</c>
    /// annotation directly above its <c>CREATE TABLE</c> in BOTH schema files, and the annotated
    /// classification agrees with <see cref="PersonalDataTables"/>.
    ///
    /// <para>
    /// The C# classification is what the export and erasure code actually reads; the annotation is
    /// what someone reading the DDL sees. Without this gate the two drift silently and the schema
    /// starts lying — worse than carrying no annotation at all, because a reader has no way to tell
    /// a stale annotation from a current one. The reason text is deliberately NOT compared: it is
    /// prose that should be free to be phrased for its audience, and pinning it would turn every
    /// wording improvement into a two-file edit for no safety gain.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EveryClassifiedTable_CarriesAMatchingAnnotationInBothSchemaFiles(bool postgres)
    {
        string root = SchemaTestPaths.SourceRoot();
        string path = postgres ? SchemaTestPaths.PostgresSchema(root) : SchemaTestPaths.SqliteSchema(root);
        var annotations = AnnotatedClassifications(File.ReadAllText(path));

        var problems = new List<string>();
        foreach (string table in PersonalDataTables.Included)
        {
            problems.AddRange(AnnotationProblems(annotations, table, "included"));
        }

        foreach (string table in PersonalDataTables.ExcludedWithReason.Keys)
        {
            problems.AddRange(AnnotationProblems(annotations, table, "excluded"));
        }

        // An annotation on a table that is not classified at all is equally a drift signal: it
        // asserts a decision the code does not hold.
        foreach ((string table, string classification) in annotations)
        {
            if (!PersonalDataTables.Included.Contains(table)
                && !PersonalDataTables.ExcludedWithReason.ContainsKey(table))
            {
                problems.Add(
                    $"{table}: annotated '{classification}' in {Path.GetFileName(path)} but absent from PersonalDataTables.");
            }
        }

        if (problems.Count > 0)
        {
            foreach (string problem in problems)
            {
                _output.WriteLine(problem);
            }

            Assert.Fail($"{problems.Count} personal-data annotation problem(s) in {Path.GetFileName(path)}. See test output.");
        }
    }

    private static IEnumerable<string> AnnotationProblems(
        Dictionary<string, string> annotations, string table, string expected)
    {
        if (!annotations.TryGetValue(table, out string? actual))
        {
            yield return $"{table}: classified '{expected}' in PersonalDataTables but carries no "
                + "'-- personal-data:' annotation above its CREATE TABLE.";
        }
        else if (!string.Equals(actual, expected, StringComparison.Ordinal))
        {
            yield return $"{table}: annotated '{actual}' but classified '{expected}' in PersonalDataTables.";
        }
    }

    /// <summary>
    /// Self-test for the annotation parser: it must read the classification, tolerate the reason
    /// text, and ignore a marker that is not directly above the table it would otherwise annotate.
    /// </summary>
    [Theory]
    [InlineData("-- personal-data: included — because\nCREATE TABLE IF NOT EXISTS t (id TEXT);", "included")]
    [InlineData("-- personal-data: excluded — because\nCREATE TABLE IF NOT EXISTS t (id TEXT);", "excluded")]
    // Not adjacent: an unrelated statement intervenes, so `t` reads as unannotated.
    [InlineData("-- personal-data: included — because\nCREATE INDEX i ON x (y);\nCREATE TABLE IF NOT EXISTS t (id TEXT);", null)]
    [InlineData("-- just a comment\nCREATE TABLE IF NOT EXISTS t (id TEXT);", null)]
    public void AnnotationParser_ReadsTheClassificationDirectlyAboveTheTable(string ddl, string? expected)
    {
        var annotations = AnnotatedClassifications(ddl);
        annotations.TryGetValue("t", out string? actual);
        Assert.Equal(expected, actual);
    }

    /// <summary>
    /// Maps each table whose <c>CREATE TABLE</c> is immediately preceded by a
    /// <c>-- personal-data: …</c> line → the classification word on that line.
    /// </summary>
    private static Dictionary<string, string> AnnotatedClassifications(string sql)
    {
        const string marker = "-- personal-data:";
        const string createPrefix = "CREATE TABLE IF NOT EXISTS ";

        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string[] lines = sql.Replace("\r\n", "\n").Split('\n');
        for (int i = 1; i < lines.Length; i++)
        {
            string line = lines[i].TrimStart();
            if (!line.StartsWith(createPrefix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string previous = lines[i - 1].TrimStart();
            if (!previous.StartsWith(marker, StringComparison.Ordinal))
            {
                continue;
            }

            string table = line[createPrefix.Length..].Split('(')[0].Trim();
            result[table] = previous[marker.Length..].TrimStart().Split(' ')[0].Trim();
        }

        return result;
    }

    /// <summary>
    /// Scanner self-test. Proves the gate actually reacts to (a) a new personal-data table and
    /// (b) the exact-name column matcher, so a future refactor cannot quietly reopen the hole or
    /// start flagging config columns that merely contain "email".
    /// </summary>
    [Theory]
    // A table declaring an exact personal-data column is flagged.
    [InlineData("CREATE TABLE new_pii (id TEXT PRIMARY KEY, user_id TEXT, note TEXT);", "new_pii", true)]
    [InlineData("CREATE TABLE t (id TEXT PRIMARY KEY, source_ip TEXT);", "t", true)]
    [InlineData("CREATE TABLE t (id TEXT PRIMARY KEY, email TEXT);", "t", true)]
    // Config/delivery columns that merely contain a personal-data token are NOT flagged.
    [InlineData("CREATE TABLE t (id TEXT PRIMARY KEY, email_status TEXT, email_smtp_username TEXT);", "t", false)]
    [InlineData("CREATE TABLE t (id TEXT PRIMARY KEY, name_id_format TEXT, email_attribute TEXT);", "t", false)]
    [InlineData("CREATE TABLE t (id TEXT PRIMARY KEY, name TEXT, created_at TEXT);", "t", false)]
    public void Scanner_FlagsExactPersonalDataColumns_Only(string ddl, string table, bool expectFlagged)
    {
        var flagged = TablesWithPersonalDataColumns(ddl);
        Assert.Equal(expectFlagged, flagged.ContainsKey(table));
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static Dictionary<string, List<string>> SchemaTablesWithPersonalDataColumns()
    {
        string schema = File.ReadAllText(SchemaTestPaths.SqliteSchema(SchemaTestPaths.SourceRoot()));
        return TablesWithPersonalDataColumns(schema);
    }

    /// <summary>Maps each table declaring ≥1 exact personal-data column → those column names.</summary>
    private static Dictionary<string, List<string>> TablesWithPersonalDataColumns(string sql)
    {
        var result = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (table, columns) in SchemaSqlParser.ParseTables(sql))
        {
            var personal = columns
                .Where(c => PersonalDataTables.PersonalDataColumns.Contains(c))
                .ToList();
            if (personal.Count > 0)
            {
                result[table] = personal;
            }
        }

        return result;
    }
}
