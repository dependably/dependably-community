using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Pins the diff semantics of <see cref="SchemaBackwardCompatibility"/> — the engine behind
/// <see cref="SchemaBackwardCompatibilityComplianceTests"/> — against hand-written before/after DDL
/// pairs. The gate itself can only ever exercise whatever the current release happens to change, so
/// each blue-green hazard (and each safe change that must NOT be reported) is proven here.
/// </summary>
[Trait("Category", "Schema")]
public sealed partial class SchemaBackwardCompatibilityAnalyzerTests
{
    private readonly ITestOutputHelper _output;
    public SchemaBackwardCompatibilityAnalyzerTests(ITestOutputHelper output) => _output = output;

    private const string Before = """
        CREATE TABLE IF NOT EXISTS packages (
            id          TEXT PRIMARY KEY,
            org_id      TEXT NOT NULL,
            description TEXT,
            keep_days   INTEGER,
            state       TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active','archived','deleting')),
            mode        TEXT CHECK (mode IS NULL OR mode IN ('passthrough','merged'))
        );
        CREATE TABLE IF NOT EXISTS legacy_counters (
            id          TEXT PRIMARY KEY,
            total       INTEGER NOT NULL DEFAULT 0
        );
        """;

    private static List<string> Analyze(string after, params string[] waivedObjects) =>
        SchemaBackwardCompatibility.Analyze("Schema.sql", Before, after, Waivers(waivedObjects));

    private static BackCompatWaivers Waivers(params string[] objects)
    {
        string file = Path.Combine(Path.GetTempPath(), $"backcompat-waivers-{Guid.NewGuid():N}.sql");
        File.WriteAllLines(file, objects.Select(o => $"-- backcompat-ok: {o} — deliberate contract step"));
        try
        {
            return BackCompatWaivers.FromFiles([file]);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void UnchangedSchema_HasNoViolations() => Assert.Empty(Analyze(Before));

    [Fact]
    public void DroppedTable_IsReported()
    {
        string after = Before.Replace("CREATE TABLE IF NOT EXISTS legacy_counters", "CREATE TABLE IF NOT EXISTS other_counters", StringComparison.Ordinal);
        string violation = Assert.Single(Analyze(after), v => v.Contains("table `legacy_counters`", StringComparison.Ordinal));
        Assert.Contains("removed here", violation, StringComparison.Ordinal);
    }

    [Fact]
    public void DroppedColumn_IsReported()
    {
        string after = Before.Replace("keep_days   INTEGER,", string.Empty, StringComparison.Ordinal);
        Assert.Single(Analyze(after), v => v.Contains("column `packages.keep_days`", StringComparison.Ordinal));
    }

    [Fact]
    public void DroppedColumn_IsSilencedByItsWaiver()
    {
        string after = Before.Replace("keep_days   INTEGER,", string.Empty, StringComparison.Ordinal);
        Assert.Empty(Analyze(after, "packages.keep_days"));
    }

    [Fact]
    public void DroppedTable_IsSilencedByItsWaiver()
    {
        string after = Before.Replace("CREATE TABLE IF NOT EXISTS legacy_counters", "CREATE TABLE IF NOT EXISTS other_counters", StringComparison.Ordinal);
        Assert.Empty(Analyze(after, "legacy_counters"));
    }

    [Fact]
    public void ColumnWaiver_DoesNotSilenceADifferentColumn()
    {
        string after = Before.Replace("keep_days   INTEGER,", string.Empty, StringComparison.Ordinal);
        Assert.Single(Analyze(after, "packages.description"));
    }

    [Fact]
    public void RenamedColumn_IsReportedAsARemoval()
    {
        // A one-step rename is exactly a drop plus an add: the add is invisible to blue, the drop is not.
        string after = Before.Replace("description TEXT,", "summary TEXT,", StringComparison.Ordinal);
        Assert.Single(Analyze(after), v => v.Contains("column `packages.description`", StringComparison.Ordinal));
    }

    [Fact]
    public void NarrowedCheck_IsReported()
    {
        string after = Before.Replace("IN ('active','archived','deleting')", "IN ('active','archived')", StringComparison.Ordinal);
        string violation = Assert.Single(Analyze(after));
        Assert.Contains("CHECK on `packages.state` no longer allows 'deleting'", violation, StringComparison.Ordinal);
    }

    [Fact]
    public void NarrowedCheck_IsSilencedByItsWaiver()
    {
        string after = Before.Replace("IN ('active','archived','deleting')", "IN ('active','archived')", StringComparison.Ordinal);
        Assert.Empty(Analyze(after, "packages.state"));
    }

    [Fact]
    public void WidenedCheck_IsNotReported()
    {
        string after = Before.Replace("IN ('active','archived','deleting')", "IN ('active','archived','deleting','held')", StringComparison.Ordinal);
        Assert.Empty(Analyze(after));
    }

    [Fact]
    public void DroppedCheck_IsNotReported()
    {
        // Removing the constraint entirely accepts everything blue writes — a widening, not a narrowing.
        string after = Before.Replace(" CHECK (state IN ('active','archived','deleting'))", string.Empty, StringComparison.Ordinal);
        Assert.Empty(Analyze(after));
    }

    [Fact]
    public void CheckNarrowedOnANullableColumn_IsReportedThroughTheIsNullGuard()
    {
        string after = Before.Replace("mode IN ('passthrough','merged')", "mode IN ('merged')", StringComparison.Ordinal);
        Assert.Single(Analyze(after), v => v.Contains("CHECK on `packages.mode` no longer allows 'passthrough'", StringComparison.Ordinal));
    }

    [Fact]
    public void ColumnMadeNotNullWithoutDefault_IsReported()
    {
        string after = Before.Replace("description TEXT,", "description TEXT NOT NULL,", StringComparison.Ordinal);
        string violation = Assert.Single(Analyze(after));
        Assert.Contains("`packages.description` becomes NOT NULL without a DEFAULT", violation, StringComparison.Ordinal);
    }

    [Fact]
    public void NotNullColumnLosingItsDefault_IsReported()
    {
        // Same cutover failure as a new NOT NULL: blue omits the column and the INSERT is rejected.
        string after = Before.Replace("state       TEXT NOT NULL DEFAULT 'active'", "state       TEXT NOT NULL", StringComparison.Ordinal);
        string violation = Assert.Single(Analyze(after));
        Assert.Contains("`packages.state` is NOT NULL and loses its DEFAULT", violation, StringComparison.Ordinal);
    }

    [Fact]
    public void NotNullColumnLosingItsDefault_IsSilencedByItsWaiver()
    {
        string after = Before.Replace("state       TEXT NOT NULL DEFAULT 'active'", "state       TEXT NOT NULL", StringComparison.Ordinal);
        Assert.Empty(Analyze(after, "packages.state"));
    }

    [Fact]
    public void NullableColumnLosingItsDefault_IsNotReported()
    {
        // Still omittable: the column simply defaults to NULL instead of the old literal.
        const string before = "CREATE TABLE IF NOT EXISTS t (id TEXT PRIMARY KEY, hits INTEGER DEFAULT 0);";
        const string after = "CREATE TABLE IF NOT EXISTS t (id TEXT PRIMARY KEY, hits INTEGER);";
        Assert.Empty(SchemaBackwardCompatibility.Analyze("Schema.sql", before, after, Waivers()));
    }

    [Fact]
    public void ColumnThatWasAlreadyNotNullWithoutADefault_IsNotReported()
    {
        // Nothing changed for blue: it could never omit the column in the first place.
        string after = Before.Replace("org_id      TEXT NOT NULL,", "org_id      VARCHAR(64) NOT NULL,", StringComparison.Ordinal);
        Assert.Empty(Analyze(after));
    }

    [Fact]
    public void ColumnMadeNotNullWithDefault_IsNotReported()
    {
        string after = Before.Replace("description TEXT,", "description TEXT NOT NULL DEFAULT '',", StringComparison.Ordinal);
        Assert.Empty(Analyze(after));
    }

    [Fact]
    public void NotNullInsideACheckExpression_IsNotMistakenForColumnNullability()
    {
        string after = Before.Replace(
            "mode        TEXT CHECK (mode IS NULL OR mode IN ('passthrough','merged'))",
            "mode        TEXT CHECK (mode IS NOT NULL OR mode IN ('passthrough','merged'))",
            StringComparison.Ordinal);
        Assert.Empty(Analyze(after));
    }

    [Fact]
    public void AddedTableAndColumn_AreNotReported()
    {
        string after = Before
            .Replace("description TEXT,", "description TEXT,\n    homepage    TEXT,", StringComparison.Ordinal)
            + "\nCREATE TABLE IF NOT EXISTS new_thing (id TEXT PRIMARY KEY);";
        Assert.Empty(Analyze(after));
    }

    [Fact]
    public void RelaxedNullability_IsNotReported()
    {
        string after = Before.Replace("org_id      TEXT NOT NULL,", "org_id      TEXT,", StringComparison.Ordinal);
        Assert.Empty(Analyze(after));
    }

    [Fact]
    public void MarkerWithoutAReason_IsRejectedRatherThanHonoured()
    {
        string file = Path.Combine(Path.GetTempPath(), $"backcompat-waivers-{Guid.NewGuid():N}.sql");
        File.WriteAllText(file, "-- backcompat-ok: packages.keep_days\n");
        try
        {
            var waivers = BackCompatWaivers.FromFiles([file]);
            Assert.False(waivers.Covers("packages.keep_days"));
            Assert.Single(waivers.Malformed);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void NewGlobCheckOnExistingColumn_IsReported()
    {
        // A GLOB pattern yields no literal value set, so the value-set comparison sees nothing on
        // either side. The clause is still a constraint the previous release never ran against.
        string after = Before.Replace(
            "description TEXT,", "description TEXT CHECK (description GLOB '[A-Za-z]*'),", StringComparison.Ordinal);
        string violation = Assert.Single(Analyze(after));
        Assert.Contains("CHECK on `packages.description` added or changed", violation, StringComparison.Ordinal);
    }

    [Fact]
    public void NewRegexCheckOnExistingColumn_IsReported()
    {
        string after = Before.Replace(
            "description TEXT,", @"description TEXT CHECK (description ~ '^\w+$'),", StringComparison.Ordinal);
        string violation = Assert.Single(Analyze(after));
        Assert.Contains("CHECK on `packages.description` added or changed", violation, StringComparison.Ordinal);
    }

    [Fact]
    public void ChangedGlobCheck_IsReported()
    {
        // Both sides carry a GLOB. Whether the new pattern accepts everything the old one did is not
        // decidable by inspection, so any textual change is reported and the reviewer rules on it.
        const string before = "CREATE TABLE IF NOT EXISTS t (id TEXT PRIMARY KEY, code TEXT CHECK (code GLOB '[A-Z][A-Z]*'));";
        const string after = "CREATE TABLE IF NOT EXISTS t (id TEXT PRIMARY KEY, code TEXT CHECK (code GLOB '[A-Z][A-Z][A-Z]*'));";
        string violation = Assert.Single(
            SchemaBackwardCompatibility.Analyze("Schema.sql", before, after, Waivers()));
        Assert.Contains("CHECK on `t.code` added or changed", violation, StringComparison.Ordinal);
    }

    [Fact]
    public void NewInListCheckOnPreviouslyUnconstrainedColumn_IsReported()
    {
        // An unconstrained column's domain is unbounded, so a first value list is a narrowing of it:
        // whatever the previous release writes into `description` today that is not in the list is
        // newly rejected. "No constraint before" is not the same as "nothing newly rejected".
        string after = Before.Replace(
            "description TEXT,", "description TEXT CHECK (description IN ('short','long')),", StringComparison.Ordinal);
        string violation = Assert.Single(Analyze(after));
        Assert.Contains("CHECK on `packages.description` added or changed", violation, StringComparison.Ordinal);
    }

    [Fact]
    public void NewGlobCheckOnExistingColumn_IsSilencedByItsWaiver()
    {
        string after = Before.Replace(
            "description TEXT,", "description TEXT CHECK (description GLOB '[A-Za-z]*'),", StringComparison.Ordinal);
        Assert.Empty(Analyze(after, "packages.description"));
    }

    [Fact]
    public void WidenedInListCheck_NeedsNoWaiverEvenThoughItsClauseTextChanged()
    {
        // The routine "widen a CHECK enum" workflow must not acquire waiver busywork: the clause
        // text necessarily changes, and the value-set reader proves the change accepts strictly more.
        string after = Before.Replace(
            "IN ('active','archived','deleting')", "IN ('active','archived','deleting','held')", StringComparison.Ordinal);
        Assert.Empty(Analyze(after));
        Assert.NotEqual(Before, after);
    }

    [Fact]
    public void CheckOnOneColumn_IsNotAttributedToAnotherWhoseNameItContains()
    {
        // The attribution match is `\bname\b`, and `_` is a word character — so the boundary never
        // falls inside a snake_case identifier. Constraining `org_id` says nothing about `id`.
        string after = Before.Replace(
            "org_id      TEXT NOT NULL,", "org_id      TEXT NOT NULL CHECK (org_id GLOB '[0-9a-f]*'),", StringComparison.Ordinal);
        string violation = Assert.Single(Analyze(after));
        Assert.Contains("CHECK on `packages.org_id` added or changed", violation, StringComparison.Ordinal);
        Assert.DoesNotContain("`packages.id`", violation, StringComparison.Ordinal);
    }

    [Fact]
    public void MultiColumnCheck_IsAttributedToEveryColumnItNames()
    {
        // Conservative by design: the waiver vocabulary is `table.column`, so a clause spanning two
        // columns needs a marker for each. Over-requiring a marker is the safe direction.
        const string before = "CREATE TABLE IF NOT EXISTS t (id TEXT PRIMARY KEY, starts_at TEXT, ends_at TEXT);";
        const string after = "CREATE TABLE IF NOT EXISTS t (id TEXT PRIMARY KEY, starts_at TEXT, ends_at TEXT, CHECK (ends_at > starts_at));";
        var violations = SchemaBackwardCompatibility.Analyze("Schema.sql", before, after, Waivers());
        Assert.Equal(2, violations.Count);
        Assert.Single(SchemaBackwardCompatibility.Analyze("Schema.sql", before, after, Waivers("t.starts_at")));
        Assert.Empty(SchemaBackwardCompatibility.Analyze("Schema.sql", before, after, Waivers("t.starts_at", "t.ends_at")));
    }

    [Fact]
    public void TableLevelCheckConstraint_IsComparedLikeAColumnLevelOne()
    {
        const string before = """
            CREATE TABLE IF NOT EXISTS metadata (
                id          TEXT PRIMARY KEY,
                owner_kind  TEXT NOT NULL,
                CHECK (owner_kind IN ('package_version','cache_artifact'))
            );
            """;
        const string after = """
            CREATE TABLE IF NOT EXISTS metadata (
                id          TEXT PRIMARY KEY,
                owner_kind  TEXT NOT NULL,
                CHECK (owner_kind IN ('package_version'))
            );
            """;
        string violation = Assert.Single(
            SchemaBackwardCompatibility.Analyze("Schema.sql", before, after, Waivers()));
        Assert.Contains("'cache_artifact'", violation, StringComparison.Ordinal);
    }

    // ---- the same engine against the real previous release, not a hand-written pair ----

    [GeneratedRegex(@"CHECK on `(?<object>\w+\.\w+)` added or changed")]
    private static partial Regex ChangedCheckObjectRegex();

    /// <summary>
    /// The waivers declared in the source tree account for the whole real diff. This is the
    /// backfill's completeness proof: a marker that is missing, misspelled, or missing its reason
    /// leaves a violation standing here.
    /// </summary>
    [Fact]
    public void AgainstTheRealPreviousRelease_TheDeclaredWaiversLeaveNothingStanding()
    {
        if (RealDiff(BackCompatWaivers.FromSourceTree()) is not { } violations)
        {
            return;
        }

        foreach (string v in violations)
        {
            _output.WriteLine(v);
        }

        Assert.Empty(violations);
    }

    /// <summary>
    /// The other half of the proof: strip the waivers and the same comparison reports the changes.
    /// Without this, "zero violations" above would be indistinguishable from an analyzer that sees
    /// nothing — which is exactly what the value-set-only comparison did with these constraints.
    /// </summary>
    [Fact]
    public void AgainstTheRealPreviousRelease_StrippingTheWaiversRevealsTheChangedChecks()
    {
        var resolution = SchemaBaselineResolver.Resolve();
        if (RealDiff(BackCompatWaivers.FromFiles([])) is not { } violations || resolution.Baseline is null)
        {
            return;
        }

        // Self-retiring precondition: once the baseline release also declares the canonical-UTC
        // shape CHECK, these clauses are no longer new relative to it, there is nothing left to
        // report, and the waiver markers become dead weight to delete.
        if (!resolution.Baseline.SqliteSql.Contains("GLOB '[0-9][0-9][0-9][0-9]-", StringComparison.Ordinal))
        {
            Assert.NotEmpty(violations);

            var objects = violations.Select(v => ChangedCheckObjectRegex().Match(v))
                .Where(m => m.Success).Select(m => m.Groups["object"].Value).ToList();

            Assert.Equal(violations.Count, objects.Count);
            _output.WriteLine($"{objects.Count} unwaived change(s) across {objects.Distinct(StringComparer.Ordinal).Count()} object(s)");

            // Both provider files carry the same declarations, so each object is reported twice —
            // once per file. An object reported once means the two schemas have drifted apart.
            Assert.Equal(objects.Count, objects.Distinct(StringComparer.Ordinal).Count() * 2);

            var waivers = BackCompatWaivers.FromSourceTree();
            Assert.All(objects, o => Assert.True(waivers.Covers(o), $"no backcompat-ok marker declares {o}"));
        }
    }

    // Both provider files diffed against the previous release, or null when no baseline resolved —
    // an offline checkout or a source export has nothing to compare against, exactly as the gate
    // itself tolerates.
    private List<string>? RealDiff(BackCompatWaivers waivers)
    {
        var resolution = SchemaBaselineResolver.Resolve();
        if (resolution.Baseline is null)
        {
            _output.WriteLine(resolution.Log);
            return null;
        }

        string src = SchemaTestPaths.SourceRoot();
        return
        [
            .. SchemaBackwardCompatibility.Analyze(
                "Schema.sql", resolution.Baseline.SqliteSql,
                File.ReadAllText(SchemaTestPaths.SqliteSchema(src)), waivers),
            .. SchemaBackwardCompatibility.Analyze(
                "Schema.pg.sql", resolution.Baseline.PostgresSql,
                File.ReadAllText(SchemaTestPaths.PostgresSchema(src)), waivers),
        ];
    }
}
