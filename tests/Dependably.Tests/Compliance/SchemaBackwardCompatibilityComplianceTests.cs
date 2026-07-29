using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// The blue-green gate. Blue (the previous release) and green (this build) run against one database
/// for the whole cutover window, so <c>Schema.sql</c> / <c>Schema.pg.sql</c> must stay backward
/// compatible with the previous release: no table or column may vanish, no <c>CHECK</c> value set
/// may shrink, and no column may become <c>NOT NULL</c> without a <c>DEFAULT</c>.
///
/// <para>The previous release's schema is read out of git at its release tag
/// (<see cref="SchemaBaselineResolver"/>), which works under a shallow CI checkout because the tag
/// is fetched explicitly rather than assumed present.</para>
///
/// <para>The deliberate contract step of an expand/migrate/contract sequence — release N+2 dropping
/// what release N+1 stopped reading — is waived per object with a
/// <c>backcompat-ok: &lt;table&gt;[.&lt;column&gt;] — &lt;reason&gt;</c> comment in a schema file or in
/// <c>SchemaInitializer</c>, alongside the <c>DROP</c> it authorises.</para>
///
/// <para>A repository with no release tag at all has nothing to be compatible with and passes. A
/// repository that HAS release tags but whose baseline could not be read is a broken signal, not a
/// pass: set <c>SCHEMA_BACKCOMPAT_REQUIRE_BASELINE=true</c> (as the CI schema job does) to fail on
/// it rather than let the gate quietly stop checking.</para>
/// </summary>
[Trait("Category", "Schema")]
public sealed class SchemaBackwardCompatibilityComplianceTests
{
    private const string RequireBaselineVariable = "SCHEMA_BACKCOMPAT_REQUIRE_BASELINE";

    private readonly ITestOutputHelper _output;
    public SchemaBackwardCompatibilityComplianceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void CurrentSchema_IsBackwardCompatibleWithThePreviousRelease()
    {
        var resolution = SchemaBaselineResolver.Resolve();
        _output.WriteLine(resolution.Log);

        if (resolution.Baseline is null)
        {
            AssertMissingBaselineIsTolerable(resolution);
            return;
        }

        var waivers = LoadWaivers();
        foreach (string declared in waivers.Declared)
        {
            _output.WriteLine($"waived: {declared}");
        }

        string src = SchemaTestPaths.SourceRoot();
        var violations = new List<string>();
        violations.AddRange(SchemaBackwardCompatibility.Analyze(
            "Schema.sql", resolution.Baseline.SqliteSql,
            File.ReadAllText(SchemaTestPaths.SqliteSchema(src)), waivers));
        violations.AddRange(SchemaBackwardCompatibility.Analyze(
            "Schema.pg.sql", resolution.Baseline.PostgresSql,
            File.ReadAllText(SchemaTestPaths.PostgresSchema(src)), waivers));

        if (violations.Count == 0)
        {
            return;
        }

        foreach (string v in violations)
        {
            _output.WriteLine(v);
        }

        Assert.Fail(
            $"{violations.Count} change(s) incompatible with release {resolution.Baseline.Tag}. "
            + "Sequence the change as expand/migrate/contract, or — if this IS the contract step and "
            + "the previous release no longer reads the object — waive it with a "
            + "`backcompat-ok: <table>[.<column>] — <reason>` comment. See test output for the full list.");
    }

    [Fact]
    public void EveryBackCompatWaiver_NamesAnObjectAndGivesAReason()
    {
        var waivers = LoadWaivers();
        foreach (string malformed in waivers.Malformed)
        {
            _output.WriteLine(malformed);
        }

        Assert.True(
            waivers.Malformed.Count == 0,
            $"{waivers.Malformed.Count} backcompat-ok marker(s) name an object but no reason. The reason is "
            + "what makes the waived drop reviewable. See test output.");
    }

    // Markers live where the change they authorise lives: the schema files, or the SchemaInitializer
    // partial that carries the RunOnceAsync drop.
    private static BackCompatWaivers LoadWaivers() => BackCompatWaivers.FromSourceTree();

    private static void AssertMissingBaselineIsTolerable(BaselineResolution resolution)
    {
        bool required = string.Equals(
            Environment.GetEnvironmentVariable(RequireBaselineVariable), "true", StringComparison.OrdinalIgnoreCase);

        Assert.True(
            SchemaBaselineResolver.IsTolerable(resolution, required),
            $"{RequireBaselineVariable} is set, but the previous release's schema could not be "
            + $"resolved ({resolution.Absence}) — the blue-green gate compared nothing. Only a "
            + "repository that has genuinely never had a release passes this way. See test output "
            + "for the resolution log.");
    }
}
