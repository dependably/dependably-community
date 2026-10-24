using System.Text.RegularExpressions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Every test source that takes <c>TEST_POSTGRES_CONNECTION</c> and runs schema- or
/// database-level destructive DDL against it passes the connection through
/// <c>DisposableTestDatabaseGuard.EnsureDisposable</c> first. The guard is what stops a connection
/// string copied from a real deployment from having its <c>public</c> schema dropped; a new fixture
/// that reads the variable and issues its own <c>DROP DATABASE</c> would bypass it silently.
///
/// <para>Tests that reach the server through <c>LivePostgresReset.FreshAsync</c> or
/// <c>PostgresTestDatabase</c> are covered by those two harnesses and contain no such DDL
/// themselves. The scan matches text in non-comment lines only: DDL assembled from fragments, or a
/// guard reached through a differently named helper, is invisible to it.</para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class LivePostgresGuardComplianceTests
{
    private const string SelfFileName = "LivePostgresGuardComplianceTests.cs";
    private const string GuardFileName = "DisposableTestDatabaseGuard.cs";
    private const string GuardCall = "DisposableTestDatabaseGuard.EnsureDisposable(";
    private static readonly string ConnectionVariable = "TEST_POSTGRES" + "_CONNECTION";

    [GeneratedRegex(@"\b(DROP\s+SCHEMA|DROP\s+DATABASE|CREATE\s+DATABASE)\b", RegexOptions.IgnoreCase)]
    private static partial Regex DestructiveDdl();

    // The harness paths that exist today; the scan must keep finding them or it has gone blind.
    private static readonly string[] KnownDestructiveHarnesses =
    [
        "LivePostgresReset.cs",
        "PostgresTestDatabase.cs",
        "RowLevelSecurityPostgresTests.cs",
    ];

    [Fact]
    public void EveryDestructiveLivePostgresPath_CallsTheGuard()
    {
        var destructive = new List<string>();
        var violations = new List<string>();
        foreach (string file in TestSourceFiles())
        {
            string text = File.ReadAllText(file);
            if (!text.Contains(ConnectionVariable, StringComparison.Ordinal))
            {
                continue;
            }

            var code = text.Split('\n').Where(l => !l.TrimStart().StartsWith("//", StringComparison.Ordinal));
            if (!code.Any(l => DestructiveDdl().IsMatch(l)))
            {
                continue;
            }

            destructive.Add(Path.GetFileName(file));
            if (!text.Contains(GuardCall, StringComparison.Ordinal))
            {
                violations.Add(Path.GetRelativePath(SourceRoots.RepoRoot(), file));
            }
        }

        Assert.Empty(violations);
        foreach (string known in KnownDestructiveHarnesses)
        {
            Assert.Contains(known, destructive);
        }
    }

    private static IEnumerable<string> TestSourceFiles() =>
        Directory.EnumerateFiles(Path.Combine(SourceRoots.RepoRoot(), "tests"), "*.cs", SearchOption.AllDirectories)
            .Where(f => Path.GetFileName(f) is not SelfFileName and not GuardFileName)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal));
}
