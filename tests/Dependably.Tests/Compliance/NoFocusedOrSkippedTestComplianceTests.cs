using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: no committed test is focused or skipped. A single focused test silently
/// disables the rest of the suite; a stray skip silently drops coverage — both pass CI green
/// while testing far less than they appear to. This is a classic AI/dev slop pattern that a
/// deterministic scan kills outright.
///
/// Covers both ecosystems:
///   • JS/TS (vitest, Playwright): <c>describe.only</c>, <c>it.only</c>, <c>test.only</c>,
///     <c>fit(</c>, <c>fdescribe(</c>, and <c>.skip</c> / <c>xit</c> / <c>xdescribe</c>.
///   • C# (xUnit): <c>[Fact(Skip = …)]</c> / <c>[Theory(Skip = …)]</c>.
///
/// Opt-out: a genuinely-needed skip annotates the same line with <c>// skip-ok: &lt;reason&gt;</c>.
/// There is no opt-out for focus markers — a focused test must never be committed.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class NoFocusedOrSkippedTestComplianceTests
{
    private readonly ITestOutputHelper _output;
    public NoFocusedOrSkippedTestComplianceTests(ITestOutputHelper output) => _output = output;

    // Focus markers (never allowed). \b anchors avoid matching e.g. "monitor.only" property access
    // is unlikely in test files, but the dot-form keeps it to the test idioms.
    [GeneratedRegex(@"\b(describe|it|test)\.only\b|\bfit\s*\(|\bfdescribe\s*\(", RegexOptions.None)]
    private static partial Regex JsFocusRegex();

    // Skip markers (allowed only with // skip-ok:).
    [GeneratedRegex(@"\b(describe|it|test)\.skip\b|\bxit\s*\(|\bxdescribe\s*\(", RegexOptions.None)]
    private static partial Regex JsSkipRegex();

    [GeneratedRegex(@"\[(?:Fact|Theory)\s*\([^)]*\bSkip\s*=", RegexOptions.None)]
    private static partial Regex CsharpSkipRegex();

    [Fact]
    public void NoTestIsFocusedOrSkipped()
    {
        string repoRoot = LocateRepoRoot();
        Assert.False(string.IsNullOrEmpty(repoRoot), "repo root not found");

        var violations = new List<string>();

        // --- JS/TS test files under web/ ---
        string webRoot = Path.Combine(repoRoot, "web");
        if (Directory.Exists(webRoot))
        {
            foreach (string file in EnumerateSource(webRoot, ".js", ".ts", ".svelte"))
            {
                string name = Path.GetFileName(file);
                bool isTest = name.Contains(".test.") || name.Contains(".spec.")
                          || file.Replace('\\', '/').Contains("/e2e/");
                if (!isTest)
                {
                    continue;
                }

                string[] lines = File.ReadAllLines(file);
                for (int i = 0; i < lines.Length; i++)
                {
                    if (JsFocusRegex().IsMatch(lines[i]))
                    {
                        violations.Add($"{Rel(repoRoot, file)}:{i + 1}: focused test (.only/fit/fdescribe) — remove it. {Trim(lines[i])}");
                    }

                    if (JsSkipRegex().IsMatch(lines[i]) && !HasSkipOk(lines, i))
                    {
                        violations.Add($"{Rel(repoRoot, file)}:{i + 1}: skipped test — remove it or annotate `// skip-ok: <reason>`. {Trim(lines[i])}");
                    }
                }
            }
        }

        // --- C# test files under tests/ ---
        string testsRoot = Path.Combine(repoRoot, "tests");
        if (Directory.Exists(testsRoot))
        {
            foreach (string file in EnumerateSource(testsRoot, ".cs"))
            {
                if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                    || file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
                {
                    continue;
                }

                string[] lines = File.ReadAllLines(file);
                for (int i = 0; i < lines.Length; i++)
                {
                    // Only real attribute lines (trimmed start '['), so an XML doc-comment that
                    // merely mentions [Fact(Skip = …)] as documentation is not flagged.
                    if (!lines[i].TrimStart().StartsWith('['))
                    {
                        continue;
                    }

                    if (CsharpSkipRegex().IsMatch(lines[i]) && !HasSkipOk(lines, i))
                    {
                        violations.Add($"{Rel(repoRoot, file)}:{i + 1}: skipped xUnit test — remove the Skip or annotate `// skip-ok: <reason>`. {Trim(lines[i])}");
                    }
                }
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} focused/skipped test(s) found. See test output for the full list.");
        }
    }

    // The marker may sit on the skip line itself or the line immediately above it.
    private static bool HasSkipOk(string[] lines, int i)
        => lines[i].Contains("skip-ok:", StringComparison.OrdinalIgnoreCase)
            || (i > 0 && lines[i - 1].Contains("skip-ok:", StringComparison.OrdinalIgnoreCase));

    private static IEnumerable<string> EnumerateSource(string root, params string[] extensions)
    {
        foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            string p = file.Replace('\\', '/');
            if (p.Contains("/node_modules/") || p.Contains("/dist/") || p.Contains("/coverage/")
                || p.Contains("/playwright-report/") || p.Contains("/test-results/"))
            {
                continue;
            }

            if (extensions.Any(e => file.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
            {
                yield return file;
            }
        }
    }

    private static string LocateRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "src", "Dependably")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }
        return string.Empty;
    }

    private static string Rel(string root, string file) => Path.GetRelativePath(root, file);
    private static string Trim(string s) => s.Trim();
}
