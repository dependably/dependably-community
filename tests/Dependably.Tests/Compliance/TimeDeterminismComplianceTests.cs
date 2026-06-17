using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: production code never reads the wall clock directly. All "now" reads go
/// through the DI-registered <see cref="TimeProvider"/> (ctor-injected; static helpers take
/// the timestamp as a parameter). Direct wall-clock reads make time-window logic, generated
/// content (ETags, checksum sidecars), and the tests that exercise them nondeterministic —
/// results change across second/midnight/year boundaries and leap days.
///
/// Banned tokens: the static now/today properties of the BCL date types (UTC and local
/// forms; the local forms are additionally wrong for a UTC-everywhere server).
///
/// Opt-out: a deliberate wall-clock read annotates with <c>// now-ok: &lt;reason&gt;</c> on
/// the same line or within the 5 lines above (the same window as <c>// rawsql:</c> /
/// <c>// xtenant:</c>).
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class TimeDeterminismComplianceTests
{
    private readonly ITestOutputHelper _output;
    public TimeDeterminismComplianceTests(ITestOutputHelper output) => _output = output;

    // The optional group between the type name and the member keeps this pattern from
    // matching its own source text.
    [GeneratedRegex(@"\bDateTime(Offset)?\s*\.\s*(UtcNow|Now|Today)\b", RegexOptions.None)]
    private static partial Regex WallClockRegex();

    [Fact]
    public void SrcUsesInjectedTimeProvider()
    {
        string repoRoot = LocateRepoRoot();
        Assert.False(string.IsNullOrEmpty(repoRoot), "repo root not found");

        var violations = ScanTree(Path.Combine(repoRoot, "src", "Dependably"), repoRoot);

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} direct wall-clock read(s) in src. Inject TimeProvider " +
                        "(or take the timestamp as a parameter in static helpers); a deliberate " +
                        "wall-clock read needs `// now-ok: <reason>`. See test output for the list.");
        }
    }

    [Fact]
    public void TestsUseFakeTimeProvider()
    {
        string repoRoot = LocateRepoRoot();
        Assert.False(string.IsNullOrEmpty(repoRoot), "repo root not found");

        var violations = ScanTree(Path.Combine(repoRoot, "tests"), repoRoot);

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} direct wall-clock read(s) in tests. Use a frozen " +
                        "FakeTimeProvider / TestTime.KnownNow (fixed instants make assertions exact " +
                        "and immune to second/midnight/leap-day boundaries); a deliberate real-clock " +
                        "read (e.g. a polling deadline awaiting actual async completion) needs " +
                        "`// now-ok: <reason>`. See test output for the list.");
        }
    }

    private List<string> ScanTree(string root, string repoRoot)
    {
        var violations = new List<string>();
        foreach (string file in EnumerateSource(root))
        {
            // The scanner's own file documents the banned tokens.
            if (Path.GetFileName(file) == nameof(TimeDeterminismComplianceTests) + ".cs")
            {
                continue;
            }

            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                // Comment-only lines can name the APIs (docs, examples) without reading them.
                if (lines[i].TrimStart().StartsWith("//"))
                {
                    continue;
                }

                if (WallClockRegex().IsMatch(lines[i]) && !HasNowOk(lines, i))
                {
                    violations.Add(
                        $"{Path.GetRelativePath(repoRoot, file)}:{i + 1}: direct wall-clock read — " +
                        $"use the injected TimeProvider or annotate `// now-ok: <reason>`. {lines[i].Trim()}");
                }
            }
        }

        return violations;
    }

    // The marker may sit on the flagged line or within the 5 lines above it (matching the
    // rawsql/xtenant opt-out window, since expressions often span wrapped lines).
    private static bool HasNowOk(string[] lines, int lineIndex)
    {
        for (int probe = Math.Max(0, lineIndex - 5); probe <= lineIndex && probe < lines.Length; probe++)
        {
            if (lines[probe].Contains("now-ok:", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static IEnumerable<string> EnumerateSource(string root)
    {
        foreach (string file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
        {
            string p = file.Replace('\\', '/');
            if (p.Contains("/obj/") || p.Contains("/bin/"))
            {
                continue;
            }

            yield return file;
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
}
