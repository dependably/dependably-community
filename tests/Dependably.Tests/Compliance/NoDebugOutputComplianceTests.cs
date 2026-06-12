using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: production code uses Serilog, not raw console/debug output, and ships no
/// unimplemented stubs. <c>Console.Write*</c> / <c>Debug.Write*</c> are debug-print slop that
/// bypasses structured logging; <c>throw new NotImplementedException()</c> is a stub that
/// compiled but does nothing — both are classic AI artifacts that pass the build silently.
///
/// One legitimate console writer is allowlisted: <see cref="Dependably.Infrastructure.FirstBootService"/>
/// prints the generated admin credentials to stdout exactly once on first boot, by design
/// (they are shown once and never logged). New console output is a violation; if another such
/// deliberate case arises, add the file to <see cref="ConsoleOutputAllowed"/> with a comment.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class NoDebugOutputComplianceTests
{
    private readonly ITestOutputHelper _output;
    public NoDebugOutputComplianceTests(ITestOutputHelper output) => _output = output;

    // Files permitted to write directly to the console, with the reason.
    private static readonly HashSet<string> ConsoleOutputAllowed = new(StringComparer.Ordinal)
    {
        // First-boot admin credential banner: printed once to stdout, deliberately never logged.
        "FirstBootService.cs",
    };

    [GeneratedRegex(@"\bConsole\.(Write|WriteLine|Error|Out)\b|\bDebug\.(Write|WriteLine)\b")]
    private static partial Regex ConsoleOrDebugRegex();

    [GeneratedRegex(@"\bnew\s+NotImplementedException\b")]
    private static partial Regex NotImplementedRegex();

    [Fact]
    public void NoConsoleOrDebugOutputOrUnimplementedStubs()
    {
        string srcRoot = LocateSourceRoot();
        Assert.True(Directory.Exists(srcRoot), $"src root not found at {srcRoot}");

        var violations = new List<string>();
        foreach (string file in Directory.EnumerateFiles(srcRoot, "*.cs", SearchOption.AllDirectories))
        {
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                || file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
            {
                continue;
            }

            string fileName = Path.GetFileName(file);
            bool consoleAllowed = ConsoleOutputAllowed.Contains(fileName);
            string[] lines = File.ReadAllLines(file);

            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i];
                string rel = Path.GetRelativePath(srcRoot, file);

                if (!consoleAllowed && ConsoleOrDebugRegex().IsMatch(line))
                {
                    violations.Add($"{rel}:{i + 1}: Console/Debug output — use the Serilog logger instead. {line.Trim()}");
                }

                if (NotImplementedRegex().IsMatch(line))
                {
                    violations.Add($"{rel}:{i + 1}: NotImplementedException stub — implement it or remove the code path. {line.Trim()}");
                }
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} debug-output / unimplemented-stub violation(s) found. " +
                        $"See test output for the full list.");
        }
    }

    private static string LocateSourceRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string candidate = Path.Combine(dir.FullName, "src", "Dependably");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            dir = dir.Parent;
        }
        return string.Empty;
    }
}
