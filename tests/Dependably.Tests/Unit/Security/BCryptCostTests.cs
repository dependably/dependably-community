using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// Enforces the BCrypt cost-factor invariant declared in encryption.md §1: every
/// password hash produced by dependably must use work factor ≥ 12. The cost is
/// hardcoded at ~10 call sites today; this test fails if any call site drifts
/// below the floor or omits the parameter (default is 11, which is below floor).
/// </summary>
[Trait("Category", "Unit")]
public sealed partial class BCryptCostTests
{
    private const int MinCostFactor = 12;

    private readonly ITestOutputHelper _output;
    public BCryptCostTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void HashPassword_with_workFactor_12_emits_hash_with_cost_12()
    {
        string hash = BCrypt.Net.BCrypt.HashPassword("correct-horse-battery-staple", workFactor: 12);
        var match = BCryptPrefixRegex().Match(hash);
        Assert.True(match.Success, $"Unexpected BCrypt hash shape: {hash}");
        Assert.Equal(12, int.Parse(match.Groups["cost"].Value));
    }

    /// <summary>
    /// Static check: every BCrypt.Net.BCrypt.HashPassword(...) call in the
    /// production source must pass workFactor: with a literal int ≥ 12. The
    /// default BCrypt.Net work factor is 11 (below our floor), so the parameter
    /// is mandatory — omitting it counts as a violation.
    /// </summary>
    [Fact]
    public void Every_HashPassword_call_site_uses_workFactor_at_least_12()
    {
        string srcRoot = LocateSourceRoot();
        Assert.True(Directory.Exists(srcRoot), $"src root not found at {srcRoot}");

        var violations = new List<string>();
        foreach (string file in Directory.EnumerateFiles(srcRoot, "*.cs", SearchOption.AllDirectories))
        {
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}") ||
                file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
            {
                continue;
            }

            string source = File.ReadAllText(file);
            foreach (Match call in HashPasswordCallRegex().Matches(source))
            {
                string args = call.Groups["args"].Value;
                int lineNumber = source[..call.Index].Count(c => c == '\n') + 1;
                string rel = Path.GetRelativePath(srcRoot, file);

                var workFactor = WorkFactorRegex().Match(args);
                if (!workFactor.Success)
                {
                    violations.Add($"{rel}:{lineNumber} — HashPassword call missing explicit workFactor:");
                    continue;
                }

                int cost = int.Parse(workFactor.Groups["cost"].Value);
                if (cost < MinCostFactor)
                {
                    violations.Add($"{rel}:{lineNumber} — workFactor: {cost} is below floor {MinCostFactor}");
                }
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} BCrypt.HashPassword call(s) violate the cost floor. " +
                        $"encryption.md §1 mandates workFactor ≥ {MinCostFactor}.");
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

    [GeneratedRegex(@"^\$2[aby]\$(?<cost>\d{2})\$")]
    private static partial Regex BCryptPrefixRegex();

    // Matches BCrypt.Net.BCrypt.HashPassword(<args up to the matching close paren>).
    // Captures `args` non-greedily; relies on argument lists not containing nested
    // parens in this codebase (verified at write time).
    [GeneratedRegex(@"BCrypt\.Net\.BCrypt\.HashPassword\((?<args>[^)]*)\)", RegexOptions.Singleline)]
    private static partial Regex HashPasswordCallRegex();

    [GeneratedRegex(@"workFactor\s*:\s*(?<cost>\d+)")]
    private static partial Regex WorkFactorRegex();
}
