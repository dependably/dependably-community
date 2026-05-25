using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Xunit;

namespace Dependably.Tests.Unit.Observability;

/// <summary>
/// Enforces the closed outcome vocabulary documented in
/// <c>dependably-enterprise/docs/observability/taxonomy.md#outcome-vocabulary</c>.
/// Scans source for the two emission idioms — attribute tagging
/// (<c>KeyValuePair&lt;string, object?&gt;("outcome", "value")</c>) and
/// local-variable assignment (<c>outcome = "value"</c>) — and fails the
/// build on any value not in the documented enum.
///
/// New outcome value? Add it to <c>taxonomy.md</c> and to <see cref="Allowed"/>.
/// </summary>
[Trait("Category", "Unit")]
public sealed partial class OutcomeValueTests
{
    private static readonly HashSet<string> Allowed = new(StringComparer.Ordinal)
    {
        // Lifecycle (most operations)
        "success", "client_error", "server_error", "upstream_error", "blocked", "cancelled",
        // Cache-result (dependably.cache.lookups only)
        "hit", "miss",
        // Auth-resolution (dependably.token_auth.requests only)
        "no_auth", "invalid",
    };

    // Matches: ("outcome", "value")  or  ("dependably.outcome", "value")
    [GeneratedRegex(@"""(?:dependably\.)?outcome""\s*,\s*""([^""]+)""")]
    private static partial Regex AttributePattern();

    // Matches: outcome = "value"  (local-variable assignment that flows to emission)
    // Note: the leading non-letter prevents matching `_outcome` field assignments
    // which are private state, not emission values.
    [GeneratedRegex(@"(?<![A-Za-z_])outcome\s*=\s*""([^""]+)""")]
    private static partial Regex AssignmentPattern();

    [Fact]
    public void NoOutcomeValueOutsideClosedEnum()
    {
        var srcDir = GetSourceDir();
        Assert.True(Directory.Exists(srcDir), $"Source directory not found: {srcDir}");

        var violations = new List<string>();

        foreach (var file in Directory.EnumerateFiles(srcDir, "*.cs", SearchOption.AllDirectories))
        {
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
                continue;

            var content = File.ReadAllText(file);

            foreach (var pattern in new[] { AttributePattern(), AssignmentPattern() })
            {
                foreach (Match m in pattern.Matches(content))
                {
                    var value = m.Groups[1].Value;
                    if (Allowed.Contains(value)) continue;

                    var line = content.AsSpan(0, m.Index).Count('\n') + 1;
                    var rel = Path.GetRelativePath(srcDir, file);
                    violations.Add($"{rel}:{line}  outcome value \"{value}\" not in the closed enum");
                }
            }
        }

        Assert.True(
            violations.Count == 0,
            "Outcome-vocabulary violation. See taxonomy.md#outcome-vocabulary.\n  " +
            string.Join("\n  ", violations));
    }

    private static string GetSourceDir([CallerFilePath] string callerFilePath = "")
    {
        var dir = Path.GetDirectoryName(callerFilePath)!;
        var repoRoot = Path.GetFullPath(Path.Combine(dir, "..", "..", "..", ".."));
        return Path.Combine(repoRoot, "src", "Dependably");
    }
}
