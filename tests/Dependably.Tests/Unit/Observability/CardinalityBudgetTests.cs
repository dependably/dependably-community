using System.Runtime.CompilerServices;
using Xunit;

namespace Dependably.Tests.Unit.Observability;

/// <summary>
/// Enforces the cardinality budget documented in
/// <c>dependably-enterprise/docs/observability/metrics.md#cardinality-budget</c>:
/// no metric instrument carries an attribute named <c>tenant_id</c>,
/// <c>org_id</c>, <c>user_id</c>, <c>email</c>, <c>purl</c>, <c>sha256</c>,
/// or <c>ip_address</c>.
///
/// Detection is a source-text scan for the OTel tagging idiom
/// <c>new KeyValuePair&lt;string, object?&gt;("&lt;banned&gt;", …)</c>. Tenant
/// attribution belongs on spans and log records, where high cardinality is
/// cheap. Putting it on metrics blows up the TSDB working set.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CardinalityBudgetTests
{
    private static readonly string[] Banned =
    {
        "tenant_id",
        "org_id",
        "user_id",
        "email",
        "purl",
        "sha256",
        "ip_address",
    };

    [Fact]
    public void NoBannedAttributeNamesOnMetricInstruments()
    {
        var srcDir = GetSourceDir();
        Assert.True(Directory.Exists(srcDir), $"Source directory not found: {srcDir}");

        var violations = new List<string>();

        foreach (var file in Directory.EnumerateFiles(srcDir, "*.cs", SearchOption.AllDirectories))
        {
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
                continue;
            if (file.EndsWith(".g.cs", StringComparison.Ordinal) || file.EndsWith(".AssemblyInfo.cs", StringComparison.Ordinal))
                continue;

            var lines = File.ReadAllLines(file);
            for (var i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                foreach (var bad in Banned)
                {
                    var pattern = $"KeyValuePair<string, object?>(\"{bad}\"";
                    if (line.Contains(pattern, StringComparison.Ordinal))
                    {
                        var rel = Path.GetRelativePath(srcDir, file);
                        violations.Add($"{rel}:{i + 1}  uses banned metric attribute \"{bad}\"");
                    }
                }
            }
        }

        Assert.True(
            violations.Count == 0,
            "Metric cardinality-budget violation. Tenant attribution belongs on " +
            "spans / logs, not on metrics. See " +
            "dependably-enterprise/docs/observability/metrics.md#cardinality-budget.\n  " +
            string.Join("\n  ", violations));
    }

    private static string GetSourceDir([CallerFilePath] string callerFilePath = "")
    {
        var dir = Path.GetDirectoryName(callerFilePath)!;
        var repoRoot = Path.GetFullPath(Path.Combine(dir, "..", "..", "..", ".."));
        return Path.Combine(repoRoot, "src", "Dependably");
    }
}
