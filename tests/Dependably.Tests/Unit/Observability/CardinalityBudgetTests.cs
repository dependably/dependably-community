using System.Runtime.CompilerServices;

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
        string srcDir = GetSourceDir();
        Assert.True(Directory.Exists(srcDir), $"Source directory not found: {srcDir}");

        var violations = new List<string>();

        foreach (string file in Directory.EnumerateFiles(srcDir, "*.cs", SearchOption.AllDirectories))
        {
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            {
                continue;
            }

            if (file.EndsWith(".g.cs", StringComparison.Ordinal) || file.EndsWith(".AssemblyInfo.cs", StringComparison.Ordinal))
            {
                continue;
            }

            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i];
                foreach (string bad in Banned)
                {
                    string pattern = $"KeyValuePair<string, object?>(\"{bad}\"";
                    if (line.Contains(pattern, StringComparison.Ordinal))
                    {
                        string rel = Path.GetRelativePath(srcDir, file);
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

    // ── bounded reason vocabulary on upstream_url_blocks ─────────────────────

    private static readonly string[] AllowedUrlBlockReasons =
    {
        "blocked_range",
        "redirect_to_internal",
        "dns_rebind",
        "dns_failure",
    };

    /// <summary>
    /// Scans <c>src/Dependably</c> for every <c>UpstreamUrlBlocks.Add(</c> call that
    /// carries a <c>"reason"</c> literal, and asserts that each literal belongs to the
    /// bounded vocabulary <c>{blocked_range|redirect_to_internal|dns_rebind|dns_failure}</c>.
    /// Prevents new callers from inventing ad-hoc reason strings that blow up the metric
    /// cardinality or drift from the documented label set.
    /// </summary>
    [Fact]
    public void UpstreamUrlBlocksReasonAttribute_MustBeWithinBoundedVocabulary()
    {
        string srcDir = GetSourceDir();
        Assert.True(Directory.Exists(srcDir), $"Source directory not found: {srcDir}");

        var violations = new List<string>();

        foreach (string file in Directory.EnumerateFiles(srcDir, "*.cs", SearchOption.AllDirectories))
        {
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            {
                continue;
            }

            if (file.EndsWith(".g.cs", StringComparison.Ordinal) || file.EndsWith(".AssemblyInfo.cs", StringComparison.Ordinal))
            {
                continue;
            }

            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i];
                if (!line.Contains("UpstreamUrlBlocks.Add(", StringComparison.Ordinal))
                {
                    continue;
                }

                // Extract the reason literal from `"reason", "<value>"` on the same line.
                int reasonIdx = line.IndexOf("\"reason\", \"", StringComparison.Ordinal);
                if (reasonIdx < 0)
                {
                    continue;
                }

                int valueStart = reasonIdx + "\"reason\", \"".Length;
                int valueEnd = line.IndexOf('"', valueStart);
                if (valueEnd < 0)
                {
                    continue;
                }

                string reason = line[valueStart..valueEnd];
                if (!Array.Exists(AllowedUrlBlockReasons, r => r == reason))
                {
                    string rel = Path.GetRelativePath(srcDir, file);
                    violations.Add(
                        $"{rel}:{i + 1}  reason \"{reason}\" is not in the bounded vocabulary " +
                        $"({string.Join("|", AllowedUrlBlockReasons)})");
                }
            }
        }

        Assert.True(
            violations.Count == 0,
            "UpstreamUrlBlocks reason attribute out of bounded vocabulary. " +
            "Add the new reason to AllowedUrlBlockReasons in CardinalityBudgetTests " +
            "and update the instrument description in DependablyMeter.\n  " +
            string.Join("\n  ", violations));
    }

    private static string GetSourceDir([CallerFilePath] string callerFilePath = "")
    {
        string dir = Path.GetDirectoryName(callerFilePath)!;
        string repoRoot = Path.GetFullPath(Path.Combine(dir, "..", "..", "..", ".."));
        return Path.Combine(repoRoot, "src", "Dependably");
    }
}
