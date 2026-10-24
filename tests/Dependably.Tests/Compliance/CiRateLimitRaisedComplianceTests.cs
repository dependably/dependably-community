using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Every <c>*_RATE_LIMIT_PERMITS</c> key the app reads must be raised in the <c>.app_boot</c>
/// anchor of <c>.gitlab-ci.yml</c>, which boots the app every DAST job scans. A limiter left at
/// its default lets a 429 land between a scanner's true/false probe pair, which ZAP's boolean
/// SQL injection rule reads as injection: a gating job then fails nondeterministically. A key
/// that is deliberately not raised is listed in <see cref="NotRaised"/> with the reason.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class CiRateLimitRaisedComplianceTests
{
    [GeneratedRegex(@"""([A-Z][A-Z0-9_]*_RATE_LIMIT_PERMITS)""")]
    private static partial Regex KeyRegex();

    [GeneratedRegex(@"^\s*export\s+([A-Z][A-Z0-9_]*_RATE_LIMIT_PERMITS)=", RegexOptions.Multiline)]
    private static partial Regex ExportRegex();

    private static readonly Dictionary<string, string> NotRaised = new(StringComparer.Ordinal)
    {
        ["TENANT_RATE_LIMIT_PERMITS"] = "per-org protocol budget, off when unset",
        ["TENANT_THROTTLED_RATE_LIMIT_PERMITS"] = "applies only under a downloads_throttled usage posture",
    };

    private readonly ITestOutputHelper _output;
    public CiRateLimitRaisedComplianceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void EveryRateLimitPermitsKeyIsRaisedInAppBoot()
    {
        var keys = KeysReadBySource();

        Assert.NotEmpty(keys);
        Assert.Contains("OCI_SCAN_RATE_LIMIT_PERMITS", keys);
        Assert.Contains("SECRETS_VERIFY_RATE_LIMIT_PERMITS", keys);

        string ci = File.ReadAllText(Path.Combine(SourceRoots.RepoRoot(), ".gitlab-ci.yml"));
        var raised = ExportRegex().Matches(AppBootBlock(ci))
            .Select(m => m.Groups[1].Value)
            .ToHashSet(StringComparer.Ordinal);

        var missing = keys.Where(k => !raised.Contains(k) && !NotRaised.ContainsKey(k)).ToList();
        foreach (string k in missing)
        {
            _output.WriteLine($"{k} is read by the app but not exported in .app_boot");
        }

        Assert.True(missing.Count == 0,
            "Rate-limit keys missing from .app_boot in .gitlab-ci.yml (add `export KEY=100000`, " +
            "or list the key in NotRaised with a reason): " + string.Join(", ", missing));
    }

    [Fact]
    public void NotRaisedEntriesAreStillReadByTheApp()
    {
        var keys = KeysReadBySource();
        foreach (string key in NotRaised.Keys)
        {
            Assert.Contains(key, keys);
        }
    }

    private static SortedSet<string> KeysReadBySource()
    {
        var keys = new SortedSet<string>(StringComparer.Ordinal);
        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            foreach (Match m in KeyRegex().Matches(File.ReadAllText(file)))
            {
                keys.Add(m.Groups[1].Value);
            }
        }

        return keys;
    }

    // The anchor's value is an indented literal block: it runs until the next line that starts
    // in column 0.
    private static string AppBootBlock(string ci)
    {
        int start = ci.IndexOf(".app_boot: &app_boot |", StringComparison.Ordinal);
        Assert.True(start >= 0, ".app_boot anchor not found in .gitlab-ci.yml");

        string[] lines = ci[start..].Split('\n');
        int count = 1;
        while (count < lines.Length && (lines[count].Length == 0 || lines[count][0] is ' ' or '\t'))
        {
            count++;
        }

        return string.Join('\n', lines.Take(count));
    }
}
