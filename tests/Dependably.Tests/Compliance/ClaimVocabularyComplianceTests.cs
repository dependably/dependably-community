using System.Text.RegularExpressions;
using Dependably.Infrastructure;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// The claims admin API accepts creates only for ecosystems whose data paths actually consult
/// <see cref="ClaimResolver"/> — a claim on an ecosystem nothing reads is a silent no-op that
/// reads as a security control. This gate pins <see cref="ClaimEcosystems.Enforced"/> to the set
/// of ecosystems that appear as a string-literal argument at a real <see cref="ClaimResolver"/>
/// call site in <c>src/</c>, so the vocabulary cannot drift away from the enforcement points
/// (the exact failure mode this test was added to close: cargo enforced but unclaimable;
/// maven/rpm/oci claimable but unconsulted).
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class ClaimVocabularyComplianceTests
{
    private readonly ITestOutputHelper _output;

    public ClaimVocabularyComplianceTests(ITestOutputHelper output) => _output = output;

    // Matches `claimResolver.IsProxyFetchAllowedAsync(orgId, "npm", …)` and the other two claim
    // resolver entry points on any receiver whose identifier ends in "laimResolver" (covers both
    // the `claimResolver` primary-ctor param and the `_claimResolver` field), capturing the
    // ecosystem literal (always the second positional argument, after the org id).
    [GeneratedRegex(@"\w*laimResolver\.(?:IsProxyFetchAllowedAsync|CanPublishAsync|ResolveAsync)\(\s*[^,]+,\s*""(?<eco>[a-z]+)""")]
    private static partial Regex ClaimResolverCallRegex();

    [Fact]
    public void EnforcedVocabularyMatchesClaimResolverCallSites()
    {
        string srcRoot = LocateSourceRoot();
        Assert.True(Directory.Exists(srcRoot), $"src root not found at {srcRoot}");

        var callSiteEcosystems = new HashSet<string>(StringComparer.Ordinal);
        foreach (string file in Directory.EnumerateFiles(srcRoot, "*.cs", SearchOption.AllDirectories))
        {
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                || file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
            {
                continue;
            }

            string source = File.ReadAllText(file);
            foreach (Match m in ClaimResolverCallRegex().Matches(source))
            {
                callSiteEcosystems.Add(m.Groups["eco"].Value);
            }
        }

        Assert.NotEmpty(callSiteEcosystems);

        var enforced = new HashSet<string>(ClaimEcosystems.Enforced, StringComparer.Ordinal);

        var missingFromVocab = callSiteEcosystems.Except(enforced).OrderBy(x => x).ToList();
        var unconsulted = enforced.Except(callSiteEcosystems).OrderBy(x => x).ToList();

        foreach (string e in missingFromVocab)
        {
            _output.WriteLine($"'{e}' consults ClaimResolver but is not in ClaimEcosystems.Enforced (unclaimable).");
        }
        foreach (string e in unconsulted)
        {
            _output.WriteLine($"'{e}' is in ClaimEcosystems.Enforced but no ClaimResolver call site references it (silent no-op).");
        }

        Assert.True(
            missingFromVocab.Count == 0 && unconsulted.Count == 0,
            "ClaimEcosystems.Enforced drifted from the ClaimResolver call sites. See test output.");
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
