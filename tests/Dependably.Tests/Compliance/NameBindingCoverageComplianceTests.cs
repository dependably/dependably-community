using System.Text.RegularExpressions;
using Dependably.Infrastructure;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Name-level publish authorization must reach every ecosystem that has a hosted push surface —
/// including maven, rpm, and oci, the three the supply-chain review found had no name-level
/// defence of any kind. This gate pins <see cref="NameBindingEcosystems.Enforced"/> to that full
/// set, and additionally proves the three bespoke publish paths (which do not route through the
/// shared <c>PackagePublishService</c>) actually consult <see cref="Security.NameBindingGate"/> —
/// so the vocabulary cannot claim coverage the code does not deliver.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class NameBindingCoverageComplianceTests
{
    private readonly ITestOutputHelper _output;
    public NameBindingCoverageComplianceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void EnforcedSet_CoversEveryHostedPushEcosystem()
    {
        foreach (string eco in new[] { "npm", "pypi", "nuget", "maven", "rpm", "oci", "cargo" })
        {
            Assert.Contains(eco, NameBindingEcosystems.Enforced);
        }
    }

    [Fact]
    public void MavenRpmOci_HaveNameLevelDefence()
    {
        // The three ecosystems called out as having no name-level defence must now be enforced.
        foreach (string eco in new[] { "maven", "rpm", "oci" })
        {
            Assert.Contains(eco, NameBindingEcosystems.Enforced);
        }
    }

    // Matches `<recv>.IsPublishAuthorizedAsync(orgId, "maven", …)` on any receiver, capturing the
    // ecosystem literal (the second positional argument, after the org id) — the same shape the
    // ClaimVocabulary gate uses for the claim resolver.
    [GeneratedRegex(@"\.IsPublishAuthorizedAsync\(\s*[^,]+,\s*""(?<eco>[a-z]+)""")]
    private static partial Regex GateCallRegex();

    [Fact]
    public void BespokePublishPaths_ConsultTheGateWithLiteralEcosystem()
    {
        var callSiteEcosystems = new HashSet<string>(StringComparer.Ordinal);
        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            foreach (Match m in GateCallRegex().Matches(File.ReadAllText(file)))
            {
                callSiteEcosystems.Add(m.Groups["eco"].Value);
            }
        }

        // The Maven, RPM, and OCI controllers write the registry tier directly (outside the shared
        // publish service) and pass a literal ecosystem to the gate. Each must be present, or that
        // ecosystem's hosted push is unguarded.
        foreach (string eco in new[] { "maven", "rpm", "oci" })
        {
            if (!callSiteEcosystems.Contains(eco))
            {
                _output.WriteLine($"'{eco}' has no NameBindingGate.IsPublishAuthorizedAsync call site — its hosted push is unguarded.");
            }

            Assert.Contains(eco, callSiteEcosystems);
        }
    }
}
