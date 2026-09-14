using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: every ecosystem key that carries a per-ecosystem upload limit
/// (<see cref="Dependably.Infrastructure.OrgRepository.GetUploadLimitAsync"/>, the switch
/// <see cref="Dependably.Protocol.IUploadLimitResolver"/> resolves against) has a matching prefix
/// entry in <c>EcosystemPathResolver</c> (the shared table <c>UploadSizeLimitMiddleware</c> and
/// the rate-limit denial audit wiring both key ecosystem off of). Without the entry the
/// Kestrel-level pre-body guard never fires for that ecosystem's push route: the framework
/// accepts and streams the whole body before the app-level counter trips, so the layered cap
/// degrades from a 413-before-a-byte-is-read to a post-buffer refusal. Cargo publish regressed
/// exactly this way (<c>PUT /cargo/api/v1/crates/new</c> had a limit tier but no path arm), and
/// before the two callers shared one table, the mapping had already drifted on <c>/go</c>,
/// <c>/apk</c>, and <c>/terraform</c> between them.
///
/// The check is deliberately one-directional: a limit-bearing ecosystem MUST have a path entry;
/// a path entry without a limit tier is fine (a future ecosystem can be routed before it grows an
/// override). Ecosystems with no hosted push path (go, apk) carry no limit tier, so they are not
/// required here — the moment one grows an upload limit in the tier switch, this gate demands the
/// corresponding path entry.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class UploadLimitEcosystemCoverageComplianceTests
{
    private readonly ITestOutputHelper _output;
    public UploadLimitEcosystemCoverageComplianceTests(ITestOutputHelper output) => _output = output;

    // "pypi" => settings?.MaxUploadBytesPyPi,  — the org-ecosystem tier switch keys.
    [GeneratedRegex(@"""(?<eco>[a-z]+)""\s*=>\s*settings\?\.MaxUploadBytes", RegexOptions.Singleline)]
    private static partial Regex TierSwitchKeyRegex();

    // ("/pypi", "pypi"),  — capture each prefix entry's ecosystem result.
    [GeneratedRegex(@"\(\s*""(?<prefix>/[^""]*)""\s*,\s*""(?<eco>[a-z0-9]+)""\s*\)", RegexOptions.Singleline)]
    private static partial Regex PathPrefixEntryRegex();

    [Fact]
    public void EveryUploadLimitEcosystemHasAPathArm()
    {
        string resolverSource = ReadSourceFile("OrgRepository.cs");
        string ecosystemResolverSource = ReadSourceFile("EcosystemPathResolver.cs");

        // The limit-bearing ecosystem keys: the org-ecosystem tier switch in GetUploadLimitAsync.
        var limitEcosystems = TierSwitchKeyRegex().Matches(resolverSource)
            .Select(m => m.Groups["eco"].Value)
            .ToHashSet(StringComparer.Ordinal);

        Assert.True(limitEcosystems.Count >= 5,
            $"Expected to parse the upload-limit tier switch in OrgRepository.GetUploadLimitAsync; " +
            $"found only [{string.Join(", ", limitEcosystems)}]. Did the switch shape change?");

        // The ecosystem ids EcosystemPathResolver.ForPath can return.
        var routedEcosystems = PathPrefixEntryRegex().Matches(ecosystemResolverSource)
            .Select(m => m.Groups["eco"].Value)
            .ToHashSet(StringComparer.Ordinal);

        Assert.Contains("cargo", routedEcosystems); // guards the specific regression the gate exists for

        var missing = limitEcosystems.Where(e => !routedEcosystems.Contains(e)).OrderBy(e => e).ToList();
        if (missing.Count > 0)
        {
            _output.WriteLine($"Limit-bearing ecosystems parsed:  {string.Join(", ", limitEcosystems.OrderBy(x => x))}");
            _output.WriteLine($"EcosystemPathResolver entries parsed: {string.Join(", ", routedEcosystems.OrderBy(x => x))}");
            Assert.Fail(
                $"{missing.Count} ecosystem(s) have a per-ecosystem upload limit but no path prefix " +
                $"entry in EcosystemPathResolver: [{string.Join(", ", missing)}]. Add a " +
                $"(\"/<prefix>\", \"<eco>\") entry so the pre-body 413 guard fires before Kestrel " +
                $"streams the push body.");
        }
    }

    private static string ReadSourceFile(string fileName)
    {
        foreach (string root in SourceRoots.All())
        {
            string? hit = Directory
                .EnumerateFiles(root, fileName, SearchOption.AllDirectories)
                .FirstOrDefault(p => !p.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                                     && !p.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"));
            if (hit is not null)
            {
                return File.ReadAllText(hit);
            }
        }

        throw new FileNotFoundException($"Could not locate {fileName} under any source root.");
    }
}
