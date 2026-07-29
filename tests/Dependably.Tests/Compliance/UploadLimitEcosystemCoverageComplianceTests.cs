using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: every ecosystem key that carries a per-ecosystem upload limit
/// (<see cref="Dependably.Infrastructure.OrgRepository.GetUploadLimitAsync"/>, the switch
/// <see cref="Dependably.Protocol.IUploadLimitResolver"/> resolves against) has a matching arm
/// in <c>UploadSizeLimitMiddleware.EcosystemForPath</c>. Without the arm the Kestrel-level
/// pre-body guard never fires for that ecosystem's push route: the framework accepts and streams
/// the whole body before the app-level counter trips, so the layered cap degrades from a
/// 413-before-a-byte-is-read to a post-buffer refusal. Cargo publish regressed exactly this way
/// (<c>PUT /cargo/api/v1/crates/new</c> had a limit tier but no path arm).
///
/// The check is deliberately one-directional: a limit-bearing ecosystem MUST have a path arm;
/// a path arm without a limit tier is fine (a future ecosystem can be routed before it grows an
/// override). Ecosystems with no hosted push path (go, apk) carry no limit tier, so they are not
/// required here — the moment one grows an upload limit in the tier switch, this gate demands the
/// corresponding path arm.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class UploadLimitEcosystemCoverageComplianceTests
{
    private readonly ITestOutputHelper _output;
    public UploadLimitEcosystemCoverageComplianceTests(ITestOutputHelper output) => _output = output;

    // "pypi" => settings?.MaxUploadBytesPyPi,  — the org-ecosystem tier switch keys.
    [GeneratedRegex(@"""(?<eco>[a-z]+)""\s*=>\s*settings\?\.MaxUploadBytes", RegexOptions.Singleline)]
    private static partial Regex TierSwitchKeyRegex();

    // _ when StartsWithSegment(path, "/pypi") ... => "pypi",  — capture the arm's ecosystem result.
    [GeneratedRegex(@"=>\s*""(?<eco>[a-z0-9]+)""", RegexOptions.Singleline)]
    private static partial Regex EcosystemForPathResultRegex();

    [Fact]
    public void EveryUploadLimitEcosystemHasAPathArm()
    {
        string resolverSource = ReadSourceFile("OrgRepository.cs");
        string middlewareSource = ReadSourceFile("UploadSizeLimitMiddleware.cs");

        // The limit-bearing ecosystem keys: the org-ecosystem tier switch in GetUploadLimitAsync.
        var limitEcosystems = TierSwitchKeyRegex().Matches(resolverSource)
            .Select(m => m.Groups["eco"].Value)
            .ToHashSet(StringComparer.Ordinal);

        Assert.True(limitEcosystems.Count >= 5,
            $"Expected to parse the upload-limit tier switch in OrgRepository.GetUploadLimitAsync; " +
            $"found only [{string.Join(", ", limitEcosystems)}]. Did the switch shape change?");

        // The ecosystem keys EcosystemForPath can return. Scoped to that method to avoid picking
        // up unrelated `=> "…"` expressions elsewhere in the file.
        string ecosystemForPath = ExtractMethodBody(middlewareSource, "EcosystemForPath(string path)");
        var routedEcosystems = EcosystemForPathResultRegex().Matches(ecosystemForPath)
            .Select(m => m.Groups["eco"].Value)
            .ToHashSet(StringComparer.Ordinal);

        Assert.Contains("cargo", routedEcosystems); // guards the specific regression the gate exists for

        var missing = limitEcosystems.Where(e => !routedEcosystems.Contains(e)).OrderBy(e => e).ToList();
        if (missing.Count > 0)
        {
            _output.WriteLine($"Limit-bearing ecosystems parsed:  {string.Join(", ", limitEcosystems.OrderBy(x => x))}");
            _output.WriteLine($"EcosystemForPath arms parsed:     {string.Join(", ", routedEcosystems.OrderBy(x => x))}");
            Assert.Fail(
                $"{missing.Count} ecosystem(s) have a per-ecosystem upload limit but no EcosystemForPath " +
                $"arm in UploadSizeLimitMiddleware: [{string.Join(", ", missing)}]. Add a `_ when " +
                $"StartsWithSegment(path, \"/<eco>\") => \"<eco>\"` arm so the pre-body 413 guard fires " +
                $"before Kestrel streams the push body.");
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

    // Returns the source from the method signature to the end of the file. EcosystemForPath is the
    // last method before the file's closing braces, so this captures its whole body without a full
    // brace-matcher; the result-arm regex only matches inside it.
    private static string ExtractMethodBody(string source, string methodName)
    {
        int idx = source.IndexOf(methodName, StringComparison.Ordinal);
        Assert.True(idx >= 0, $"Method {methodName} not found in source.");
        return source[idx..];
    }
}
