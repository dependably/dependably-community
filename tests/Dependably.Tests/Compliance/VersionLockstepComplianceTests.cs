using System.Text.Json;
using System.Text.RegularExpressions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check enforcing the version-lockstep rule: <c>Directory.Build.props</c> is the single
/// source of truth for the application version; <c>web/package.json</c> must carry the same value.
/// The <c>release</c> skill (and <c>CONTRIBUTING.md</c> → Versioning) bumps both files together
/// so they never drift silently. A mismatch here means one of the two was updated without the other.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class VersionLockstepComplianceTests
{
    [GeneratedRegex(@"<Version>\s*([^<\s]+)\s*</Version>")]
    private static partial Regex VersionPattern();

    [Fact]
    public void DirectoryBuildPropsAndPackageJsonVersionsMatch()
    {
        string repoRoot = LocateRepoRoot();
        Assert.True(Directory.Exists(repoRoot), $"repo root not found at {repoRoot}");

        string propsPath = Path.Combine(repoRoot, "Directory.Build.props");
        string packageJsonPath = Path.Combine(repoRoot, "web", "package.json");

        string propsText = File.ReadAllText(propsPath);
        var m = VersionPattern().Match(propsText);
        Assert.True(m.Success,
            $"Could not find <Version> element in {propsPath}. " +
            $"Expected a line of the form <Version>x.y.z</Version>.");
        string propsVersion = m.Groups[1].Value;

        string packageJsonText = File.ReadAllText(packageJsonPath);
        using var doc = JsonDocument.Parse(packageJsonText);
        Assert.True(
            doc.RootElement.TryGetProperty("version", out var versionElement),
            $"Could not find \"version\" property in {packageJsonPath}.");
        string packageJsonVersion = versionElement.GetString() ?? string.Empty;

        if (!string.Equals(propsVersion, packageJsonVersion, StringComparison.Ordinal))
        {
            Assert.Fail(
                $"Version mismatch: Directory.Build.props has \"{propsVersion}\" " +
                $"({propsPath}) but web/package.json has \"{packageJsonVersion}\" " +
                $"({packageJsonPath}). " +
                $"Both files must be bumped together. " +
                $"Use the `release` skill or follow CONTRIBUTING.md → Versioning to update both in lockstep.");
        }
    }

    private static string LocateRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "src", "Dependably")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }
        return string.Empty;
    }
}
