using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check that every shipped runtime image installs the tz database and proves it at
/// build time. .NET resolves IANA zones by reading <c>/usr/share/zoneinfo</c>; the
/// <c>runtime-deps</c> Alpine base ships none of it, so an image without <c>tzdata</c> makes
/// <see cref="TimeZoneInfo.TryFindSystemTimeZoneById"/> reject every zone. The user- and
/// org-level display-timezone preferences then validate to 400 and every timestamp renders
/// UTC, while the frontend dropdown stays fully populated because it is built from the
/// browser's own <c>Intl.supportedValuesOf('timeZone')</c>.
///
/// <para>
/// This gate exists because the obvious test is green-but-blind: a unit test over
/// <c>TimeZoneCodes.IsSupported</c> passes on macOS and on the glibc CI runners, which have
/// tzdata, while the shipped image stays broken. The failure is a property of the image, so
/// the check has to read the image definition.
/// </para>
///
/// <para>
/// Two conditions, because either alone is escapable. Every <c>apk add</c> in the final stage
/// must name <c>tzdata</c> — a Dockerfile with several install paths ships broken if one of
/// them is missed. And the final stage must probe <c>/usr/share/zoneinfo</c>, because dropping
/// the package leaves <c>apk</c> exiting 0: only an explicit probe turns a silently UTC-only
/// image into a failed build. The probe is the durable half; the package list is what it
/// guards.
/// </para>
///
/// <para>
/// Roots resolve through <see cref="SourceRoots.RepoRoot"/> rather than
/// <see cref="SourceRoots.All"/>: the Dockerfiles are repo-root artefacts, not source roots.
/// Finding no Dockerfile is a failure, not a pass — a gate that silently scans nothing is
/// worse than one that goes red.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed class RuntimeTzDataComplianceTests
{
    private const string ZoneInfoPath = "/usr/share/zoneinfo";

    private static readonly Regex ApkAdd = new(@"\bapk\s+add\b", RegexOptions.Compiled);
    private static readonly Regex TzData = new(@"\btzdata\b", RegexOptions.Compiled);

    private readonly ITestOutputHelper _output;
    public RuntimeTzDataComplianceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void RuntimeImagesShipTheTzDatabase()
    {
        string repoRoot = SourceRoots.RepoRoot();

        var dockerfiles = Directory
            .EnumerateFiles(repoRoot, "Dockerfile*", SearchOption.TopDirectoryOnly)
            .OrderBy(p => p, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            dockerfiles.Count > 0,
            $"No Dockerfile found at the repo root ({repoRoot}). This gate scans the shipped " +
            "image definitions; finding none means it verified nothing, which is a failure, " +
            "not a pass.");

        var violations = new List<string>();
        foreach (string file in dockerfiles)
        {
            violations.AddRange(Analyze(Path.GetFileName(file), File.ReadAllText(file)));
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail(
                $"{violations.Count} runtime image(s) would resolve only UTC:{Environment.NewLine}" +
                string.Join(Environment.NewLine, violations));
        }

        _output.WriteLine($"Verified {dockerfiles.Count} Dockerfile(s) install and probe tzdata.");
    }

    /// <summary>
    /// The gate's own adversarial twin. The scan is textual, so it can degrade to matching
    /// nothing and reporting clean — exactly the failure mode it exists to prevent. These
    /// fixtures assert it still reports each half of the rule independently.
    /// </summary>
    [Fact]
    public void TheScanReportsBothHalvesOfTheRule()
    {
        const string prelude = """
            FROM node AS frontend
            RUN apk add --no-cache sqlite-libs
            FROM runtime-deps AS final
            """;

        string missingPackage = prelude + """

            RUN apk add --no-cache sqlite-libs icu-libs && \
                [ -f "/usr/share/zoneinfo/UTC" ] || exit 1
            """;

        string missingProbe = prelude + """

            RUN apk add --no-cache sqlite-libs icu-libs tzdata
            """;

        string compliant = prelude + """

            RUN apk add --no-cache sqlite-libs icu-libs tzdata && \
                [ -f "/usr/share/zoneinfo/UTC" ] || exit 1
            """;

        string[] noPackage = Analyze("fixture", missingPackage).ToArray();
        Assert.Contains(noPackage, v => v.Contains("does not install tzdata", StringComparison.Ordinal));

        string[] noProbe = Analyze("fixture", missingProbe).ToArray();
        Assert.Contains(noProbe, v => v.Contains(ZoneInfoPath, StringComparison.Ordinal));

        // The prelude's own tzdata-less `apk add` sits in an earlier stage: proving the
        // compliant fixture is clean is what shows discarded stages are not scanned.
        Assert.Empty(Analyze("fixture", compliant));

        // The reported line must be the final stage's install, not the prelude's.
        Assert.Contains("fixture:4:", noPackage.Single(v => v.Contains("tzdata", StringComparison.Ordinal)), StringComparison.Ordinal);
    }

    /// <summary>
    /// Checks the final stage only — the earlier build/frontend stages are discarded, so their
    /// package lists say nothing about what ships. The final stage is everything from the last
    /// <c>FROM</c> onward, which holds regardless of the stage's alias.
    /// </summary>
    private static IEnumerable<string> Analyze(string name, string text)
    {
        string[] lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');

        int lastFrom = -1;
        for (int i = 0; i < lines.Length; i++)
        {
            if (lines[i].TrimStart().StartsWith("FROM ", StringComparison.Ordinal))
            {
                lastFrom = i;
            }
        }

        if (lastFrom < 0)
        {
            yield return $"{name}: no FROM instruction — cannot identify the runtime stage.";
            yield break;
        }

        bool probed = false;
        for (int i = lastFrom; i < lines.Length; i++)
        {
            string line = lines[i];

            // Comments narrate the install (one already mentions "apk add" verbatim); only
            // instructions ship anything.
            if (line.TrimStart().StartsWith('#'))
            {
                continue;
            }

            if (line.Contains(ZoneInfoPath, StringComparison.Ordinal))
            {
                probed = true;
            }

            if (ApkAdd.IsMatch(line) && !TzData.IsMatch(line))
            {
                yield return $"{name}:{i + 1}: runtime-stage 'apk add' does not install tzdata — " +
                             $"the image would resolve only UTC. Line: {line.Trim()}";
            }
        }

        if (!probed)
        {
            yield return $"{name}: the runtime stage never probes {ZoneInfoPath}. Dropping the " +
                         "tzdata package leaves apk exiting 0, so without an explicit probe the " +
                         "build cannot fail on a UTC-only image.";
        }
    }
}
