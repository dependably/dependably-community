using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: a <see cref="System.Diagnostics.Metrics.MeterListener"/> filtered only by
/// <c>DependablyMeter.MeterName</c> + instrument name captures emissions from EVERY parallel
/// test in the process, because <c>DependablyMeter.Meter</c> is a deliberately static,
/// process-wide taxonomy (<c>Dependably.Core/Infrastructure/Observability/DependablyMeter.cs</c>).
/// A test class that attaches such a listener and asserts exact counts must serialize against
/// every other test that could emit the same instrument by carrying
/// <c>[Collection("MeterSensitive")]</c> (see <c>MeterSensitiveCollection</c>) — otherwise the
/// assertion is a coin flip under parallel load. This gate is the test-side isolation seam;
/// migrating <c>DependablyMeter</c> to <c>IMeterFactory</c> just to satisfy tests would be the
/// tail wagging the dog.
///
/// A listener scoped to a fresh, per-test <see cref="System.Diagnostics.Metrics.Meter"/>
/// instance (not the shared <c>DependablyMeter.Meter</c>) is immune to cross-talk by
/// construction and is not flagged — the gate only fires when the file both attaches a
/// <c>MeterListener</c> and filters on <c>DependablyMeter.MeterName</c>.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class MeterListenerIsolationComplianceTests
{
    private readonly ITestOutputHelper _output;
    public MeterListenerIsolationComplianceTests(ITestOutputHelper output) => _output = output;

    [GeneratedRegex(@"new\s+MeterListener\b", RegexOptions.None)]
    private static partial Regex MeterListenerRegex();

    [Fact]
    public void MeterListenersFilteredByDependablyMeterName_LiveInSerializedCollection()
    {
        string testsRoot = Path.Combine(SourceRoots.RepoRoot(), "tests");
        var violations = new List<string>();

        foreach (string file in Directory.EnumerateFiles(testsRoot, "*.cs", SearchOption.AllDirectories))
        {
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                || file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
            {
                continue;
            }

            // The collection-definition file itself references the collection name but never
            // attaches a MeterListener — the MeterListenerRegex() guard below already excludes it,
            // this comment just documents why it's safe to not special-case it.
            string content = File.ReadAllText(file);
            if (!MeterListenerRegex().IsMatch(content) || !content.Contains("DependablyMeter.MeterName"))
            {
                continue;
            }

            if (!content.Contains("[Collection(\"MeterSensitive\")]"))
            {
                violations.Add(
                    $"{Path.GetRelativePath(SourceRoots.RepoRoot(), file)}: attaches a MeterListener " +
                    "filtered by DependablyMeter.MeterName without [Collection(\"MeterSensitive\")] — " +
                    "it will capture emissions from every other parallel test against the process-wide " +
                    "static meter. Add [Collection(\"MeterSensitive\")] to the test class.");
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} MeterListener isolation violation(s). See test output for the full list.");
        }
    }
}
