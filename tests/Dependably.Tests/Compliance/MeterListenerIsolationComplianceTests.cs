using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: a <see cref="System.Diagnostics.Metrics.MeterListener"/> that selects the shared
/// meter, either by <c>DependablyMeter.MeterName</c> or by matching a Dependably instrument name
/// literal (<c>instrument.Name == "dependably.…"</c> / <c>instrument.Name is "dependably.…"</c>),
/// captures emissions from EVERY parallel
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
/// <c>MeterListener</c> and selects the shared meter by <c>DependablyMeter.MeterName</c> or by a
/// <c>"dependably.</c> instrument-name literal. Tag-name literals such as
/// <c>"dependably.outcome"</c> are not instrument selectors and do not trip the gate.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class MeterListenerIsolationComplianceTests
{
    private readonly ITestOutputHelper _output;
    public MeterListenerIsolationComplianceTests(ITestOutputHelper output) => _output = output;

    // Matches `new MeterListener`, `new System.Diagnostics.Metrics.MeterListener`, and the
    // target-typed form `MeterListener _x = new();`.
    [GeneratedRegex(@"new\s+(System\.Diagnostics\.Metrics\.)?MeterListener\b|\bMeterListener\s+\w+\s*=\s*new\s*\(", RegexOptions.None)]
    private static partial Regex MeterListenerRegex();

    // Selection by name literal: an instrument (`Name == "dependably.x"`, `Name is "dependably.x" or ...`)
    // or the shared meter itself (`Meter.Name == "dependably"`, DependablyMeter.MeterName's value).
    // An instrument name matches process-wide regardless of which Meter instance emits it.
    [GeneratedRegex("""\bName\s*(==|is)\s*"dependably[."]""", RegexOptions.None)]
    private static partial Regex InstrumentNameLiteralRegex();

    [Fact]
    public void MeterListenersOnSharedMeter_LiveInSerializedCollection()
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
            bool selectsSharedMeter = content.Contains("DependablyMeter.MeterName")
                || InstrumentNameLiteralRegex().IsMatch(content);
            if (!MeterListenerRegex().IsMatch(content) || !selectsSharedMeter)
            {
                continue;
            }

            if (!content.Contains("[Collection(\"MeterSensitive\")]"))
            {
                violations.Add(
                    $"{Path.GetRelativePath(SourceRoots.RepoRoot(), file)}: attaches a MeterListener " +
                    "selecting the shared meter (DependablyMeter.MeterName or a \"dependably.*\" instrument-name literal) without [Collection(\"MeterSensitive\")] — " +
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
