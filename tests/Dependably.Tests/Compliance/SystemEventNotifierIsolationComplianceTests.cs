using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static gate for the operator-Slack isolation invariant: the system-realm notifier
/// (<c>Dependably.Infrastructure.SystemEvents.ISystemEventNotifier</c>) is a wiring seam
/// deliberately separate from the per-org alert notifier
/// (<c>Dependably.Infrastructure.Alerts.IAlertNotifier</c>). No production file should reference
/// both interfaces — a file that does is either fanning operator events into the per-org alert
/// path or vice versa, either of which breaks the "operator Slack never repeats a tenant alert"
/// guarantee. DI composition files that merely register both independently (they never pass one
/// into the other's constructor) are excepted by name.
///
/// The second leg pins the assembly boundary: <c>Dependably.Core</c> — the shared closure the
/// edge composition root references — must never reference <c>ISystemEventNotifier</c> at all.
/// The interface, its background-service implementation, and every producer call site live in
/// <c>Dependably.Management</c> (or the composition root), so an edge deployment — which never
/// references Management — can never end up with the operator-Slack seam wired into its DI graph.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class SystemEventNotifierIsolationComplianceTests
{
    private readonly ITestOutputHelper _output;
    public SystemEventNotifierIsolationComplianceTests(ITestOutputHelper output) => _output = output;

    // DI composition files that register both seams independently — neither passes an
    // IAlertNotifier into an ISystemEventNotifier call site or vice versa, so co-mention here is
    // wiring, not a cross-wire.
    private static readonly HashSet<string> DiExtensionFilesAllowed = new(StringComparer.Ordinal)
    {
        "ManagementServiceCollectionExtensions.cs",
        "Program.cs",
    };

    [GeneratedRegex(@"\bIAlertNotifier\b")]
    private static partial Regex AlertNotifierRegex();

    [GeneratedRegex(@"\bISystemEventNotifier\b")]
    private static partial Regex SystemEventNotifierRegex();

    // Lines that are comments only (including `///` doc comments) are excluded before matching —
    // the interfaces' own doc comments legitimately name each other in prose to describe the
    // isolation boundary (see ISystemEventNotifier's XML doc). The gate cares about actual wiring
    // (a constructor parameter, a field, a cast) landing in the same file, not documentation.
    private static string StripCommentLines(string content)
    {
        var kept = content.Split('\n').Where(line => !line.TrimStart().StartsWith("//", StringComparison.Ordinal));
        return string.Join('\n', kept);
    }

    [Fact]
    public void NoFileReferencesBothNotifierSeams()
    {
        var violations = new List<string>();
        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string fileName = Path.GetFileName(file);
            if (DiExtensionFilesAllowed.Contains(fileName))
            {
                continue;
            }

            string code = StripCommentLines(File.ReadAllText(file));
            bool hasAlert = AlertNotifierRegex().IsMatch(code);
            bool hasSystem = SystemEventNotifierRegex().IsMatch(code);
            if (hasAlert && hasSystem)
            {
                violations.Add(Path.GetRelativePath(SourceRoots.OwningRoot(file), file));
            }
        }

        if (violations.Count > 0)
        {
            _output.WriteLine("Files referencing both IAlertNotifier and ISystemEventNotifier:");
            violations.ForEach(_output.WriteLine);
        }

        Assert.True(violations.Count == 0,
            $"{violations.Count} file(s) reference both IAlertNotifier and ISystemEventNotifier — the operator " +
            "Slack channel must never be wired to the per-org alert path. See test output for the file list.");
    }

    [Fact]
    public void CoreNeverReferencesSystemEventNotifier()
    {
        string coreRoot = SourceRoots.All().Single(r => Path.GetFileName(r) == "Dependably.Core");

        var violations = Directory.EnumerateFiles(coreRoot, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                        && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
            .Where(f => SystemEventNotifierRegex().IsMatch(File.ReadAllText(f)))
            .Select(f => Path.GetRelativePath(coreRoot, f))
            .ToList();

        if (violations.Count > 0)
        {
            _output.WriteLine("Dependably.Core files referencing ISystemEventNotifier:");
            violations.ForEach(_output.WriteLine);
        }

        Assert.True(violations.Count == 0,
            $"{violations.Count} file(s) in Dependably.Core reference ISystemEventNotifier — the operator Slack " +
            "seam belongs to Dependably.Management (or the composition root) only, so the edge closure never " +
            "wires it up.");
    }
}
