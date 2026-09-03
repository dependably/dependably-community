using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Fail-closed gate for the ZIP entry-count invariant: <c>SafeZipArchive</c> is the only place a
/// <c>ZipArchive</c> is constructed, so every archive opened over untrusted bytes has had its
/// declared entry count checked first.
///
/// <para>
/// <c>ZipArchive.Entries</c> materialises the whole central directory into a
/// <c>List&lt;ZipArchiveEntry&gt;</c> on first access, and the entry count is attacker-controlled
/// independently of the compressed size the upload limits bound — a central-directory record is
/// ~46 bytes plus a one-byte filename, and the local file data it points at need not exist for the
/// listing to succeed. The existing byte caps (<c>ZipEntryLimits.MaxMetadataEntryBytes</c>) bound a
/// single *matched* entry's decompressed size, which is a different quantity: they say nothing about
/// the cost of finding it.
/// </para>
///
/// <para>
/// This is the same rule the tar path has always had (<c>TarScanLimits.MaxEntries</c>, whose comment
/// states the reasoning outright). The ZIP path never inherited it, across 14 construction sites in
/// 9 files — which is exactly the drift a gate prevents and a reviewer does not, since each
/// individual <c>new ZipArchive(...)</c> looks unremarkable.
/// </para>
///
/// <para>
/// A deliberate exception opts out with <c>// zip-open-ok: &lt;reason&gt;</c> in the 5 lines above,
/// matching the <c>// xtenant:</c> / <c>// rawsql:</c> / <c>// blobkey-ok:</c> convention. A bare
/// marker with no stated reason is malformed and is never honoured.
/// </para>
///
/// <para>
/// <b>Known limitations, stated plainly:</b> a source scan. It catches the <c>new ZipArchive(…)</c>
/// spelling and nothing else — an archive opened through a helper that itself wraps the constructor
/// elsewhere, or via <c>ZipFile.OpenRead</c>, would need its own rule (neither exists in this
/// codebase today, and <c>ZipFile</c> is checked below for that reason). It proves the *construction*
/// is routed through the factory; it cannot prove the stream handed to it is the untrusted one, nor
/// that the cap value is the right one.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class ZipArchiveConstructionComplianceTests
{
    private const string Marker = "zip-open-ok:";
    private const int MarkerWindow = 5;

    /// <summary>The single file permitted to construct a <c>ZipArchive</c> directly.</summary>
    private const string FactoryFileName = "SafeZipArchive.cs";

    [GeneratedRegex(@"new\s+ZipArchive\s*\(")]
    private static partial Regex RawConstruction();

    // ZipFile.OpenRead/Open hand back a ZipArchive without passing through the factory.
    [GeneratedRegex(@"\bZipFile\s*\.\s*Open(?:Read)?\s*\(")]
    private static partial Regex ZipFileOpen();

    private readonly ITestOutputHelper _output;
    public ZipArchiveConstructionComplianceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void ZipArchivesAreOpenedOnlyThroughSafeZipArchive()
    {
        var violations = new List<string>();

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            if (Path.GetFileName(file).Equals(FactoryFileName, StringComparison.Ordinal))
            {
                continue;
            }

            string text = File.ReadAllText(file);
            string rel = Path.GetRelativePath(SourceRoots.RepoRoot(), file);

            foreach (var (pattern, what) in
                     new[] { (RawConstruction(), "new ZipArchive(...)"), (ZipFileOpen(), "ZipFile.Open/OpenRead(...)") })
            {
                foreach (Match m in pattern.Matches(text))
                {
                    if (HasMarkerAbove(text, m.Index))
                    {
                        continue;
                    }

                    violations.Add(
                        $"{rel}:{LineOf(text, m.Index)}: {what} bypasses SafeZipArchive.Open, so the " +
                        $"archive's entry count is never checked before ZipArchive.Entries allocates " +
                        $"one object per entry.");
                }
            }
        }

        Assert.True(violations.Count == 0, Report(violations,
            "ZipArchive construction(s) bypassing the entry-count cap"));
    }

    [Fact]
    public void EveryZipOpenOkMarkerCarriesAStatedReason()
    {
        var violations = new List<string>();

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string rel = Path.GetRelativePath(SourceRoots.RepoRoot(), file);
            string[] lines = File.ReadAllLines(file);

            for (int i = 0; i < lines.Length; i++)
            {
                int at = lines[i].IndexOf(Marker, StringComparison.Ordinal);
                if (at >= 0 && lines[i][(at + Marker.Length)..].Trim().Length == 0)
                {
                    violations.Add($"{rel}:{i + 1}: bare '{Marker}' marker with no stated reason.");
                }
            }
        }

        Assert.True(violations.Count == 0, Report(violations, "Malformed zip-open-ok marker(s)"));
    }

    private static bool HasMarkerAbove(string text, int index)
    {
        int line = LineOf(text, index);
        string[] lines = text.Split('\n');
        int first = Math.Max(0, line - 1 - MarkerWindow);

        for (int i = first; i < line && i < lines.Length; i++)
        {
            int at = lines[i].IndexOf(Marker, StringComparison.Ordinal);
            if (at >= 0 && lines[i][(at + Marker.Length)..].Trim().Length > 0)
            {
                return true;
            }
        }

        return false;
    }

    private static int LineOf(string text, int index) => 1 + text.AsSpan(0, index).Count('\n');

    private string Report(List<string> violations, string headline)
    {
        foreach (string v in violations)
        {
            _output.WriteLine(v);
        }

        return $"{headline} ({violations.Count}):{Environment.NewLine}" +
               string.Join(Environment.NewLine, violations);
    }
}
