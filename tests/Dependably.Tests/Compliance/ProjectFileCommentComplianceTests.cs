using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check enforcing the project-file comment-hygiene rule (CLAUDE.md → Key architectural
/// rules): <c>*.csproj</c> and <c>*.props</c> files carry no XML comments. Rationale for package
/// pins and build config belongs in git history, the issue tracker, and project memory — not in
/// inline <c>&lt;!-- … --&gt;</c> essays that drift from the truth.
///
/// A deliberate, rare comment opts out with an inline <c>&lt;!-- csproj-comment-ok: reason --&gt;</c>
/// marker (the XML analogue of the <c>// xtenant:</c> / <c>// rawsql:</c> / <c>// blobkey-ok:</c>
/// source markers). The standard is no comments, so this marker is expected to stay empty.
///
/// Scans the canonical tree only: <c>bin/</c>, <c>obj/</c>, <c>node_modules/</c>, and the
/// <c>.claude/</c> worktree copies are excluded.
/// </summary>
[Trait("Category", "Compliance")]
public sealed class ProjectFileCommentComplianceTests
{
    private const string OptOutMarker = "csproj-comment-ok:";

    // Matched against repo-root-relative path segments (not the absolute path) so the scan is
    // correct whether the test runs from the main checkout or from a .claude/worktrees/ copy —
    // a worktree's own files live under .claude/ in their absolute path but not relative to it.
    private static readonly HashSet<string> ExcludedSegments =
        new(StringComparer.Ordinal) { "bin", "obj", "node_modules", ".claude" };

    private readonly ITestOutputHelper _output;
    public ProjectFileCommentComplianceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void NoCommentsInProjectFiles()
    {
        string repoRoot = LocateRepoRoot();
        Assert.True(Directory.Exists(repoRoot), $"repo root not found at {repoRoot}");

        var violations = new List<string>();
        foreach ((string file, string rel) in EnumerateProjectFiles(repoRoot))
        {
            string text = File.ReadAllText(file);

            int cursor = 0;
            while (true)
            {
                int open = text.IndexOf("<!--", cursor, StringComparison.Ordinal);
                if (open < 0)
                {
                    break;
                }

                int close = text.IndexOf("-->", open + 4, StringComparison.Ordinal);
                int blockEnd = close < 0 ? text.Length : close + 3;
                string block = text[open..blockEnd];

                if (!block.Contains(OptOutMarker, StringComparison.Ordinal))
                {
                    int line = 1 + text.AsSpan(0, open).Count('\n');
                    violations.Add($"{rel}:{line}: XML comment in project file. " +
                                   $"First line: {FirstLine(block)}");
                }

                cursor = blockEnd;
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} XML comment(s) in project files. See test output; " +
                        $"move the rationale to git history / the tracker / project memory, or opt " +
                        $"out a deliberate comment with <!-- {OptOutMarker} reason -->.");
        }
    }

    private static IEnumerable<(string File, string Rel)> EnumerateProjectFiles(string repoRoot)
    {
        foreach (string pattern in new[] { "*.csproj", "*.props" })
        {
            foreach (string file in Directory.EnumerateFiles(repoRoot, pattern, SearchOption.AllDirectories))
            {
                string rel = Path.GetRelativePath(repoRoot, file);
                string[] segments = rel.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                if (segments.Any(ExcludedSegments.Contains))
                {
                    continue;
                }

                yield return (file, rel);
            }
        }
    }

    private static string FirstLine(string block)
    {
        int nl = block.IndexOf('\n');
        string first = (nl < 0 ? block : block[..nl]).Trim();
        return first.Length > 100 ? first[..100] + "…" : first;
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
