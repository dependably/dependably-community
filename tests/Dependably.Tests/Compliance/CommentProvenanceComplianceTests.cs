using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check enforcing the comment-hygiene rule (CLAUDE.md → Key architectural rules):
/// comments describe the current architecture, not its development history. No issue/tracker
/// numbers (<c>#123</c>), milestone tags (<c>M2.1</c>), or ephemeral branch/PR pointers
/// (<c>this PR</c>, <c>this MR</c>, <c>see plan</c>, <c>pre-#91</c>) belong in source comments —
/// that provenance lives in git history and the issue tracker.
///
/// Only the comment portion of each line (text after <c>//</c>) is inspected, so a string
/// literal or regex that legitimately contains <c>#123</c> is not flagged. Patterns are kept
/// to the unambiguous set; prose like "X is used to do Y" is intentionally NOT matched (only a
/// human can tell "used to" present-tense purpose from "used to" past-tense history).
///
/// Functional markers (<c>// xtenant:</c>, <c>// rawsql:</c>, <c>// blobkey-ok:</c>,
/// <c>// deepcode ignore</c>, etc.) are not provenance and are unaffected.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class CommentProvenanceComplianceTests
{
    private readonly ITestOutputHelper _output;
    public CommentProvenanceComplianceTests(ITestOutputHelper output) => _output = output;

    private static readonly (Regex Pattern, string Label)[] Banned =
    {
        // Issue/MR number like #123. Lookbehind excludes identifiers such as "C#10".
        (IssueNumberRegex(),   "issue/tracker number (#NNN) — provenance belongs in git history"),
        (MilestoneRegex(),     "milestone tag (M<major>.<minor>) — provenance belongs in the tracker"),
        (PrPointerRegex(),     "ephemeral PR/MR/plan pointer — describe present-tense behavior instead"),
    };

    [GeneratedRegex(@"(?<![A-Za-z0-9])#\d{2,5}\b")]
    private static partial Regex IssueNumberRegex();

    [GeneratedRegex(@"\bM\d+\.\d+\b")]
    private static partial Regex MilestoneRegex();

    [GeneratedRegex(@"\bthis (PR|MR)\b|\bsee plan\b|\bpre-#", RegexOptions.IgnoreCase)]
    private static partial Regex PrPointerRegex();

    [Fact]
    public void NoDevelopmentProvenanceInComments()
    {
        string srcRoot = LocateSourceRoot();
        Assert.True(Directory.Exists(srcRoot), $"src root not found at {srcRoot}");

        var violations = new List<string>();
        foreach (string file in Directory.EnumerateFiles(srcRoot, "*.cs", SearchOption.AllDirectories))
        {
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                || file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
            {
                continue;
            }

            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                string? comment = CommentText(lines[i]);
                if (comment is null)
                {
                    continue;
                }

                foreach (var (pattern, label) in Banned)
                {
                    if (pattern.IsMatch(comment))
                    {
                        string rel = Path.GetRelativePath(srcRoot, file);
                        violations.Add($"{rel}:{i + 1}: {label}. Comment: {comment.Trim()}");
                    }
                }
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} comment(s) carry development provenance. " +
                        $"See test output; move the reference to git history / the tracker.");
        }
    }

    /// <summary>
    /// Returns the comment portion of a line (text after the first <c>//</c> that is not inside
    /// a string), or null if the line has no line comment. Crude: ignores <c>//</c> appearing
    /// inside string literals by tracking quote state. Block comments are not handled (the
    /// codebase uses <c>//</c> and <c>///</c> almost exclusively).
    /// </summary>
    private static string? CommentText(string line)
    {
        bool inString = false;
        char stringChar = '"';
        for (int i = 0; i < line.Length - 1; i++)
        {
            char c = line[i];
            if (inString)
            {
                if (c == '\\') { i++; continue; }
                if (c == stringChar)
                {
                    inString = false;
                }

                continue;
            }
            if (c is '"' or '\'') { inString = true; stringChar = c; continue; }
            if (c == '/' && line[i + 1] == '/')
            {
                return line[(i + 2)..];
            }
        }
        return null;
    }

    private static string LocateSourceRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string candidate = Path.Combine(dir.FullName, "src", "Dependably");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            dir = dir.Parent;
        }
        return string.Empty;
    }
}
