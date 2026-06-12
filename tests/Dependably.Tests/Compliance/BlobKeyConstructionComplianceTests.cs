using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check enforcing the architectural rule "BlobKeys is the only place blob keys are
/// constructed; callers never build key strings inline" (see CLAUDE.md → Key architectural
/// rules). A blob key passed to an <see cref="Dependably.Storage.IBlobStore"/> member must be
/// a variable or a <c>BlobKeys.…</c> call — never an inline string literal or an interpolated
/// / concatenated string built at the call site. Inlining a key string is exactly the drift
/// that fragments the key namespace and breaks the single-source-of-truth invariant.
///
/// Scope: the first argument to <c>PutAsync</c> / <c>GetAsync</c> / <c>ExistsAsync</c> /
/// <c>DeleteAsync</c>. Two deliberate exclusions keep this precise:
///   • a literal whose value starts with a URL scheme (http://, https://, file:) — that is an
///     <c>HttpClient</c>/SDK call of the same method name, not a blob-store call.
///   • BlobKeys.cs itself — the one place keys are legitimately built.
///
/// Opt-out: annotate the call line (or the window above it) with <c>// blobkey-ok: &lt;reason&gt;</c>.
/// Used for the readiness probe, whose fixed sentinel key never participates in the key namespace.
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class BlobKeyConstructionComplianceTests
{
    private readonly ITestOutputHelper _output;
    public BlobKeyConstructionComplianceTests(ITestOutputHelper output) => _output = output;

    // First argument to a blob-store method is an inline string literal or interpolated/
    // concatenated string. Captures the opening of the argument so the value can be inspected.
    //   .PutAsync("…"      .GetAsync($"…"      .ExistsAsync(@"…"
    [GeneratedRegex(@"\.(?:PutAsync|GetAsync|ExistsAsync|DeleteAsync)\(\s*(?<arg>\$?@?""[^""]*)", RegexOptions.None)]
    private static partial Regex InlineKeyArgRegex();

    [Fact]
    public void BlobKeysAreNeverConstructedInline()
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

            // BlobKeys.cs is the one place keys are legitimately built.
            if (Path.GetFileName(file).Equals("BlobKeys.cs", StringComparison.Ordinal))
            {
                continue;
            }

            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                foreach (Match m in InlineKeyArgRegex().Matches(lines[i]))
                {
                    string arg = m.Groups["arg"].Value;
                    if (IsUrlLiteral(arg))
                    {
                        continue;          // HttpClient/SDK call, not a blob key
                    }

                    if (HasOptOutComment(lines, i))
                    {
                        continue;
                    }

                    string rel = Path.GetRelativePath(srcRoot, file);
                    violations.Add(
                        $"{rel}:{i + 1}: blob key built inline at an IBlobStore call. Construct the key " +
                        $"via BlobKeys.… instead. If this is intentionally not a namespaced key (e.g. a " +
                        $"fixed probe sentinel), annotate with `// blobkey-ok: <reason>`. Call: {Truncate(lines[i].Trim(), 120)}");
                }
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} inline blob-key construction site(s) found. " +
                        $"See test output for the full list and remediation hint.");
        }
    }

    private static bool IsUrlLiteral(string arg)
    {
        // arg looks like  $?@?"value…  — strip the prefix and quote, then inspect the value.
        int idx = arg.IndexOf('"');
        if (idx < 0)
        {
            return false;
        }

        string value = arg[(idx + 1)..];
        return value.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("file:", StringComparison.OrdinalIgnoreCase);
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

    private static bool HasOptOutComment(string[] lines, int lineIndex)
    {
        for (int probe = Math.Max(0, lineIndex - 5); probe <= lineIndex && probe < lines.Length; probe++)
        {
            if (lines[probe].Contains("blobkey-ok:", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string Truncate(string s, int max)
    {
        s = s.Replace('\n', ' ').Replace('\r', ' ').Trim();
        return s.Length <= max ? s : s[..max] + "...";
    }
}
