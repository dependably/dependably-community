using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check enforcing that management-API problem details are localized: the detail
/// passed to <c>ProblemResults.ValidationErrorAction</c> / <c>ConflictAction</c> /
/// <c>ForbiddenAction</c> must never be an inline English string literal. Callers use the
/// key-based variants (<c>ValidationErrorActionKey</c>, <c>ConflictActionKey</c>,
/// <c>ConflictActionKeyFormat</c>, <c>ForbiddenActionKey</c>) with a SharedResource key so
/// the detail resolves against the per-request culture.
///
/// Scope: the <c>*Action</c> (IActionResult) helpers used by the management controllers.
/// The IResult variants (<c>ValidationError</c>, <c>Conflict</c>, <c>Forbidden</c>, …) used
/// by protocol surfaces (npm/PyPI/NuGet/OCI/Cargo clients) are deliberately not gated —
/// those responses go to CLI tools, not the localized SPA.
///
/// Opt-out: annotate the call line (or the window above it) with
/// <c>// detail-ok: &lt;reason&gt;</c> for a detail that is deliberately not localizable
/// (e.g. text echoed verbatim from an external system).
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class LocalizedProblemDetailComplianceTests
{
    private readonly ITestOutputHelper _output;
    public LocalizedProblemDetailComplianceTests(ITestOutputHelper output) => _output = output;

    // ValidationErrorAction("field", "literal…   — the detail (second arg) is a literal.
    // "ValidationErrorActionKey(" does not match: the method name must be followed by "(".
    [GeneratedRegex(@"ValidationErrorAction\(\s*""[^""]*""\s*,\s*\$?@?""", RegexOptions.Singleline)]
    private static partial Regex ValidationLiteralRegex();

    // ConflictAction("literal… / ForbiddenAction("literal… — the detail (first arg) is a literal.
    [GeneratedRegex(@"(?<!\w)(?:ConflictAction|ForbiddenAction)\(\s*\$?@?""", RegexOptions.Singleline)]
    private static partial Regex ConflictForbiddenLiteralRegex();

    [Fact]
    public void ProblemDetailsAreNeverInlineEnglishLiterals()
    {
        var violations = new List<string>();
        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string src = File.ReadAllText(file);
            string[] lines = src.Split('\n');

            foreach (var regex in new[] { ValidationLiteralRegex(), ConflictForbiddenLiteralRegex() })
            {
                foreach (Match m in regex.Matches(src))
                {
                    int lineIndex = src[..m.Index].Count(c => c == '\n');
                    if (HasOptOutComment(lines, lineIndex))
                    {
                        continue;
                    }

                    string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
                    violations.Add(
                        $"{rel}:{lineIndex + 1}: inline literal problem detail. Add the message to " +
                        $"SharedResource.resx (en + fr, with a translator <comment>) and call the " +
                        $"…ActionKey variant instead. Deliberately unlocalizable text opts out with " +
                        $"`// detail-ok: <reason>`. Call: {Truncate(lines[lineIndex].Trim(), 120)}");
                }
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} inline-literal problem-detail site(s) found. " +
                        $"See test output for the full list and remediation hint.");
        }
    }

    private static bool HasOptOutComment(string[] lines, int lineIndex)
    {
        for (int probe = Math.Max(0, lineIndex - 5); probe <= lineIndex && probe < lines.Length; probe++)
        {
            if (lines[probe].Contains("detail-ok:", StringComparison.OrdinalIgnoreCase))
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
