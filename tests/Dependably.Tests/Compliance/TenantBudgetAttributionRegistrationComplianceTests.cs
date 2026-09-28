using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Every composition root that runs the rate limiter registers
/// <c>TenantBudgetAttributionMiddleware</c> as the statement immediately before
/// <c>app.UseRateLimiter()</c>, and after <c>app.UseRouting()</c> and <c>app.UseAuthorization()</c>.
///
/// The middleware is what keeps a request an org would refuse (no credential of that org while
/// anonymous pull is off) off that org's tenant budget. Its absence is silent: the limiter's
/// default is to charge, so a root that forgets it keeps working while any anonymous source can
/// drain an org's window. It reads the routed endpoint and the validated principal, so it must
/// follow routing and authorization, and it must precede the limiter it informs. Composition
/// roots are discovered by globbing <c>Program.cs</c> across <see cref="SourceRoots"/>, so the
/// edge root, and any later one, is covered without being named here.
/// </summary>
[Trait("Category", "Compliance")]
public sealed class TenantBudgetAttributionRegistrationComplianceTests
{
    private const string Limiter = "app.UseRateLimiter();";
    private const string Attribution = "TenantBudgetAttributionMiddleware>();";

    private readonly ITestOutputHelper _output;
    public TenantBudgetAttributionRegistrationComplianceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void Every_root_with_a_rate_limiter_registers_the_attribution_middleware_just_before_it()
    {
        string repoRoot = SourceRoots.RepoRoot();
        var roots = new List<(string Rel, List<string> Statements)>();
        foreach (string root in SourceRoots.All())
        {
            string program = Path.Combine(root, "Program.cs");
            if (File.Exists(program))
            {
                roots.Add((Path.GetRelativePath(repoRoot, program), Statements(File.ReadAllText(program))));
            }
        }

        var limited = roots.Where(r => r.Statements.Contains(Limiter)).ToList();
        Assert.True(
            limited.Count >= 2,
            $"Expected at least the community and edge composition roots to run the rate limiter, found {limited.Count}.");

        var violations = new List<string>();
        foreach (var (rel, statements) in limited)
        {
            int limiter = statements.IndexOf(Limiter);
            if (limiter == 0 || !statements[limiter - 1].EndsWith(Attribution, StringComparison.Ordinal))
            {
                violations.Add($"{rel}: the statement before {Limiter} is not app.UseMiddleware<…{Attribution}");
                continue;
            }

            foreach (string earlier in new[] { "app.UseRouting();", "app.UseAuthorization();" })
            {
                int at = statements.IndexOf(earlier);
                if (at < 0 || at > limiter - 1)
                {
                    violations.Add($"{rel}: the attribution middleware must follow {earlier}");
                }
            }
        }

        foreach (string v in violations)
        {
            _output.WriteLine(v);
        }

        Assert.True(violations.Count == 0, string.Join(Environment.NewLine, violations));
    }

    // Trimmed non-blank, non-comment lines: each registration is one line in these files.
    private static List<string> Statements(string source) =>
        source.Split('\n')
            .Select(l => l.Trim())
            .Where(l => l.Length > 0 && !l.StartsWith("//", StringComparison.Ordinal))
            .ToList();
}
