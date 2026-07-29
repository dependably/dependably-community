using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check enforcing that every composition root installs the terminal exception handler,
/// and installs it outermost.
///
/// The handler is the only thing standing between an unexpected exception and a bare framework
/// 500 with no problem document, no correlation id, and no structured Error log. The community
/// server and the edge are separate assemblies with separate <c>Program</c> files, so "it is
/// registered" is a per-root property: wiring one root and forgetting the other yields an error
/// contract that silently differs between the two images. Composition roots are discovered by
/// globbing for <c>Program.cs</c> across the source roots rather than being listed here, so a
/// third root added later is covered the moment it lands.
///
/// Outermost matters as much as present. The typed exception middlewares translate their own
/// domain exceptions; the terminal handler only sees what they decline. Registered anywhere but
/// first, it stops being terminal — exceptions thrown by the middlewares ahead of it escape.
/// </summary>
[Trait("Category", "Compliance")]
public sealed class TerminalExceptionHandlerRegistrationComplianceTests
{
    private const string ServiceRegistration = "AddDependablyTerminalExceptionHandler()";
    private const string PipelineRegistration = "UseDependablyTerminalExceptionHandler()";

    private readonly ITestOutputHelper _output;
    public TerminalExceptionHandlerRegistrationComplianceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void EveryCompositionRootInstallsTheTerminalHandlerOutermost()
    {
        var roots = CompositionRoots();

        // Guard the guard: a glob that silently matches nothing would make this gate green-blind.
        Assert.True(
            roots.Count >= 2,
            $"Expected at least the community and edge composition roots, found {roots.Count}.");

        var violations = new List<string>();
        foreach ((string rel, string source) in roots)
        {
            if (!source.Contains(ServiceRegistration, StringComparison.Ordinal))
            {
                violations.Add($"{rel}: does not call builder.{ServiceRegistration}.");
            }

            if (!source.Contains(PipelineRegistration, StringComparison.Ordinal))
            {
                violations.Add($"{rel}: does not call app.{PipelineRegistration} in ConfigureApp.");
                continue;
            }

            string? firstUse = FirstPipelineRegistration(source);
            if (firstUse is not null && !firstUse.Contains(PipelineRegistration, StringComparison.Ordinal))
            {
                violations.Add(
                    $"{rel}: the terminal handler is not the outermost middleware — the pipeline " +
                    $"opens with `{firstUse}`. Move app.{PipelineRegistration} above it.");
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail(
                $"{violations.Count} composition-root registration violation(s). An unexpected " +
                $"exception must produce the same localized problem+json with a correlation id on " +
                $"every image. See test output for the full list.");
        }
    }

    /// <summary>Every <c>Program.cs</c> across the source roots, with its repo-relative path.</summary>
    private static List<(string Rel, string Source)> CompositionRoots()
    {
        string repoRoot = SourceRoots.RepoRoot();
        var found = new List<(string, string)>();
        foreach (string root in SourceRoots.All())
        {
            string program = Path.Combine(root, "Program.cs");
            if (File.Exists(program))
            {
                found.Add((Path.GetRelativePath(repoRoot, program), File.ReadAllText(program)));
            }
        }

        return found;
    }

    /// <summary>
    /// The first <c>app.Use…</c> / <c>app.Map…</c> call in the file — i.e. the outermost frame of
    /// the middleware pipeline. Comment lines are skipped so a commented-out registration cannot
    /// masquerade as the first one.
    /// </summary>
    private static string? FirstPipelineRegistration(string source)
    {
        foreach (string line in source.Split('\n'))
        {
            string trimmed = line.Trim();
            if (trimmed.StartsWith("//", StringComparison.Ordinal))
            {
                continue;
            }

            if (trimmed.StartsWith("app.Use", StringComparison.Ordinal)
                || trimmed.StartsWith("app.Map", StringComparison.Ordinal))
            {
                return trimmed;
            }
        }

        return null;
    }
}
