namespace Dependably.Tests.Compliance;

/// <summary>
/// No production background job may set <c>ContinueOnTickError</c> to false. A tick exception
/// then escapes <c>ExecuteAsync</c>, and the host's default
/// <c>BackgroundServiceExceptionBehavior.StopHost</c> stops the whole application rather than
/// the one job. Every job runs a pass at startup, so one failing query, one unreachable feed or
/// one undecryptable secret becomes a crash loop on every boot, with the replica never ready.
/// A failed pass is logged and retried at the next scheduled occurrence instead.
/// </summary>
[Trait("Category", "Compliance")]
public sealed class BackgroundJobTickErrorComplianceTests
{
    [Fact]
    public void No_production_job_stops_the_host_on_a_tick_error()
    {
        string repoRoot = SourceRoots.RepoRoot();
        var violations = SourceRoots.AllCSharpFiles()
            .SelectMany(file => File.ReadAllLines(file).Select((line, i) => (file, line, i)))
            .Where(x => x.line.Contains("ContinueOnTickError => false", StringComparison.Ordinal))
            .Select(x => $"{Path.GetRelativePath(repoRoot, x.file)}:{x.i + 1}: {x.line.Trim()}")
            .ToList();

        Assert.True(violations.Count == 0,
            "A background job stops the whole host when a tick throws:\n" + string.Join("\n", violations));
    }
}
