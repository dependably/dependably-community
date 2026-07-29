using System.Diagnostics;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Pins how <see cref="SchemaBaselineResolver"/> classifies a missing baseline, because that
/// classification is the whole difference between the blue-green gate failing loudly and passing
/// green having compared nothing. Each case runs against a throwaway git repository rather than
/// this checkout, so the distinction is exercised for real instead of mocked.
///
/// <para>The hazard being pinned: the tag list for a shallow CI checkout is discovered by asking
/// the remote, so an unreachable origin must not read as "this repository has never had a
/// release".</para>
/// </summary>
[Trait("Category", "Schema")]
public sealed class SchemaBaselineResolverTests
{
    [Fact]
    public void UnreachableOrigin_IsAnUnknownBaseline_NotABootstrap()
    {
        using var repo = TempGitRepo.Create();
        repo.Git("remote", "add", "origin", Path.Combine(repo.Path, "no-such-remote.git"));

        var resolution = SchemaBaselineResolver.Resolve(repo.Path);

        Assert.Null(resolution.Baseline);
        Assert.Equal(BaselineAbsence.DiscoveryFailed, resolution.Absence);
        Assert.False(SchemaBaselineResolver.IsTolerable(resolution, baselineRequired: true), resolution.Log);
        Assert.True(SchemaBaselineResolver.IsTolerable(resolution, baselineRequired: false), resolution.Log);
    }

    [Fact]
    public void RemoteThatAnswersWithNoReleaseTags_IsABootstrap()
    {
        using var remote = TempGitRepo.CreateBare();
        using var repo = TempGitRepo.Create();
        repo.Git("remote", "add", "origin", remote.Path);

        var resolution = SchemaBaselineResolver.Resolve(repo.Path);

        Assert.Null(resolution.Baseline);
        Assert.Equal(BaselineAbsence.NoReleaseTags, resolution.Absence);
        Assert.True(SchemaBaselineResolver.IsTolerable(resolution, baselineRequired: true), resolution.Log);
    }

    [Fact]
    public void RepositoryWithNoOriginRemote_FailsOnlyWhenABaselineIsRequired()
    {
        // Nowhere to ask is a tolerable absence for a developer checkout, but under
        // REQUIRE_BASELINE it must not pass: removing the remote would otherwise be a way to make
        // the gate go green.
        using var repo = TempGitRepo.Create();

        var resolution = SchemaBaselineResolver.Resolve(repo.Path);

        Assert.Null(resolution.Baseline);
        Assert.Equal(BaselineAbsence.NoOriginToAsk, resolution.Absence);
        Assert.False(SchemaBaselineResolver.IsTolerable(resolution, baselineRequired: true), resolution.Log);
        Assert.True(SchemaBaselineResolver.IsTolerable(resolution, baselineRequired: false), resolution.Log);
    }

    [Fact]
    public void DirectoryThatIsNotAGitRepository_FailsOnlyWhenABaselineIsRequired()
    {
        // Same shape as the missing remote: a source export is fine locally, but it cannot satisfy
        // an operator's assertion that a baseline exists.
        using var dir = TempGitRepo.CreateEmptyDirectory();

        var resolution = SchemaBaselineResolver.Resolve(dir.Path);

        Assert.Null(resolution.Baseline);
        Assert.Equal(BaselineAbsence.NotAGitRepository, resolution.Absence);
        Assert.False(SchemaBaselineResolver.IsTolerable(resolution, baselineRequired: true), resolution.Log);
        Assert.True(SchemaBaselineResolver.IsTolerable(resolution, baselineRequired: false), resolution.Log);
    }

    [Fact]
    public void ThisCheckout_ClassifiesCleanly_AndAnyBaselineItProducesIsWellFormed()
    {
        // Exactly as strict as the gate itself, and no stricter: an export or an offline checkout
        // tolerates a missing baseline, so this asserts the classification rather than demanding a
        // tag — running the suite must not require a git checkout with a discoverable release.
        // When a baseline IS produced (the normal case) it must be a real schema pair, so the
        // resolver cannot satisfy the gate with an empty read.
        var resolution = SchemaBaselineResolver.Resolve();

        if (resolution.Baseline is null)
        {
            return;
        }

        Assert.Equal(BaselineAbsence.None, resolution.Absence);
        Assert.Matches(@"^v\d+\.\d+\.\d+$", resolution.Baseline.Tag);
        Assert.Contains("CREATE TABLE", resolution.Baseline.SqliteSql, StringComparison.Ordinal);
        Assert.Contains("CREATE TABLE", resolution.Baseline.PostgresSql, StringComparison.Ordinal);
    }

    private sealed class TempGitRepo : IDisposable
    {
        public string Path { get; }

        private TempGitRepo(string path) => Path = path;

        public static TempGitRepo CreateEmptyDirectory()
        {
            string path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(), $"dependably-baseline-{Guid.NewGuid():N}");
            Directory.CreateDirectory(path);
            return new TempGitRepo(path);
        }

        public static TempGitRepo Create()
        {
            var repo = CreateEmptyDirectory();
            repo.Git("init", "--quiet");
            return repo;
        }

        public static TempGitRepo CreateBare()
        {
            var repo = CreateEmptyDirectory();
            repo.Git("init", "--bare", "--quiet");
            return repo;
        }

        public void Git(params string[] args)
        {
            var psi = new ProcessStartInfo("git")
            {
                WorkingDirectory = Path,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            foreach (string arg in args)
            {
                psi.ArgumentList.Add(arg);
            }

            psi.Environment["GIT_TERMINAL_PROMPT"] = "0";
            using var process = Process.Start(psi)!;
            string error = process.StandardError.ReadToEnd();
            process.WaitForExit(30_000);
            Assert.True(process.ExitCode == 0, $"git {string.Join(' ', args)} failed: {error}");
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Path, recursive: true);
            }
            catch (IOException)
            {
                // A leftover temp directory is not worth failing a test over.
            }
            catch (UnauthorizedAccessException)
            {
                // Same.
            }
        }
    }
}
