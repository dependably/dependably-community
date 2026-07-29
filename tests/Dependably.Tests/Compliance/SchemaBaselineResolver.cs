using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace Dependably.Tests.Compliance;

/// <summary>The previous release's schema DDL, read out of git at that release's tag.</summary>
internal sealed record SchemaBaseline(string Tag, string SqliteSql, string PostgresSql);

/// <summary>Why no baseline was produced. Exactly one of these is a genuine "there is nothing to be
/// compatible with"; the rest are ways of having compared nothing, which is a different claim.</summary>
internal enum BaselineAbsence
{
    /// <summary>A baseline was resolved.</summary>
    None,

    /// <summary>The tag list was established and holds no release: a pre-first-release repository.</summary>
    NoReleaseTags,

    /// <summary>No local tags and no <c>origin</c> to ask — nowhere to look, so the tag list is unknown.</summary>
    NoOriginToAsk,

    /// <summary>Asking <c>origin</c> for the tag list failed, so the tag list is unknown.</summary>
    DiscoveryFailed,

    /// <summary>A release tag is known, but its objects or schema files could not be read.</summary>
    TagUnreadable,

    /// <summary>Not a git work tree at all — a source export rather than a checkout.</summary>
    NotAGitRepository,
}

/// <summary>
/// Outcome of baseline resolution. <see cref="Absence"/> distinguishes the several ways of ending up
/// without a baseline, because only one of them (<see cref="BaselineAbsence.NoReleaseTags"/>) means
/// "this repository has never had a release". The rest mean the gate compared nothing, which is not
/// evidence of compatibility — see <see cref="SchemaBaselineResolver.IsTolerable"/>.
/// </summary>
internal sealed record BaselineResolution(SchemaBaseline? Baseline, BaselineAbsence Absence, string Log);

/// <summary>
/// Resolves the previous release's <c>Schema.sql</c> / <c>Schema.pg.sql</c> from git.
///
/// <para>The previous release is the newest <c>vX.Y.Z</c> tag reachable from <c>HEAD</c>; when
/// reachability cannot be established (a shallow checkout has no ancestry to walk), the
/// highest-versioned known tag is used instead.</para>
///
/// <para>Nothing here assumes full history. Tag names come from the local tag list and, failing
/// that, from <c>git ls-remote</c>; the tag's objects are fetched explicitly with
/// <c>git fetch --depth=1 origin refs/tags/&lt;tag&gt;:refs/tags/&lt;tag&gt;</c> when they are absent,
/// which is what makes the gate work under GitLab's shallow clone. Git runs with terminal prompts
/// disabled and a bounded timeout, so a checkout with no network access degrades to "no baseline"
/// instead of hanging.</para>
///
/// <para>The schema files are located by path inside the tag's tree rather than by a hard-coded
/// path, so a release predating a source-tree reorganisation still resolves.</para>
/// </summary>
internal static partial class SchemaBaselineResolver
{
    private const int LocalTimeoutMs = 30_000;
    private const int NetworkTimeoutMs = 120_000;

    [GeneratedRegex(@"^v(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)$")]
    private static partial Regex ReleaseTagRegex();

    [GeneratedRegex(@"refs/tags/(?<tag>v\d+\.\d+\.\d+)$", RegexOptions.Multiline)]
    private static partial Regex RemoteTagRegex();

    private static readonly string SqliteSchemaSuffix =
        string.Join('/', "Infrastructure", "schema", "Schema.sql");
    private static readonly string PostgresSchemaSuffix =
        string.Join('/', "Infrastructure", "schema", "Schema.pg.sql");

    /// <param name="repoRoot">Repository to resolve against; defaults to this checkout's root.</param>
    public static BaselineResolution Resolve(string? repoRoot = null)
    {
        string repo = repoRoot ?? SourceRoots.RepoRoot();
        var log = new StringBuilder();

        if (Git(repo, LocalTimeoutMs, "rev-parse", "--is-inside-work-tree") is not { Ok: true })
        {
            log.AppendLine("not a git work tree — no previous release to compare against");
            return new BaselineResolution(null, BaselineAbsence.NotAGitRepository, log.ToString());
        }

        (var tags, var absence) = KnownReleaseTags(repo, log);
        if (tags.Count == 0)
        {
            log.AppendLine(absence == BaselineAbsence.NoReleaseTags
                ? "no vX.Y.Z release tag is known — treating this as a pre-first-release repository"
                : "the release tag list could not be established — this is an unknown baseline, NOT a pre-first-release repository");
            return new BaselineResolution(null, absence, log.ToString());
        }

        string tag = PreviousReleaseTag(repo, tags, log);
        log.AppendLine($"previous release tag: {tag}");

        if (!EnsureTagAvailable(repo, tag, log))
        {
            return new BaselineResolution(null, BaselineAbsence.TagUnreadable, log.ToString());
        }

        var tree = Git(repo, LocalTimeoutMs, "ls-tree", "-r", "--name-only", tag);
        if (tree is not { Ok: true })
        {
            log.AppendLine($"could not list the tree at {tag}: {tree?.Error}");
            return new BaselineResolution(null, BaselineAbsence.TagUnreadable, log.ToString());
        }

        string[] paths = tree.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        string? sqlitePath = paths.FirstOrDefault(p => p.EndsWith(SqliteSchemaSuffix, StringComparison.Ordinal));
        string? pgPath = paths.FirstOrDefault(p => p.EndsWith(PostgresSchemaSuffix, StringComparison.Ordinal));
        if (sqlitePath is null || pgPath is null)
        {
            log.AppendLine($"{tag} declares no Schema.sql / Schema.pg.sql pair under Infrastructure/schema/");
            return new BaselineResolution(null, BaselineAbsence.TagUnreadable, log.ToString());
        }

        var sqlite = Git(repo, LocalTimeoutMs, "show", $"{tag}:{sqlitePath}");
        var postgres = Git(repo, LocalTimeoutMs, "show", $"{tag}:{pgPath}");
        if (sqlite is not { Ok: true } || postgres is not { Ok: true })
        {
            log.AppendLine($"could not read the schema files at {tag}: {sqlite?.Error} {postgres?.Error}");
            return new BaselineResolution(null, BaselineAbsence.TagUnreadable, log.ToString());
        }

        log.AppendLine($"baseline schema read from {tag}: {sqlitePath}, {pgPath}");
        return new BaselineResolution(
            new SchemaBaseline(tag, sqlite.Output, postgres.Output), BaselineAbsence.None, log.ToString());
    }

    /// <summary>
    /// Whether a resolution may be reported as success.
    ///
    /// <para>Without <paramref name="baselineRequired"/> every absence is tolerable: a developer
    /// checkout offline, or a source export with no git, should not fail a build over a comparison
    /// it cannot run.</para>
    ///
    /// <para>With it — the operator asserting that a baseline must exist — the only tolerable
    /// absence is <see cref="BaselineAbsence.NoReleaseTags"/>: the tag list was established and the
    /// repository has genuinely never had a release. Every other absence leaves the tag list or the
    /// schema unknown, and none of them may be reachable by *removing* something (a remote, the
    /// tags, the <c>.git</c> directory), or "delete it and the gate goes green" becomes the easiest
    /// way past the gate.</para>
    /// </summary>
    public static bool IsTolerable(BaselineResolution resolution, bool baselineRequired) =>
        resolution.Baseline is not null
        || !baselineRequired
        || resolution.Absence == BaselineAbsence.NoReleaseTags;

    // Local tags first; a shallow CI clone may carry none, so fall back to asking the remote for
    // the tag names (cheap — no objects transferred).
    //
    // An empty result means one of two opposite things, and they must not be conflated: a remote
    // that answered and has no release tags is a genuine pre-first-release repository, while a
    // remote that could not be reached leaves the tag list UNKNOWN. Collapsing the second into the
    // first is how a name-resolution blip silently turns the gate into a no-op, so the failure is
    // carried out as a flag rather than logged and dropped. A repository with no `origin` at all is
    // not a failure — there is simply nowhere to ask.
    private static (List<string> Tags, BaselineAbsence Absence) KnownReleaseTags(string repo, StringBuilder log)
    {
        var local = Git(repo, LocalTimeoutMs, "tag", "--list", "v[0-9]*");
        var tags = local is { Ok: true }
            ? local.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(t => ReleaseTagRegex().IsMatch(t)).ToList()
            : [];
        if (tags.Count > 0)
        {
            return (tags, BaselineAbsence.None);
        }

        if (Git(repo, LocalTimeoutMs, "remote", "get-url", "origin") is not { Ok: true })
        {
            log.AppendLine("no release tag present locally and no origin remote configured — nowhere to ask");
            return ([], BaselineAbsence.NoOriginToAsk);
        }

        log.AppendLine("no release tag present locally — asking origin for the tag list");
        var remote = Git(repo, NetworkTimeoutMs, "ls-remote", "--tags", "--refs", "origin", "v*");
        if (remote is not { Ok: true })
        {
            log.AppendLine($"git ls-remote failed, so the release tag list is unknown: {remote?.Error}");
            return ([], BaselineAbsence.DiscoveryFailed);
        }

        var discovered = RemoteTagRegex().Matches(remote.Output)
            .Select(m => m.Groups["tag"].Value)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        return (discovered, discovered.Count > 0 ? BaselineAbsence.None : BaselineAbsence.NoReleaseTags);
    }

    // The newest release reachable from HEAD is the release a cutover would run against. When git
    // cannot answer that (shallow history), the highest version among the known tags is the closest
    // available stand-in.
    private static string PreviousReleaseTag(string repo, List<string> tags, StringBuilder log)
    {
        var described = Git(repo, LocalTimeoutMs, "describe", "--tags", "--abbrev=0", "--match", "v[0-9]*", "HEAD");
        string? reachable = described is { Ok: true } ? described.Output.Trim() : null;
        if (reachable is not null && ReleaseTagRegex().IsMatch(reachable))
        {
            return reachable;
        }

        log.AppendLine("no reachable tag from HEAD (shallow history) — using the highest known release tag");
        return tags.OrderByDescending(Version).First();
    }

    private static (int Major, int Minor, int Patch) Version(string tag)
    {
        var m = ReleaseTagRegex().Match(tag);
        return (int.Parse(m.Groups["major"].Value), int.Parse(m.Groups["minor"].Value), int.Parse(m.Groups["patch"].Value));
    }

    // A shallow clone knows the tag name but not its objects. Fetch exactly that tag before giving
    // up on it.
    //
    // `--depth=1` is applied ONLY to a repository that is already shallow. On a complete
    // repository the flag is destructive in the other direction: it writes a `.git/shallow`
    // boundary and truncates the history that was there, which breaks anything downstream that
    // needs full history (SCM blame in the Sonar job runs this same test suite against a complete,
    // tagless checkout). Fetching one tag ref into a complete repository is cheap anyway — the
    // objects behind it are almost entirely present already.
    private static bool EnsureTagAvailable(string repo, string tag, StringBuilder log)
    {
        if (Git(repo, LocalTimeoutMs, "rev-parse", "--verify", "--quiet", $"{tag}^{{commit}}") is { Ok: true })
        {
            return true;
        }

        var shallow = Git(repo, LocalTimeoutMs, "rev-parse", "--is-shallow-repository");
        bool isShallow = shallow is { Ok: true } && shallow.Output.Trim()
            .Equals("true", StringComparison.OrdinalIgnoreCase);

        log.AppendLine(
            $"{tag} is not present locally — fetching it explicitly"
            + (isShallow ? " (shallow repository: one commit deep)" : " (complete repository: full depth)"));

        string[] args = isShallow
            ? ["fetch", "--depth=1", "--no-tags", "origin", $"+refs/tags/{tag}:refs/tags/{tag}"]
            : ["fetch", "--no-tags", "origin", $"+refs/tags/{tag}:refs/tags/{tag}"];
        var fetch = Git(repo, NetworkTimeoutMs, args);
        if (fetch is not { Ok: true })
        {
            log.AppendLine($"git fetch of {tag} failed: {fetch?.Error}");
            return false;
        }

        if (Git(repo, LocalTimeoutMs, "rev-parse", "--verify", "--quiet", $"{tag}^{{commit}}") is { Ok: true })
        {
            return true;
        }

        log.AppendLine($"{tag} is still unavailable after an explicit fetch");
        return false;
    }

    private sealed record GitResult(bool Ok, string Output, string Error);

    private static GitResult? Git(string repo, int timeoutMs, params string[] args)
    {
        var psi = new ProcessStartInfo("git")
        {
            WorkingDirectory = repo,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (string arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        // Never let a credential helper or terminal prompt block the gate on a machine without
        // access to origin; a failed network call degrades to "no baseline", it does not hang.
        psi.Environment["GIT_TERMINAL_PROMPT"] = "0";
        psi.Environment["GIT_ASKPASS"] = "true";
        psi.Environment["GCM_INTERACTIVE"] = "never";

        try
        {
            using var process = Process.Start(psi);
            if (process is null)
            {
                return null;
            }

            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(timeoutMs))
            {
                process.Kill(entireProcessTree: true);
                return new GitResult(false, string.Empty, $"git {args[0]} timed out after {timeoutMs}ms");
            }

            return new GitResult(process.ExitCode == 0, stdout.Result, stderr.Result);
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return new GitResult(false, string.Empty, ex.Message);
        }
    }
}
