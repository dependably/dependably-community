using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check enforcing that the <c>publish-image</c> job in <c>.gitlab-ci.yml</c> actually
/// routes the three base images (<c>NODE_IMAGE</c>/<c>SDK_IMAGE</c>/<c>RUNTIME_IMAGE</c>) through
/// the private-registry mirror, in lockstep with the <c>ARG</c> defaults declared in
/// <c>Dockerfile</c>/<c>Dockerfile.edge</c>. Three distinct failure modes are checked, because
/// each leaves a different piece of the chain intact and would otherwise pass silently:
///
/// <list type="bullet">
/// <item><b>Digest drift</b> — the mirrored assignment and the Dockerfile <c>ARG</c> default
/// name different digests for the same image. <c>publish-image</c> always overrides the ARG, so
/// the Dockerfile defaults are never what actually builds on main/release pipelines — but the two
/// must still agree, because the defaults are what a local <c>docker compose up --build</c>, a
/// fork build, and the GitHub Actions workflow (no mirror access) actually resolve.
/// Base-image bumps are applied by hand, so updating one location and not the other produces no
/// other signal — the build still succeeds, just on a base the repository does not declare.</item>
/// <item><b>Unwired build-arg</b> — the mirrored shell variable is assigned but never passed to
/// <c>docker buildx build</c> via <c>--build-arg &lt;NAME&gt;=</c>. The Dockerfile ARG default
/// (a public registry ref) then silently wins even though the mirrored value looks correct in
/// the script.</item>
/// <item><b>Bypassed mirror</b> — the mirrored assignment points at the same digest but the
/// original public host (<c>mcr.microsoft.com</c>/<c>docker.io</c>) instead of
/// <c>${DEP_IMAGE_REGISTRY}/…</c>, so the digest-equality check alone would pass while completely
/// defeating the purpose of routing the pull through the mirror.</item>
/// </list>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class DockerBaseImageMirrorComplianceTests
{
    private readonly ITestOutputHelper _output;
    public DockerBaseImageMirrorComplianceTests(ITestOutputHelper output) => _output = output;

    private static readonly string[] ImageArgNames = { "NODE_IMAGE", "SDK_IMAGE", "RUNTIME_IMAGE" };

    private const string MirrorPrefix = "${DEP_IMAGE_REGISTRY}/";

    [GeneratedRegex(@"^ARG\s+(NODE_IMAGE|SDK_IMAGE|RUNTIME_IMAGE)=\S*@(sha256:[0-9a-f]{64})\s*$")]
    private static partial Regex DockerfileArgPattern();

    // Captures the ref (everything before "@sha256:...") separately from the digest so the
    // mirror-prefix check can inspect the ref without re-deriving it from the digest match.
    [GeneratedRegex(@"(NODE_IMAGE|SDK_IMAGE|RUNTIME_IMAGE)=""(\S*)@(sha256:[0-9a-f]{64})""")]
    private static partial Regex GitlabCiAssignmentPattern();

    [GeneratedRegex(@"--build-arg\s+(NODE_IMAGE|SDK_IMAGE|RUNTIME_IMAGE)=")]
    private static partial Regex GitlabCiBuildArgWiringPattern();

    private sealed record GitlabCiAssignment(string Ref, string Digest);

    [Fact]
    public void PublishImageMirrorsBaseImagesInLockstepWithDockerfileDefaults()
    {
        string repoRoot = SourceRoots.RepoRoot();

        string dockerfilePath = Path.Combine(repoRoot, "Dockerfile");
        string dockerfileEdgePath = Path.Combine(repoRoot, "Dockerfile.edge");
        string gitlabCiPath = Path.Combine(repoRoot, ".gitlab-ci.yml");

        var violations = new List<string>();

        var dockerfileDigests = ExtractDockerfileArgDigests(dockerfilePath, violations);
        var dockerfileEdgeDigests = ExtractDockerfileArgDigests(dockerfileEdgePath, violations);
        var publishImageLines = ExtractPublishImageJobLines(gitlabCiPath);
        var gitlabCiAssignments = ExtractGitlabCiAssignments(publishImageLines, gitlabCiPath, violations);
        var wiredNames = ExtractWiredBuildArgNames(publishImageLines);

        foreach (string name in ImageArgNames)
        {
            bool haveDockerfile = dockerfileDigests.TryGetValue(name, out string? dockerfileDigest);
            bool haveDockerfileEdge = dockerfileEdgeDigests.TryGetValue(name, out string? dockerfileEdgeDigest);
            bool haveGitlabCi = gitlabCiAssignments.TryGetValue(name, out var assignment);

            if (!haveDockerfile)
            {
                violations.Add($"{name}: no `ARG {name}=...@sha256:...` default found in {RelPath(repoRoot, dockerfilePath)}.");
                continue;
            }

            if (!haveDockerfileEdge)
            {
                violations.Add($"{name}: no `ARG {name}=...@sha256:...` default found in {RelPath(repoRoot, dockerfileEdgePath)}.");
                continue;
            }

            if (!haveGitlabCi)
            {
                violations.Add($"{name}: no `{name}=\"...@sha256:...\"` mirrored assignment found in the " +
                                $"publish-image job of {RelPath(repoRoot, gitlabCiPath)}.");
                continue;
            }

            if (!string.Equals(dockerfileDigest, dockerfileEdgeDigest, StringComparison.Ordinal))
            {
                violations.Add(
                    $"{name}: DIGEST DRIFT — Dockerfile default is {dockerfileDigest} but Dockerfile.edge " +
                    $"default is {dockerfileEdgeDigest} — the two Dockerfiles must pin the same digest for {name}.");
            }

            if (!string.Equals(dockerfileDigest, assignment!.Digest, StringComparison.Ordinal))
            {
                violations.Add(
                    $"{name}: DIGEST DRIFT — Dockerfile ARG default is {dockerfileDigest} but the publish-image " +
                    $"mirrored assignment in .gitlab-ci.yml carries {assignment.Digest}. Update both to the same " +
                    $"digest (bump the ARG default in Dockerfile and Dockerfile.edge, and the matching mirrored " +
                    $"assignment in the publish-image job).");
            }

            if (!assignment.Ref.StartsWith(MirrorPrefix, StringComparison.Ordinal))
            {
                violations.Add(
                    $"{name}: MIRROR BYPASSED — the publish-image assignment `{name}=\"{assignment.Ref}@{assignment.Digest}\"` " +
                    $"does not start with `{MirrorPrefix}`, so it resolves straight to the public registry instead of the " +
                    $"private-registry mirror. Rewrite the ref to `{MirrorPrefix}<flattened-path>:<tag>@{assignment.Digest}`.");
            }

            if (!wiredNames.Contains(name))
            {
                violations.Add(
                    $"{name}: UNWIRED BUILD-ARG — the publish-image job assigns `{name}` but never passes it to " +
                    $"`docker buildx build` via `--build-arg {name}=\"${name}\"`. Without that flag the Dockerfile's " +
                    $"public-registry ARG default silently wins and the mirror is never used.");
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} base-image mirror-lockstep violation(s) between Dockerfile/Dockerfile.edge " +
                        $"and the publish-image job. See test output for the full list.");
        }
    }

    /// <summary>
    /// Fail-closed on a duplicate <c>ARG</c> declaration for the same name with a different
    /// digest: silently taking the last match would let a stale second declaration (e.g. a
    /// leftover from a botched merge) shadow the one actually being checked below.
    /// </summary>
    private static Dictionary<string, string> ExtractDockerfileArgDigests(string path, List<string> violations)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in File.ReadAllLines(path))
        {
            var m = DockerfileArgPattern().Match(line);
            if (!m.Success)
            {
                continue;
            }

            string name = m.Groups[1].Value;
            string digest = m.Groups[2].Value;
            if (result.TryGetValue(name, out string? existing) && !string.Equals(existing, digest, StringComparison.Ordinal))
            {
                violations.Add($"{name}: AMBIGUOUS — {Path.GetFileName(path)} declares `ARG {name}` more than once " +
                                $"with different digests ({existing} vs {digest}). Remove the duplicate so there's " +
                                $"exactly one value to check.");
            }

            result[name] = digest;
        }

        return result;
    }

    /// <summary>
    /// Every line inside the <c>publish-image</c> job block: the job's key is a top-level
    /// (unindented) YAML key, so the block runs from that line until the next unindented key.
    /// </summary>
    private static List<string> ExtractPublishImageJobLines(string path)
    {
        var lines = new List<string>();
        bool inPublishImageJob = false;
        foreach (string line in File.ReadAllLines(path))
        {
            if (line.StartsWith("publish-image:", StringComparison.Ordinal))
            {
                inPublishImageJob = true;
                lines.Add(line);
                continue;
            }

            if (inPublishImageJob && line.Length > 0 && !char.IsWhiteSpace(line[0]))
            {
                inPublishImageJob = false;
            }

            if (inPublishImageJob)
            {
                lines.Add(line);
            }
        }

        return lines;
    }

    /// <summary>
    /// Fail-closed on a duplicate mirrored assignment for the same name with a different ref or
    /// digest, for the same reason as <see cref="ExtractDockerfileArgDigests"/>.
    /// </summary>
    private static Dictionary<string, GitlabCiAssignment> ExtractGitlabCiAssignments(
        IEnumerable<string> publishImageLines, string path, List<string> violations)
    {
        var result = new Dictionary<string, GitlabCiAssignment>(StringComparer.Ordinal);
        foreach (string line in publishImageLines)
        {
            var m = GitlabCiAssignmentPattern().Match(line);
            if (!m.Success)
            {
                continue;
            }

            string name = m.Groups[1].Value;
            var candidate = new GitlabCiAssignment(m.Groups[2].Value, m.Groups[3].Value);
            if (result.TryGetValue(name, out var existing) && existing != candidate)
            {
                violations.Add($"{name}: AMBIGUOUS — the publish-image job of {Path.GetFileName(path)} assigns " +
                                $"`{name}` more than once with different values ({existing.Ref}@{existing.Digest} " +
                                $"vs {candidate.Ref}@{candidate.Digest}). Remove the duplicate so there's exactly " +
                                $"one value to check.");
            }

            result[name] = candidate;
        }

        return result;
    }

    /// <summary>
    /// Every image name actually passed to the <c>docker buildx build</c> invocation via
    /// <c>--build-arg &lt;NAME&gt;=</c>. Scoped to just that invocation's lines (not the whole
    /// <c>publish-image</c> block) so a comment or an <c>echo</c> mentioning the flag elsewhere in
    /// the job — e.g. the prose comment above the mirrored assignments — cannot satisfy the check;
    /// only the flags the build command itself actually receives count. The invocation is found by
    /// a "starts with" match (not exact-equals) so this also survives the folded <c>&gt;-</c> YAML
    /// scalar being collapsed onto a single physical line by a future reformat, and
    /// <see cref="Regex.Matches(string)"/> (not <see cref="Regex.Match(string)"/>) is used so every
    /// <c>--build-arg</c> flag on that line is counted, not just the first.
    /// </summary>
    private static HashSet<string> ExtractWiredBuildArgNames(List<string> publishImageLines)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);

        int startIndex = -1;
        for (int i = 0; i < publishImageLines.Count; i++)
        {
            if (publishImageLines[i].TrimStart().StartsWith("docker buildx build", StringComparison.Ordinal))
            {
                startIndex = i;
                break;
            }
        }

        if (startIndex < 0)
        {
            return result;
        }

        string anchorLine = publishImageLines[startIndex];
        int blockIndent = anchorLine.Length - anchorLine.TrimStart().Length;

        for (int i = startIndex; i < publishImageLines.Count; i++)
        {
            string line = publishImageLines[i];
            string trimmed = line.TrimStart();
            int indent = line.Length - trimmed.Length;

            if (i > startIndex && indent < blockIndent)
            {
                // A shallower-indented line is the next script bullet — the invocation ended.
                break;
            }

            if (trimmed.StartsWith('#'))
            {
                continue;
            }

            foreach (Match m in GitlabCiBuildArgWiringPattern().Matches(line))
            {
                result.Add(m.Groups[1].Value);
            }
        }

        return result;
    }

    private static string RelPath(string root, string file) => Path.GetRelativePath(root, file);
}
