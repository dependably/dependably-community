using System.Text;
using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: every per-tenant scheduled background job or delivery worker makes an
/// <b>explicit</b> decision about whether it stops for a non-active (suspended/archived/deleting)
/// org — <see cref="Dependably.Infrastructure.TenantStatusEnforcementMiddleware"/> only sits in
/// the HTTP pipeline, so nothing that runs off a cron schedule or a channel/dispatch-queue timer
/// consults <c>orgs.status</c> on its own, and a job left silent on the question is
/// indistinguishable from a job that forgot to check.
///
/// <para>
/// Coverage is fully structural: every <c>class X : ScheduledBackgroundService</c>, every
/// <c>class X : BackgroundService</c>, and every class implementing <c>IHostedService</c> directly
/// (a one-shot startup/shutdown hook with no <c>BackgroundService</c> in its hierarchy at all,
/// matched anywhere in the base list rather than requiring it be the first token, since a class
/// can implement it alongside another interface in either order) under <c>src/</c> is found by
/// regex over <see cref="SourceRoots.AllCSharpFiles"/> — <c>ScheduledBackgroundService</c> itself
/// derives from <c>BackgroundService</c>, so the first two patterns alone already cover every
/// timer/queue-driven worker (the event-driven dispatch queues like <c>WebhookDispatchQueue</c>
/// and <c>SiemForwarderQueue</c> declare <c>: BackgroundService</c> directly and need no
/// hand-maintained name list to be covered), and the third closes the one shape those two miss: a
/// hosted service that implements <c>IHostedService</c> without going through
/// <c>BackgroundService</c> — no job in this repo is per-tenant that way today, but a future one
/// registered via <c>AddHostedService&lt;T&gt;</c> against a bare <c>IHostedService</c> now lands
/// with the same explicit-decision requirement instead of a gate that reads as comprehensive while
/// silently not looking. A new job — scheduled, event-driven, or a bare hosted service — is
/// covered the moment it lands.
/// </para>
///
/// <para>
/// A class satisfies the gate by carrying the <c>o.status = 'active'</c> SQL predicate (the
/// literal text every per-org query in this codebase already writes beside its
/// <c>o.deleted_at IS NULL</c> exclusion — see <c>TenantLifecycle</c>) or the in-process
/// <c>TenantLifecycle.IsActive(</c> call, as <b>live code</b> — comments are stripped before this
/// check runs, so a doc comment that merely describes the predicate in prose does not satisfy it.
/// The evidence may live in the job's own file, or in a collaborator file — several jobs in this
/// repo enumerate tenants through a repository method rather than issuing SQL inline, and the
/// evidence for those lives where the SQL actually is, not in the job's own file. Reaching a
/// collaborator file requires <b>two</b> matches, not one: the job's own file names a dependency
/// type (a <c>…Repository</c>/<c>…Resolver</c>/<c>…Client</c>, matched by filename, partial-class
/// files included) AND invokes a specific method on it (the <c>_field.Method(</c> convention this
/// codebase uses uniformly for injected dependencies) — only THAT method's own body (a bounded
/// window from its name onward, approximating a parser without being one) is searched for
/// evidence, not the whole collaborator file. This is what stops one job "inheriting" a suspension
/// decision that actually belongs to a different method a sibling job calls on the same shared
/// repository — an early whole-file version of this gate had exactly that hole, closed by a
/// negative control that shared a dependency between a covered job and an exempt one.
/// Absent code evidence, a <c>// suspension-ok: &lt;reason&gt;</c> marker anywhere in the job's own
/// file satisfies the gate instead — matched line by line (not a whole-file regex, so a bare
/// marker on its own line cannot be "satisfied" by unrelated code on the next line); a bare marker
/// with no reason text is rejected as malformed, same posture as every other reasoned-opt-out gate
/// in this family (<c>AuditAttributionComplianceTests.LineCarriesReasonedMarker</c>).
/// </para>
///
/// <para>
/// <b>Blind spots.</b> This is a textual presence check, not a data-flow proof: it cannot tell
/// whether the predicate actually reaches the query that matters within the method it found, or
/// whether it is applied to every per-org SELECT in a method with several (only a targeted
/// regression test, not this gate, pins per-query behavior — see
/// <c>DeprecationRefreshSuspensionTests</c>'s hosted-plane/cache-plane pair, which independently
/// exercises both of that job's queries for exactly this reason), or whether
/// <c>TenantLifecycle.IsActive(...)</c> is actually consulted before the tenant-facing side effect
/// rather than merely present in an unreachable branch — only a reviewer closes that gap, the same
/// caveat <c>OrgIdFilteringComplianceTests</c> documents for its own predicate-position check. The
/// method-window is still a heuristic, not a parser: a method whose body genuinely exceeds the
/// window could have its own evidence missed, and a very short method's window can run into a
/// neighbour's body — in practice this codebase's per-org query methods are compact enough that
/// neither has yet produced a false result, but neither is structurally impossible. It also cannot
/// judge whether an opt-out's reasoning is actually true, only that a reason was written. And an
/// intermediate base class between a job and <c>BackgroundService</c>/
/// <c>ScheduledBackgroundService</c> would be invisible to the structural regex — no such base
/// class exists for any job in this repo today. Two more, neither yet observed to have produced a
/// false result in this repo: <c>MakesExplicitDecision</c> evaluates whole-file evidence per class
/// declaration, so two covered classes declared in the same file could in principle cross-satisfy
/// each other's check — one job's real predicate read as the other's decision merely because they
/// share a file, the same shape the method-window scoping above was added to close for a shared
/// *collaborator* file, but not (yet) guarded against for a shared *job* file. And a recurring
/// timer that never becomes a <c>BackgroundService</c>/<c>ScheduledBackgroundService</c>/
/// <c>IHostedService</c> subclass at all — a raw <c>PeriodicTimer</c> or polling loop owned by a
/// plain class and started some other way, e.g. <c>LocalOsvSource.cs</c>'s refresh timer or
/// <c>InProcessDistributedLock.cs</c>'s sweep — is structurally invisible to this gate's regex
/// scan regardless of whether it is per-tenant, because the scan only looks for the three declared
/// shapes above.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class BackgroundJobSuspensionComplianceTests
{
    private readonly ITestOutputHelper _output;
    public BackgroundJobSuspensionComplianceTests(ITestOutputHelper output) => _output = output;

    [GeneratedRegex(@"\bclass\s+(?<name>\w+)\s*:\s*ScheduledBackgroundService\b")]
    private static partial Regex ScheduledBackgroundServiceSubclassRegex();

    [GeneratedRegex(@"\bclass\s+(?<name>\w+)\s*:\s*BackgroundService\b")]
    private static partial Regex BackgroundServiceSubclassRegex();

    // A class implementing IHostedService directly, without going through BackgroundService —
    // e.g. a one-shot startup/shutdown hook with its own StartAsync/StopAsync. Unlike the two
    // regexes above, IHostedService is not necessarily the token immediately after the colon: a
    // class can implement it alongside another interface in either order
    // (RedisMetadataInvalidationBus : IMetadataInvalidationBus, IHostedService), so this captures
    // the whole base-list between the colon and the opening brace (or end of line — this
    // codebase's style keeps a base list on one line) and the caller checks it for the literal
    // token rather than requiring position. A class already matched by one of the two regexes
    // above never also matches this one: BackgroundService's own declaration does not restate
    // "IHostedService" by name, it only implements it transitively.
    [GeneratedRegex(@"\bclass\s+(?<name>\w+)\s*:\s*(?<bases>[^\n{]+)")]
    private static partial Regex ClassBaseListRegex();

    [GeneratedRegex(@"o\.status\s*=\s*'active'")]
    private static partial Regex SqlPredicateRegex();

    [GeneratedRegex(@"TenantLifecycle\.IsActive\(")]
    private static partial Regex InProcessCheckRegex();

    // Dependency type names worth following into a collaborator file: repository/resolver/client
    // types are where this codebase's per-org SQL and upstream calls actually live, as opposed to
    // e.g. a *Service suffix, which would match almost every job's own type and defeat the point
    // of widening at all.
    [GeneratedRegex(@"\b([A-Z]\w*(?:Repository|Resolver|Client))\b")]
    private static partial Regex CollaboratorTypeNameRegex();

    // Method names the job's own file invokes on a field (the `_fieldName.Method(` convention this
    // codebase uses uniformly for injected dependencies) — the set of methods worth following into
    // a collaborator file, as opposed to every method that file happens to declare.
    [GeneratedRegex(@"_\w+\.(?<method>[A-Z]\w*)\s*\(")]
    private static partial Regex InvokedMethodNameRegex();

    // One of those method names occurring as a declaration-shaped token in a collaborator file —
    // "public async Task<…> MethodName(" or similar. Matched loosely (the name as a whole word
    // preceded by whitespace, not the full signature grammar) because a signature can wrap
    // multiple lines or use varying return-type shapes; precision comes from requiring the name to
    // already be in the job's own invoked-method set, not from parsing the declaration exactly.
    [GeneratedRegex(@"\bIHostedService\b")]
    private static partial Regex HostedServiceBaseRegex();

    [GeneratedRegex(@"/\*.*?\*/", RegexOptions.Singleline)]
    private static partial Regex BlockCommentRegex();

    [GeneratedRegex(@"(?<![.\w])(?<method>[A-Z]\w*)\s*\(")]
    private static partial Regex MethodNameOccurrenceRegex();

    private const string OptOutMarker = "suspension-ok:";

    // Known baseline (28 ScheduledBackgroundService/BackgroundService subclasses, 4 bare
    // IHostedService implementations) — see EveryBackgroundServiceSubclassMakesAnExplicitSuspensionDecision.
    private const int MinimumKnownJobCount = 32;

    [Fact]
    public void EveryBackgroundServiceSubclassMakesAnExplicitSuspensionDecision()
    {
        string repoRoot = SourceRoots.RepoRoot();
        var allFiles = SourceRoots.AllCSharpFiles().ToList();
        var violations = new List<string>();
        var seenClasses = new HashSet<string>(StringComparer.Ordinal);

        foreach (string file in allFiles)
        {
            string rawText = File.ReadAllText(file);
            foreach (var (className, baseType) in MatchJobDeclarations(rawText))
            {
                seenClasses.Add(className);

                bool decided = MakesExplicitDecision(
                    file, rawText, allFiles, File.ReadAllText, out string? _);
                if (decided)
                {
                    continue;
                }

                violations.Add(
                    $"{Rel(repoRoot, file)}: class {className} derives from {baseType} but makes "
                    + "no explicit suspension decision — apply the `o.status = 'active'` predicate "
                    + "(see TenantLifecycle) to its own or a collaborator repository's per-org "
                    + "selection, apply `TenantLifecycle.IsActive(...)` before its tenant-facing "
                    + "side effect, or opt out with `// suspension-ok: <reason>`.");
            }
        }

        // Sanity: the structural scan must actually find the jobs this repo is known to have
        // today, or the regex itself has regressed silently (matching nothing is a
        // green-but-blind gate). >= rather than == so a genuinely new job never trips this on its
        // own — only a regression in the regex, or a job disappearing, does.
        Assert.True(seenClasses.Count >= MinimumKnownJobCount,
            $"Structural scan for `class X : BackgroundService` / `: ScheduledBackgroundService` / "
            + "a bare `IHostedService` implementation "
            + $"found only {seenClasses.Count} class(es) "
            + $"({string.Join(", ", seenClasses.OrderBy(c => c, StringComparer.Ordinal))}); "
            + $"expected at least {MinimumKnownJobCount}. The regex may no longer be matching real "
            + "declarations, or a job class was removed — update the baseline if the removal was "
            + "deliberate.");

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail(
                $"{violations.Count} background service subclass(es) make no explicit suspension "
                + "decision. See test output for the full list.");
        }
    }

    // Every (className, baseType) declared directly against ScheduledBackgroundService,
    // BackgroundService, or bare IHostedService in one file's text. Skips an abstract declaration
    // — ScheduledBackgroundService is itself declared
    // `public abstract class ScheduledBackgroundService : BackgroundService`, which is the base
    // type this gate exists to require subclasses of, not a job in its own right; scanning it
    // as a job would demand a suspension decision that makes no sense at the abstract level.
    // Deduplicated by class name within the file: a class can only match one of the three shapes
    // in practice (see ClassBaseListRegex's own comment for why the third cannot double-count the
    // first two), but the guard costs nothing and keeps that invariant enforced rather than
    // assumed.
    private static IEnumerable<(string ClassName, string BaseType)> MatchJobDeclarations(string rawText)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (Match m in ScheduledBackgroundServiceSubclassRegex().Matches(rawText))
        {
            if (!IsAbstractDeclaration(rawText, m.Index) && seen.Add(m.Groups["name"].Value))
            {
                yield return (m.Groups["name"].Value, "ScheduledBackgroundService");
            }
        }

        foreach (Match m in BackgroundServiceSubclassRegex().Matches(rawText))
        {
            if (!IsAbstractDeclaration(rawText, m.Index) && seen.Add(m.Groups["name"].Value))
            {
                yield return (m.Groups["name"].Value, "BackgroundService");
            }
        }

        foreach (Match m in ClassBaseListRegex().Matches(rawText))
        {
            if (!IsHostedServiceBaseList(m.Groups["bases"].Value))
            {
                continue;
            }

            if (!IsAbstractDeclaration(rawText, m.Index) && seen.Add(m.Groups["name"].Value))
            {
                yield return (m.Groups["name"].Value, "IHostedService");
            }
        }
    }

    private static bool IsHostedServiceBaseList(string bases) =>
        HostedServiceBaseRegex().IsMatch(bases);

    // True when the "abstract" keyword appears on the same source line, before the match — the
    // line-local scope keeps this from ever mistaking an unrelated earlier "abstract" (e.g. in a
    // doc comment two lines up) for this declaration's own modifier.
    private static bool IsAbstractDeclaration(string text, int matchIndex)
    {
        int lineStart = text.LastIndexOf('\n', Math.Max(0, matchIndex - 1)) + 1;
        string prefix = text[lineStart..matchIndex];
        return prefix.Contains("abstract", StringComparison.Ordinal);
    }

    /// <summary>
    /// The gate's core decision function, factored out so the regression tests below can drive it
    /// against a synthetic in-memory corpus (via <paramref name="readFile"/>) instead of real
    /// files on disk. See the class doc comment for the full rule.
    /// </summary>
    private static bool MakesExplicitDecision(
        string file,
        string rawText,
        IReadOnlyList<string> allFiles,
        Func<string, string> readFile,
        out string? reason)
    {
        string strippedOwn = StripComments(rawText);
        if (HasCodeEvidence(strippedOwn))
        {
            reason = null;
            return true;
        }

        var typeNames = CollaboratorTypeNameRegex().Matches(rawText)
            .Select(m => m.Value)
            .ToHashSet(StringComparer.Ordinal);
        var methodNames = InvokedMethodNameRegex().Matches(rawText)
            .Select(m => m.Groups["method"].Value)
            .ToHashSet(StringComparer.Ordinal);

        // Both must be non-empty: a type name with no invoked method (or vice versa) gives no
        // method-scoped window to search, and widening on the type alone is exactly the hole a
        // negative control against this gate found — CacheEvictionService and DeprecationRefreshService
        // both depend on CacheArtifactRepository, but only DeprecationRefreshService's own call
        // (ListGroupsNeedingDeprecationRefreshAsync) is the one whose method body carries the
        // predicate; a whole-file OR-match let CacheEvictionService "inherit" that unrelated
        // method's evidence. Requiring the SPECIFIC invoked method's own body to carry the
        // evidence — not just any method anywhere in a same-named file — closes that.
        if (typeNames.Count > 0 && methodNames.Count > 0)
        {
            foreach (string collaboratorFile in FindCollaboratorFiles(file, typeNames, allFiles))
            {
                string collaboratorRaw = readFile(collaboratorFile);
                foreach (string methodWindow in FindMethodWindows(collaboratorRaw, methodNames))
                {
                    if (HasCodeEvidence(StripComments(methodWindow)))
                    {
                        reason = null;
                        return true;
                    }
                }
            }
        }

        reason = FindReasonedOptOut(rawText);
        return reason is not null;
    }

    // Does the (already comment-stripped) text carry live-code evidence of the check?
    private static bool HasCodeEvidence(string strippedText) =>
        SqlPredicateRegex().IsMatch(strippedText) || InProcessCheckRegex().IsMatch(strippedText);

    // Every file (excluding the job's own) whose filename stem is exactly one of the referenced
    // type names, or starts with "<TypeName>." — the partial-class naming convention this codebase
    // uses (e.g. PackageRepository.Lifecycle.cs for PackageRepository).
    private static IEnumerable<string> FindCollaboratorFiles(
        string ownFile, IReadOnlySet<string> typeNames, IReadOnlyList<string> allFiles)
    {
        foreach (string file in allFiles)
        {
            if (file == ownFile)
            {
                continue;
            }

            string stem = Path.GetFileNameWithoutExtension(file);
            foreach (string typeName in typeNames)
            {
                if (stem == typeName || stem.StartsWith(typeName + ".", StringComparison.Ordinal))
                {
                    yield return file;
                    break;
                }
            }
        }
    }

    // Bounds how far forward from a method-name occurrence this gate reads as "that method's
    // body" — long enough to comfortably cover this codebase's per-org SQL methods (typically
    // 15-40 lines / a few hundred characters of query text after the signature), short enough
    // that spilling into a sibling method stays the rare case rather than the common one. Still a
    // heuristic, not a parser: a very long method could spill its own evidence out of window, and
    // a short one could spill a neighbour's evidence in — see the class doc comment.
    private const int MethodWindowChars = 4000;

    // Yields one text window per occurrence of any of `methodNames` as a whole-word match in
    // `collaboratorText` — from the occurrence through MethodWindowChars characters (or EOF) —
    // approximating "that method's own body" without a real C# parser.
    private static IEnumerable<string> FindMethodWindows(string collaboratorText, IReadOnlySet<string> methodNames)
    {
        foreach (Match m in MethodNameOccurrenceRegex().Matches(collaboratorText))
        {
            if (!methodNames.Contains(m.Groups["method"].Value))
            {
                continue;
            }

            int len = Math.Min(MethodWindowChars, collaboratorText.Length - m.Index);
            yield return collaboratorText.Substring(m.Index, len);
        }
    }

    // Line-scoped reasoned-marker lookup — matches AuditAttributionComplianceTests.LineCarriesReasonedMarker's
    // idiom rather than a whole-file regex, so a bare marker on its own line cannot be "satisfied"
    // by unrelated code that happens to follow it (the whole-file-regex version of this gate had
    // exactly that hole: `\s*` after the marker matches a newline, so a bare `// suspension-ok:`
    // immediately followed by a class declaration read as a reasoned marker whose "reason" was the
    // declaration itself).
    private static string? FindReasonedOptOut(string rawText)
    {
        foreach (string line in rawText.Split('\n'))
        {
            if (LineCarriesReasonedMarker(line, out string? reason))
            {
                return reason;
            }
        }

        return null;
    }

    private static bool LineCarriesReasonedMarker(string line, out string? reason)
    {
        int idx = line.IndexOf(OptOutMarker, StringComparison.Ordinal);
        if (idx < 0)
        {
            reason = null;
            return false;
        }

        string rest = line[(idx + OptOutMarker.Length)..].Trim();
        if (rest.Length == 0)
        {
            reason = null;
            return false;
        }

        reason = rest;
        return true;
    }

    // Crude but sufficient comment stripper: block comments first (non-greedy, spans lines), then
    // a line comment truncates everything from the first "//" on its own line. This is a heuristic
    // scan, not a C# parser — a "//" inside a string literal would be mis-treated as a comment
    // start, but none of the patterns this gate looks for (o.status = 'active', TenantLifecycle.IsActive())
    // ever legitimately contain "//", so over-stripping cannot hide real evidence for this gate's
    // purposes; it exists solely to stop a /// doc comment's prose from satisfying the gate.
    private static string StripComments(string text)
    {
        string noBlockComments = BlockCommentRegex().Replace(text, "");

        var sb = new StringBuilder(noBlockComments.Length);
        foreach (string line in noBlockComments.Split('\n'))
        {
            int idx = line.IndexOf("//", StringComparison.Ordinal);
            sb.Append(idx >= 0 ? line[..idx] : line).Append('\n');
        }

        return sb.ToString();
    }

    private static string Rel(string root, string file) => Path.GetRelativePath(root, file);

    // ── Regression coverage: the scanner itself, proven against synthetic fixtures ──────────

    [Fact]
    public void MakesExplicitDecision_RejectsThePredicateHiddenInsideABlockComment()
    {
        // The predicate below is inside a /* */ block comment on purpose: this only proves the
        // block-comment stripper is exercised, not bypassed, by a predicate that happens to also
        // be present as prose.
        bool decided = MakesExplicitDecision(
            "/src/FooJob.cs",
            "class FooJob : ScheduledBackgroundService { /* WHERE o.deleted_at IS NULL AND o.status = 'active' */ }",
            allFiles: [],
            readFile: _ => throw new InvalidOperationException("should not read any file"),
            out _);

        Assert.False(decided);
    }

    [Fact]
    public void MakesExplicitDecision_AcceptsTheSqlPredicateAsLiveCode()
    {
        bool decided = MakesExplicitDecision(
            "/src/FooJob.cs",
            "class FooJob : ScheduledBackgroundService { }\nWHERE o.deleted_at IS NULL AND o.status = 'active'",
            allFiles: [],
            readFile: _ => throw new InvalidOperationException("should not read any file"),
            out _);

        Assert.True(decided);
    }

    [Fact]
    public void MakesExplicitDecision_RejectsTheSqlPredicateWrittenOnlyAsDocCommentProse()
    {
        // The exact hole the verifier demonstrated: DeprecationRefreshService.cs's own doc comment
        // described the predicate in prose ("/// <c>o.status = 'active'</c> predicate excluding…"),
        // with no live code anywhere in the file — the old whole-file, comment-blind regex treated
        // that prose as satisfying evidence.
        string rawText =
            "/// The <c>o.status = 'active'</c> predicate excludes a non-active org.\n"
            + "public sealed class FooJob : ScheduledBackgroundService { }";

        bool decided = MakesExplicitDecision(
            "/src/FooJob.cs",
            rawText,
            allFiles: [],
            readFile: _ => throw new InvalidOperationException("should not read any file"),
            out string? reason);

        Assert.False(decided);
        Assert.Null(reason);
    }

    [Fact]
    public void MakesExplicitDecision_FollowsACollaboratorRepositoryFileForTheRealEvidence()
    {
        // Mirrors the real DeprecationRefreshService shape: the job's own file has no SQL at all,
        // just a field of its repository dependency's type and a call to the specific method that
        // carries the predicate; the real predicate lives in that repository's own file, inside
        // that same method.
        const string jobFile = "/src/FooJob.cs";
        const string repoFile = "/src/FooRepository.cs";
        var files = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [jobFile] =
                "public sealed class FooJob : ScheduledBackgroundService\n"
                + "{\n    private readonly FooRepository _repo;\n"
                + "    private async Task RunAsync() => await _repo.ListDueAsync();\n}",
            [repoFile] =
                "public sealed class FooRepository\n"
                + "{\n    public async Task ListDueAsync()\n    {\n"
                + "        string sql = \"WHERE o.deleted_at IS NULL AND o.status = 'active'\";\n    }\n}",
        };

        bool decided = MakesExplicitDecision(
            jobFile, files[jobFile], files.Keys.ToList(), f => files[f], out _);

        Assert.True(decided);
    }

    [Fact]
    public void MakesExplicitDecision_DoesNotFollowARepositoryWhoseFileHasNoRealEvidenceEither()
    {
        const string jobFile = "/src/FooJob.cs";
        const string repoFile = "/src/FooRepository.cs";
        var files = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [jobFile] =
                "public sealed class FooJob : ScheduledBackgroundService\n"
                + "{\n    private readonly FooRepository _repo;\n"
                + "    private async Task RunAsync() => await _repo.ListDueAsync();\n}",
            [repoFile] =
                "public sealed class FooRepository\n"
                + "{\n    public async Task ListDueAsync()\n    {\n"
                + "        // no per-org predicate here at all\n    }\n}",
        };

        bool decided = MakesExplicitDecision(
            jobFile, files[jobFile], files.Keys.ToList(), f => files[f], out string? reason);

        Assert.False(decided);
        Assert.Null(reason);
    }

    /// <summary>
    /// The exact false positive a negative control against the real gate found: two jobs share a
    /// collaborator TYPE, but only one job's own invoked METHOD is the one whose body carries the
    /// predicate. The other job — which invokes a different method on the same shared repository —
    /// must not be "rescued" by evidence that belongs to a sibling method it never calls.
    /// </summary>
    [Fact]
    public void MakesExplicitDecision_DoesNotRescueAJobFromASiblingMethodOnASharedCollaborator()
    {
        const string coveredJobFile = "/src/CoveredJob.cs";
        const string exemptJobFile = "/src/ExemptJob.cs";
        const string repoFile = "/src/SharedRepository.cs";
        var files = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [coveredJobFile] =
                "public sealed class CoveredJob : ScheduledBackgroundService\n"
                + "{\n    private readonly SharedRepository _repo;\n"
                + "    private async Task RunAsync() => await _repo.ListGroupsNeedingRefreshAsync();\n}",
            [exemptJobFile] =
                "public sealed class ExemptJob : ScheduledBackgroundService\n"
                + "{\n    private readonly SharedRepository _repo;\n"
                + "    private async Task RunAsync() => await _repo.ListLruCandidatesAsync();\n}",
            [repoFile] =
                "public sealed class SharedRepository\n"
                + "{\n    public async Task ListGroupsNeedingRefreshAsync()\n    {\n"
                + "        string sql = \"WHERE o.deleted_at IS NULL AND o.status = 'active'\";\n    }\n\n"
                + "    public async Task ListLruCandidatesAsync()\n    {\n"
                + "        string sql = \"ORDER BY last_accessed_at\";\n    }\n}",
        };
        var allFiles = files.Keys.ToList();

        Assert.True(MakesExplicitDecision(
            coveredJobFile, files[coveredJobFile], allFiles, f => files[f], out _));

        bool exemptDecided = MakesExplicitDecision(
            exemptJobFile, files[exemptJobFile], allFiles, f => files[f], out string? reason);
        Assert.False(exemptDecided);
        Assert.Null(reason);
    }

    [Fact]
    public void MakesExplicitDecision_AcceptsTheInProcessCheck()
    {
        bool decided = MakesExplicitDecision(
            "/src/FooJob.cs",
            "class FooJob : BackgroundService { if (!TenantLifecycle.IsActive(org.Status)) { return; } }",
            allFiles: [],
            readFile: _ => throw new InvalidOperationException("should not read any file"),
            out _);

        Assert.True(decided);
    }

    [Fact]
    public void MakesExplicitDecision_AcceptsAReasonedOptOut()
    {
        bool decided = MakesExplicitDecision(
            "/src/FooJob.cs",
            "class FooJob : BackgroundService { }\n// suspension-ok: not per-tenant, no egress\n",
            allFiles: [],
            readFile: _ => throw new InvalidOperationException("should not read any file"),
            out string? reason);

        Assert.True(decided);
        Assert.Equal("not per-tenant, no egress", reason);
    }

    [Fact]
    public void MakesExplicitDecision_RejectsABareOptOutFollowedByUnrelatedCodeOnTheNextLine()
    {
        // The exact hole the verifier demonstrated in the opt-out marker: a whole-file regex whose
        // `\s*` after "suspension-ok:" matches a newline lets a bare marker on its own line be
        // "satisfied" by the very next line of source, which is never what a bare marker means.
        string rawText =
            "/// suspension-ok:\n"
            + "public sealed class FooJob : BackgroundService\n{\n}\n";

        bool decided = MakesExplicitDecision(
            "/src/FooJob.cs", rawText, allFiles: [],
            readFile: _ => throw new InvalidOperationException("should not read any file"),
            out string? reason);

        Assert.False(decided);
        Assert.Null(reason);
    }

    [Fact]
    public void LineCarriesReasonedMarker_RejectsABareMarkerAndAcceptsAReasonedOne()
    {
        Assert.True(LineCarriesReasonedMarker(
            $"// {OptOutMarker} scheduled sweep — no per-org axis", out string? reason));
        Assert.Equal("scheduled sweep — no per-org axis", reason);

        Assert.False(LineCarriesReasonedMarker($"// {OptOutMarker}", out _));
        Assert.False(LineCarriesReasonedMarker($"// {OptOutMarker}   ", out _));
    }

    [Fact]
    public void StripComments_RemovesLineAndBlockCommentsButKeepsLiveCode()
    {
        string stripped = StripComments(
            "WHERE o.status = 'live' // o.status = 'active'\n"
            + "/* o.status = 'active' */ AND real_code = 1");

        Assert.DoesNotContain("'active'", stripped);
        Assert.Contains("real_code = 1", stripped);
    }

    [Fact]
    public void ScheduledBackgroundServiceSubclassRegex_MatchesARealDeclaration()
    {
        var m = ScheduledBackgroundServiceSubclassRegex().Match(
            "public sealed class FooService : ScheduledBackgroundService\n{\n}");
        Assert.True(m.Success);
        Assert.Equal("FooService", m.Groups["name"].Value);
    }

    [Fact]
    public void BackgroundServiceSubclassRegex_MatchesADirectDeclarationWithTrailingInterfaces()
    {
        var m = BackgroundServiceSubclassRegex().Match(
            "public sealed class FooQueue : BackgroundService, IPackageEventSink\n{\n}");
        Assert.True(m.Success);
        Assert.Equal("FooQueue", m.Groups["name"].Value);
    }

    [Fact]
    public void BackgroundServiceSubclassRegex_DoesNotDoubleMatchAScheduledBackgroundServiceSubclass()
    {
        // ScheduledBackgroundService itself derives from BackgroundService, but a class declared
        // "class X : ScheduledBackgroundService" must be counted once, via the Scheduled regex
        // only — the direct-BackgroundService regex requires the token immediately after the
        // colon to be BackgroundService, which this text does not contain.
        string text = "public sealed class FooJob : ScheduledBackgroundService\n{\n}";
        Assert.DoesNotMatch(BackgroundServiceSubclassRegex(), text);
        Assert.Matches(ScheduledBackgroundServiceSubclassRegex(), text);
    }

    [Fact]
    public void MatchJobDeclarations_FindsABareIHostedServiceImplementation()
    {
        var found = MatchJobDeclarations(
            "public sealed class FooStartupHook : IHostedService\n{\n}").ToList();

        Assert.Single(found);
        Assert.Equal(("FooStartupHook", "IHostedService"), found[0]);
    }

    [Fact]
    public void MatchJobDeclarations_FindsIHostedServiceRegardlessOfItsPositionInTheBaseList()
    {
        // RedisMetadataInvalidationBus's real shape: IHostedService is the SECOND interface, not
        // the token immediately after the colon — the two BackgroundService-family regexes above
        // require exactly that position, which is why this needs its own, position-independent match.
        var found = MatchJobDeclarations(
            "public sealed class FooBus : IFooBus, IHostedService\n{\n}").ToList();

        Assert.Single(found);
        Assert.Equal(("FooBus", "IHostedService"), found[0]);
    }

    [Fact]
    public void MatchJobDeclarations_DoesNotDoubleCountAClassAlreadyMatchedAsABackgroundServiceSubclass()
    {
        // A class declared "class X : BackgroundService" never also re-states "IHostedService" by
        // name (it implements it transitively), so this is a defensive proof of the dedup guard
        // rather than a real-world collision this repo has ever hit.
        var found = MatchJobDeclarations(
            "public sealed class FooQueue : BackgroundService, IHostedService\n{\n}").ToList();

        Assert.Single(found);
        Assert.Equal("BackgroundService", found[0].BaseType);
    }
}
