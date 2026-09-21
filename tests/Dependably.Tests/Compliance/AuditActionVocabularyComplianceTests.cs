using System.Text;
using System.Text.RegularExpressions;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// <c>audit_log.action</c> is one vocabulary with two ends, and for most of this project's life
/// nothing held them together. The writers were ~160 string literals at their call sites; the
/// readers — the SIEM feed's default filter and the CEF name/severity table — were separate
/// hand-written lists. Three failures followed from the same absence, and all three shipped:
/// <list type="bullet">
/// <item>the same event written under two names (<c>project.create</c> at one call site,
/// <c>project.created</c> at another), so a consumer filtering either one silently missed half of
/// them;</item>
/// <item>a default filter advertising <c>token.</c> and <c>rbac.</c> families that no writer has
/// ever emitted — the real names are <c>token_created</c> and <c>member_role_changed</c> — so a
/// collector trusting the default believed it had credential and RBAC coverage and had neither;</item>
/// <item>a CEF table mapping those same phantom names, leaving the real events to fall through to
/// the raw action string and the lowest severity.</item>
/// </list>
///
/// <para>
/// This gate binds the ends together against <see cref="AuditActions"/>: every action a writer
/// names must be declared, every declared action must have a writer, and every name the CEF table
/// maps must be one of them. None of it is visible at runtime — a wrong name writes and serves
/// perfectly, it is just never the name anybody asked for.
/// </para>
///
/// <para>
/// <b>Blind spots, stated.</b> The scan resolves an action argument that is a string literal (a
/// ternary of literals included) or a <c>const string</c> reference; anything else — a local, a
/// property, a parameter threaded in from a caller — it cannot see, and demands a
/// <c>// audit-action-ok: &lt;reason&gt;</c> marker for instead, so the hole is a reviewed line
/// rather than a silence. The <em>declared-has-a-writer</em> direction is weaker still: it proves
/// the name appears as a literal somewhere in <c>src/</c> outside the files that consume the
/// vocabulary, not that the write is reachable. A name reachable only through dead code passes.
/// </para>
///
/// <para>Opt-out: <c>// audit-action-ok: &lt;reason&gt;</c> within the 5 lines above the call. A
/// bare marker with no stated reason is malformed and is never honoured.</para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class AuditActionVocabularyComplianceTests
{
    private const string OptOut = "audit-action-ok:";
    private const int MarkerWindow = 5;

    /// <summary>
    /// Files that read the vocabulary rather than write it. They are excluded from the
    /// "some writer mentions this name" scan, because a name mentioned only by its own
    /// declaration or by the CEF table it feeds is exactly the dead entry that check exists to
    /// find — <c>token.created</c> sat in <c>CefFormat</c> for releases with no writer anywhere.
    /// </summary>
    private static readonly string[] VocabularyConsumerFiles =
    [
        "AuditActions.cs",
        "CefFormat.cs",
        "SiemController.cs",
    ];

    /// <summary>
    /// <c>AuditRepository</c> declares <c>LogAsync</c>/<c>LogSystemAsync</c>, so the call-site
    /// scanner would read their parameter lists as call arguments.
    /// </summary>
    private const string WriterDeclaringFile = "AuditRepository.cs";

    private readonly ITestOutputHelper _output;

    public AuditActionVocabularyComplianceTests(ITestOutputHelper output) => _output = output;

    [GeneratedRegex(@"\bLog(?:System)?Async\s*\(")]
    private static partial Regex AuditWriteRegex();

    [GeneratedRegex(@"\bconst\s+string\s+(?<name>\w+)\s*=\s*""(?<value>[^""\\]*)""\s*;")]
    private static partial Regex ConstStringRegex();

    [GeneratedRegex(@"""(?<literal>[^""\\\r\n]*)""")]
    private static partial Regex StringLiteralRegex();

    // A CEF switch arm: `"login.failure" => "Login Failure",` / `"login.failure" => SeverityMedium,`.
    [GeneratedRegex(@"^\s*""(?<action>[^""\\]+)""\s*=>")]
    private static partial Regex CefSwitchArmRegex();

    // ── The writers ──────────────────────────────────────────────────────────

    [Fact]
    public void EveryActionAWriterNamesIsDeclaredInTheVocabulary()
    {
        var consts = BuildConstMap();
        var undeclared = new List<string>();
        var unresolved = new List<string>();

        foreach (var site in EnumerateWriteSites())
        {
            var names = ResolveActionNames(site.ActionArgument, consts);
            if (names.Count == 0)
            {
                if (!HasReasonedOptOutAbove(site.Lines, site.LineIndex))
                {
                    unresolved.Add(
                        $"{site.RelativePath}:{site.LineIndex + 1}: action argument " +
                        $"`{Condense(site.ActionArgument)}` is not a literal or a const this gate " +
                        $"can resolve — annotate `// {OptOut} <reason>` naming the declared " +
                        "action(s) it carries.");
                }

                continue;
            }

            foreach (string name in names.Where(n => !AuditActions.IsDeclared(n)))
            {
                undeclared.Add(
                    $"{site.RelativePath}:{site.LineIndex + 1}: writes '{name}', which is not in " +
                    "AuditActions.All — declare it (security set or operational set) so a " +
                    "collector can discover and subscribe to it.");
            }
        }

        Report(undeclared.Concat(unresolved).ToList(),
            "audit action write(s) outside the declared vocabulary");
    }

    [Fact]
    public void EveryDeclaredActionIsNamedBySomeWriter()
    {
        var literals = new HashSet<string>(StringComparer.Ordinal);
        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            if (VocabularyConsumerFiles.Contains(Path.GetFileName(file), StringComparer.Ordinal))
            {
                continue;
            }

            foreach (Match m in StringLiteralRegex().Matches(File.ReadAllText(file)))
            {
                literals.Add(m.Groups["literal"].Value);
            }
        }

        Assert.NotEmpty(literals);

        var orphans = AuditActions.All
            .Where(a => !literals.Contains(a))
            .Select(a =>
                $"'{a}' is declared in AuditActions but appears as a literal nowhere in src/ " +
                "outside the vocabulary's own consumers — either a writer was renamed and the " +
                "declaration was not, or the entry never had one. A declared action nothing " +
                "writes reads as coverage on the /api/v1/siem/actions catalogue.")
            .ToList();

        Report(orphans, "declared action(s) with no writer");
    }

    // ── The readers ──────────────────────────────────────────────────────────

    [Fact]
    public void EveryActionTheCefTableMapsIsOneAWriterEmits()
    {
        string cefPath = SourceRoots.AllCSharpFiles()
            .Single(f => Path.GetFileName(f) == "CefFormat.cs");

        var mapped = new HashSet<string>(StringComparer.Ordinal);
        foreach (string line in File.ReadAllLines(cefPath))
        {
            var m = CefSwitchArmRegex().Match(line);
            if (m.Success)
            {
                mapped.Add(m.Groups["action"].Value);
            }
        }

        Assert.NotEmpty(mapped);

        var phantom = mapped
            .Where(a => !AuditActions.IsDeclared(a))
            .OrderBy(a => a, StringComparer.Ordinal)
            .Select(a =>
                $"CefFormat maps '{a}', which is not in AuditActions.All. The mapping is not " +
                "merely unused: it reads as coverage while the real event falls through to the " +
                "raw action name and the default severity.")
            .ToList();

        Report(phantom, "CEF mapping(s) for actions nothing writes");
    }

    [Fact]
    public void TheDefaultFilterSetIsDeclaredLeafNamesWithinTheBindCap()
    {
        Assert.NotEmpty(AuditActions.DefaultFilters);

        var problems = new List<string>();

        foreach (string filter in AuditActions.DefaultFilters
            .Where(f => !AuditActions.IsDeclared(AuditActions.NormalizeFilter(f))))
        {
            problems.Add(
                $"default filter '{filter}' is not a declared action name — and a family prefix " +
                "is not one either, because the default feed binds exact names. A default entry " +
                "with nothing under it is what shipped `token.` and `rbac.`: a collector reads " +
                "the default as coverage and receives nothing.");
        }

        // AuditRepository.BuildActionPredicate skips the family LIKE term on the default path,
        // which is only sound while no default entry is the root of a family: a declared action
        // extending one would be silently absent from the no-filter feed.
        foreach (string filter in AuditActions.DefaultFilters.Select(AuditActions.NormalizeFilter))
        {
            foreach (string other in AuditActions.All.Where(
                a => a.StartsWith(filter + ".", StringComparison.Ordinal)))
            {
                problems.Add(
                    $"default filter '{filter}' is a family root of declared action '{other}' — " +
                    $"the default feed binds exact names only, so '{other}' would not be served. " +
                    "Name it in the default set directly.");
            }
        }

        Report(problems, "default filter-set defect(s)");
    }

    [Fact]
    public void NoDeclaredActionSitsUnderAnotherDeclaredAction()
    {
        // The whole family-term elision rests on this and nothing else. AuditActions.IsDeclaredLeaf
        // answers correctly either way — it checks for declared children rather than assuming there
        // are none — but the day someone declares both `saml.config` and `saml.config.updated`,
        // `action=saml.config` stops serving `saml.config.updated` through the IN half and starts
        // needing the LIKE half back, and the two caps stop meaning what OPERATIONS.md says they
        // mean. That is a conversation to have deliberately, not a behaviour to discover from a
        // collector's missing events, so it fails here first.
        var problems = new List<string>();

        foreach (string action in AuditActions.All)
        {
            foreach (string child in AuditActions.All.Where(
                other => other.StartsWith(action + ".", StringComparison.Ordinal)))
            {
                problems.Add(
                    $"declared action '{action}' is a dotted ancestor of declared action " +
                    $"'{child}'. The auth feed omits the family LIKE term for a declared leaf, so " +
                    $"a caller filtering on '{action}' would no longer receive '{child}' — and " +
                    "the family filter count would no longer be bounded by the implied-family " +
                    "count. Declare the family root in ImpliedFamilyPrefixes' place, or name " +
                    $"'{child}' by a spelling that is not under '{action}'.");
            }
        }

        Report(problems, "declared-ancestor defect(s)");
    }

    [Fact]
    public void TheTwoFilterCapsComposeToCoverEveryValueACallerCanSend()
    {
        // The two caps are published as independent budgets and a caller reads them that way, so
        // they have to compose: every declared action AND a full complement of families has to be
        // sendable, or the better subscription (pin the vocabulary, keep the families for what the
        // next release adds) is the one that 400s. Lowering either bound alone breaks that.
        Assert.True(
            AuditRepository.MaxAuthEventActionFilters
                >= AuditActions.All.Length + AuditRepository.MaxAuthEventFamilyFilters,
            $"The total cap is {AuditRepository.MaxAuthEventActionFilters}, below the " +
            $"{AuditActions.All.Length} declared actions plus the " +
            $"{AuditRepository.MaxAuthEventFamilyFilters} families a caller may name together. A " +
            "collector pinning the whole vocabulary and keeping one family prefix would be " +
            "rejected by a bound that exists to protect the driver, not to curate subscriptions.");

        // Which makes the family cap the gate that actually answers. Only declared actions are
        // free and there are exactly All.Length of them, so any list longer than
        // All.Length + MaxAuthEventFamilyFilters necessarily carries more non-declared values than
        // the family cap allows and is refused there first. Stated here so that a later change
        // raising the total cap for headroom does not read as opening a second budget.
        Assert.True(
            AuditRepository.MaxAuthEventActionFilters
                <= AuditActions.All.Length + AuditRepository.MaxAuthEventFamilyFilters,
            $"The total cap is {AuditRepository.MaxAuthEventActionFilters}, above the " +
            $"{AuditActions.All.Length + AuditRepository.MaxAuthEventFamilyFilters} distinct " +
            "values the family cap already permits. The excess is unreachable, so the constant " +
            "would publish a limit no request can hit — pick the composition, or drop the cap.");
    }

    [Fact]
    public void ImpliedFamilyPrefixesAreExactlyTheFamiliesTheVocabularyImpliesAndDeclaresNowhere()
    {
        // This list is not decoration: its length is AuditRepository.MaxAuthEventFamilyFilters,
        // the bound on the only half of the auth feed's filter list with a measured per-filter
        // cost. A derivation that drifted from the vocabulary would move that bound silently.
        // Asserted as properties rather than by recomputing the same expression: a mirror of the
        // derivation catches an edit to one copy, never a misconception shared by both.
        var problems = new List<string>();
        var listed = AuditActions.ImpliedFamilyPrefixes.ToHashSet(StringComparer.Ordinal);

        foreach (string family in AuditActions.ImpliedFamilyPrefixes)
        {
            if (AuditActions.IsDeclared(family))
            {
                problems.Add(
                    $"'{family}' is listed as an implied family and is also a declared action. The " +
                    "two lists are published side by side as what a filter can name, and the caps " +
                    "assume they partition that — a value in both is counted once and budgeted twice.");
            }

            if (!AuditActions.All.Any(a => a.StartsWith(family + ".", StringComparison.Ordinal)))
            {
                problems.Add(
                    $"'{family}' is listed as an implied family but no declared action sits under " +
                    "it — the family bound would be padded by a value no collector has reason to send.");
            }
        }

        // Completeness in the other direction: every family a caller could reach for by truncating
        // a declared action at a dot is either itself declared or listed.
        foreach (string action in AuditActions.All)
        {
            for (int i = action.IndexOf('.'); i >= 0; i = action.IndexOf('.', i + 1))
            {
                string prefix = action[..i];
                if (!AuditActions.IsDeclared(prefix) && !listed.Contains(prefix))
                {
                    problems.Add(
                        $"'{prefix}' is a dotted family implied by declared action '{action}' but " +
                        "ImpliedFamilyPrefixes omits it — a caller can filter on it, so it belongs " +
                        "to the count that bounds them.");
                }
            }
        }

        Assert.NotEmpty(AuditActions.ImpliedFamilyPrefixes);
        Report(problems, "implied-family-prefix defect(s)");
    }

    [Fact]
    public void IsDeclaredLeafIsTrueOnlyForADeclaredActionWithNothingDeclaredUnderIt()
    {
        // AuditRepository.BuildActionPredicate omits a filter's family LIKE term exactly when this
        // returns true, so a wrong answer here is a silently absent event rather than a failure:
        // eliding the term for an action that DOES have declared children would stop serving them.
        var problems = new List<string>();

        foreach (string action in AuditActions.All)
        {
            bool hasDeclaredChildren = AuditActions.All.Any(
                other => other.StartsWith(action + ".", StringComparison.Ordinal));

            if (AuditActions.IsDeclaredLeaf(action) == hasDeclaredChildren)
            {
                problems.Add(
                    $"IsDeclaredLeaf(\"{action}\") returned {AuditActions.IsDeclaredLeaf(action)} " +
                    $"while {(hasDeclaredChildren ? "at least one declared action sits under it" : "nothing is declared under it")}. " +
                    "The family LIKE term is skipped on this answer.");
            }
        }

        foreach (string family in AuditActions.ImpliedFamilyPrefixes)
        {
            if (AuditActions.IsDeclaredLeaf(family))
            {
                problems.Add(
                    $"'{family}' is a family root but reads as a declared leaf — its LIKE term " +
                    "would be skipped and the family would serve nothing.");
            }
        }

        // A name outside the vocabulary is never a leaf: a collector filtering on an action a
        // newer build writes still has to get the family term.
        Assert.False(AuditActions.IsDeclaredLeaf("zzz_not_in_this_release"));

        Report(problems, "declared-leaf defect(s)");
    }

    [Fact]
    public void TheVocabularyIsOneListWithNoDuplicates()
    {
        var duplicates = AuditActions.All
            .GroupBy(a => a, StringComparer.Ordinal)
            .Where(g => g.Count() > 1)
            .Select(g => $"'{g.Key}' is declared {g.Count()} times")
            .ToList();

        Report(duplicates, "duplicate vocabulary entr(ies)");

        // The two groups partition the vocabulary: an action is served by the no-filter default or
        // it is not, and an entry in both would make the catalogue's security_relevant flag depend
        // on which list won.
        Assert.Equal(
            AuditActions.All.Length,
            AuditActions.All.Count(AuditActions.IsSecurityRelevant)
                + AuditActions.All.Count(a => !AuditActions.IsSecurityRelevant(a)));
    }

    [Fact]
    public void EveryOptOutMarkerCarriesAStatedReason()
    {
        var malformed = new List<string>();

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                int at = lines[i].IndexOf(OptOut, StringComparison.OrdinalIgnoreCase);
                if (at >= 0 && lines[i][(at + OptOut.Length)..].Trim().Length < 10)
                {
                    malformed.Add(
                        $"{Path.GetRelativePath(SourceRoots.OwningRoot(file), file)}:{i + 1}: " +
                        lines[i].Trim());
                }
            }
        }

        Report(malformed, $"`{OptOut}` marker(s) with no stated reason");
    }

    // ── Self-tests: the scanner and the match rule see the real shapes ────────

    [Fact]
    public void Scanner_FindsTheRealCallShapesAndNotThePhrasesAboutThem()
    {
        var consts = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal)
        {
            ["TypeEnrolled"] = ["mfa.enrolled"],
            ["Ambiguous"] = ["a.one", "a.two"],
        };

        Assert.Equal(
            new[] { "login.success" },
            ResolveActionNames("\"login.success\"", consts).ToArray());
        Assert.Equal(
            new[] { "project.version_reinstated", "project.version_retired" },
            ResolveActionNames(
                "updated.IsActive ? \"project.version_reinstated\" : \"project.version_retired\"",
                consts).OrderBy(x => x, StringComparer.Ordinal).ToArray());
        Assert.Equal(
            new[] { "mfa.enrolled" },
            ResolveActionNames("MfaEvents.TypeEnrolled", consts).ToArray());

        // A name that resolves two ways is treated as unresolved rather than guessed at.
        Assert.Empty(ResolveActionNames("SomeType.Ambiguous", consts));
        Assert.Empty(ResolveActionNames("request.AuditAction", consts));
        Assert.Empty(ResolveActionNames("key.Action", consts));
    }

    [Fact]
    public void Scanner_ReadsTheActionArgumentThroughTheConnectionOverloadAndNamedArguments()
    {
        string[] lines =
        [
            "await _audit.LogSystemAsync(conn, tx, \"tenant.hard_deleted\", actorId: a, ct: ct);",
            "await _audit.LogAsync(orgId: orgId, action: \"token_created\", ct: ct);",
        ];

        var sites = EnumerateWriteSitesIn(lines, "fake.cs").ToList();
        Assert.Equal(2, sites.Count);
        Assert.Equal("\"tenant.hard_deleted\"", sites[0].ActionArgument);
        Assert.Equal("\"token_created\"", sites[1].ActionArgument);
    }

    [Fact]
    public void MatchRule_ReachesAFlatNameExactlyAndAFamilyByItsRoot()
    {
        // The bug this vocabulary exists around: every filter pattern used to be `<value>.%`, so a
        // dot-free action could not be matched by any value a caller could send.
        Assert.True(AuditActions.Matches("checksum_failure", "checksum_failure"));
        Assert.True(AuditActions.Matches("login.", "login.success"));
        Assert.True(AuditActions.Matches("login", "login.success"));
        Assert.True(AuditActions.Matches("auth", "auth.saml.login.failure"));

        // A family root is a dotted prefix, never a substring: `login` must not sweep in `logins.*`.
        Assert.False(AuditActions.Matches("login", "logins.not_a_family"));
        Assert.False(AuditActions.Matches("token_created", "token_created_v2"));
        Assert.False(AuditActions.Matches("checksum_failure", "checksum_failures"));

        // A declared leaf carries no family half — the rule states what the SQL implements, and
        // AuditRepository.BuildActionPredicate omits the LIKE term for exactly these names.
        // An undeclared filter keeps it, so a collector naming an action from a newer release
        // still matches that action's family.
        Assert.False(AuditActions.Matches("checksum_failure", "checksum_failure.extra"));
        Assert.False(AuditActions.Matches("token_created.", "token_created.v2"));
        Assert.True(AuditActions.Matches("zzz_future", "zzz_future.event"));
    }

    [Fact]
    public void OptOutMarkerRequiresAReason()
    {
        Assert.True(HasReasonedOptOutAbove([$"// {OptOut} the declared push action", "call();"], 1));
        Assert.False(HasReasonedOptOutAbove([$"// {OptOut}", "call();"], 1));
        Assert.False(HasReasonedOptOutAbove(["call();"], 0));
    }

    // ── Scanner ──────────────────────────────────────────────────────────────

    private sealed record WriteSite(
        string RelativePath, string[] Lines, int LineIndex, string ActionArgument);

    private static IEnumerable<WriteSite> EnumerateWriteSites()
    {
        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            if (Path.GetFileName(file) == WriterDeclaringFile)
            {
                continue;
            }

            string[] lines = File.ReadAllLines(file);
            string relative = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
            foreach (var site in EnumerateWriteSitesIn(lines, relative))
            {
                yield return site;
            }
        }
    }

    private static IEnumerable<WriteSite> EnumerateWriteSitesIn(string[] lines, string relativePath)
    {
        string source = string.Join('\n', lines);
        foreach (Match m in AuditWriteRegex().Matches(source))
        {
            string arguments = ReadBalancedArguments(source, m.Index + m.Length - 1);
            string? action = ActionArgumentOf(arguments);
            if (action is null)
            {
                continue;
            }

            int lineIndex = source.Take(m.Index).Count(c => c == '\n');
            yield return new WriteSite(relativePath, lines, lineIndex, action);
        }
    }

    /// <summary>
    /// The argument text between <paramref name="openParenIndex"/> and its matching close paren,
    /// skipping over nested brackets and string literals (plain, verbatim and raw) so a bracket or
    /// comma inside one never ends the list early.
    /// </summary>
    private static string ReadBalancedArguments(string source, int openParenIndex)
    {
        int depth = 0;
        var buffer = new StringBuilder();
        for (int i = openParenIndex; i < source.Length; i++)
        {
            char c = source[i];
            if (c == '"')
            {
                int end = SkipStringLiteral(source, i);
                buffer.Append(source, i, end - i + 1);
                i = end;
                continue;
            }

            if (c is '(' or '[' or '{')
            {
                depth++;
                if (depth == 1)
                {
                    continue;
                }
            }
            else if (c is ')' or ']' or '}')
            {
                depth--;
                if (depth == 0)
                {
                    break;
                }
            }

            buffer.Append(c);
        }

        return buffer.ToString();
    }

    /// <summary>Index of the closing quote of the literal opening at <paramref name="start"/>.</summary>
    private static int SkipStringLiteral(string source, int start)
    {
        if (source.AsSpan(start).StartsWith("\"\"\""))
        {
            int close = source.IndexOf("\"\"\"", start + 3, StringComparison.Ordinal);
            return close < 0 ? source.Length - 1 : close + 2;
        }

        bool verbatim = start > 0 && source[start - 1] == '@';
        for (int i = start + 1; i < source.Length; i++)
        {
            if (!verbatim && source[i] == '\\')
            {
                i++;
                continue;
            }

            if (source[i] == '"')
            {
                if (verbatim && i + 1 < source.Length && source[i + 1] == '"')
                {
                    i++;
                    continue;
                }

                return i;
            }
        }

        return source.Length - 1;
    }

    /// <summary>
    /// The action argument of a <c>LogAsync</c>/<c>LogSystemAsync</c> call: the one named
    /// <c>action:</c>, or the first positional argument once the connection/transaction prefix of
    /// the transactional <c>LogSystemAsync</c> overload is dropped. Null when the call has no
    /// arguments at all, which is what a method declaration's own parameter list reduces to after
    /// the type-name prefixes are rejected.
    /// </summary>
    private static string? ActionArgumentOf(string arguments)
    {
        var parts = SplitTopLevel(arguments);
        foreach (string part in parts)
        {
            if (part.StartsWith("action:", StringComparison.Ordinal))
            {
                return part["action:".Length..].Trim();
            }
        }

        var positional = parts
            .Where(p => p.Length > 0 && NamedArgColonIndex(p) < 0)
            .SkipWhile(p => p is "conn" or "connection" or "tx" or "transaction" or "null")
            .ToList();

        return positional.Count > 0 ? positional[0] : null;
    }

    private static List<string> SplitTopLevel(string arguments)
    {
        var parts = new List<string>();
        var current = new StringBuilder();
        int depth = 0;
        for (int i = 0; i < arguments.Length; i++)
        {
            char c = arguments[i];
            if (c == '"')
            {
                int end = SkipStringLiteral(arguments, i);
                current.Append(arguments, i, end - i + 1);
                i = end;
                continue;
            }

            if (c is '(' or '[' or '{')
            {
                depth++;
            }
            else if (c is ')' or ']' or '}')
            {
                depth--;
            }
            else if (c == ',' && depth == 0)
            {
                parts.Add(current.ToString().Trim());
                current.Clear();
                continue;
            }

            current.Append(c);
        }

        parts.Add(current.ToString().Trim());
        return parts;
    }

    /// <summary>
    /// Index of the <c>:</c> that makes <paramref name="arg"/> a named argument, or -1 — so a
    /// ternary's own <c>:</c> is never read as one.
    /// </summary>
    private static int NamedArgColonIndex(string arg)
    {
        int i = 0;
        while (i < arg.Length && (char.IsLetterOrDigit(arg[i]) || arg[i] == '_'))
        {
            i++;
        }

        return i == 0 || i >= arg.Length
            ? -1
            : arg[i] == ':' && (i + 1 >= arg.Length || arg[i + 1] != ':') ? i : -1;
    }

    /// <summary>
    /// Every action name an argument expression can resolve to: its string literals when it has
    /// any (a ternary of two literals resolves to both), otherwise the value of the
    /// <c>const string</c> whose member name it ends with. An expression naming a const that
    /// resolves two ways, or naming nothing this gate understands, resolves to no names — which
    /// is a marker-requiring unknown, never an implicit pass.
    /// </summary>
    private static IReadOnlyList<string> ResolveActionNames(
        string argument, Dictionary<string, HashSet<string>> consts)
    {
        var literals = StringLiteralRegex().Matches(argument)
            .Select(m => m.Groups["literal"].Value)
            .ToList();
        if (literals.Count > 0)
        {
            return literals;
        }

        string member = argument.Split('.')[^1].Trim();
        return consts.TryGetValue(member, out var values) && values.Count == 1
            ? [values.Single()]
            : [];
    }

    private static Dictionary<string, HashSet<string>> BuildConstMap()
    {
        var map = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            foreach (Match m in ConstStringRegex().Matches(File.ReadAllText(file)))
            {
                if (!map.TryGetValue(m.Groups["name"].Value, out var values))
                {
                    map[m.Groups["name"].Value] = values = new HashSet<string>(StringComparer.Ordinal);
                }

                values.Add(m.Groups["value"].Value);
            }
        }

        return map;
    }

    private static bool HasReasonedOptOutAbove(string[] lines, int lineIndex)
    {
        for (int i = Math.Max(0, lineIndex - MarkerWindow); i <= lineIndex; i++)
        {
            int at = lines[i].IndexOf(OptOut, StringComparison.OrdinalIgnoreCase);
            if (at >= 0 && lines[i][(at + OptOut.Length)..].Trim().Length >= 10)
            {
                return true;
            }
        }

        return false;
    }

    private static string Condense(string expression) =>
        string.Join(' ', expression.Split((char[])['\n', '\r', ' ', '\t'],
            StringSplitOptions.RemoveEmptyEntries));

    private void Report(IReadOnlyList<string> violations, string what)
    {
        if (violations.Count == 0)
        {
            return;
        }

        foreach (string v in violations)
        {
            _output.WriteLine(v);
        }

        Assert.Fail($"{violations.Count} {what}. See test output.");
    }
}
