using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Every <c>CacheFillGuard.GuardFor</c>-shaped mint site — a line that calls a consumer's own
/// private <c>GuardFor(key)</c> helper to snapshot a generation token before a DB read — must have
/// a <c>try</c> and a <c>CacheFillGuard.RetireUnbound(</c> call within <see cref="RetireWindow"/>
/// lines, or a reasoned <c>// fillguard-ok: &lt;reason&gt;</c> opt-out. Without the pairing, a DB
/// open/read that throws (or any early return) between the mint and the eventual
/// <c>TieToEntryLifetime</c>/<c>_cache.Set</c> leaves the just-minted generation in a
/// process-lifetime map forever — the throwing-branch leak every <c>CacheFillGuard</c> consumer is
/// registered Singleton for and so is live for. <c>SubdomainTenantResolver</c> is the reference
/// shape: mint, <c>try</c>, tie-and-set on success, <c>RetireUnbound</c> in a <c>finally</c> guarded
/// by a <c>tied</c> flag.
///
/// <para>
/// <b>Blind spots</b>, stated plainly rather than left implicit, same as every other regex gate in
/// this family: this proves PROXIMITY, not control flow. It cannot tell whether the nearby
/// <c>try</c> actually wraps the mint-to-install window (a <c>try</c> for an unrelated inner
/// operation a few lines later would satisfy it), whether <c>RetireUnbound</c> actually runs on
/// EVERY non-installing path out of the method (a second early return the <c>finally</c> does not
/// cover would still read as paired, the same class of gap
/// <c>ResponseHeaderPreserverComplianceTests</c> documents for its own Capture/Restore pairing), or
/// whether the <c>RetireUnbound</c> call passes the SAME key and source the mint captured rather
/// than a coincidentally nearby one for a different guard. It also cannot see a mint reached through
/// a wrapper method, a compiled delegate, or reflection. A file with two independent fill methods
/// that each mint their own guard is covered independently — each mint site gets its own forward
/// window — but a <c>RetireUnbound</c> that happens to sit within the window of BOTH mints while
/// only truly belonging to one would pass for both; no consumer in this repo has that shape today.
/// <b>The likeliest way consumer number eight diverges is not on this list of near-misses: an
/// inline mint that never goes through a <c>GuardFor</c>-named helper at all</b> — a fill that
/// calls <c>_fillGuards.GetOrAdd(key, static _ =&gt; new CancellationTokenSource())</c> directly,
/// ties the result to a cache entry, and never retires it on the throwing path. This gate keys
/// entirely on the token <c>GuardFor(</c>, so an inline mint is structurally invisible to it —
/// confirmed against a real file placed in a real source root, which the gate did not flag. Every
/// consumer in this repo goes through a named <c>GuardFor</c> helper today, which is what keeps
/// this blind spot latent rather than open; a future consumer that mints inline reopens it, and
/// only a reviewer — not this gate — closes it, unless a future revision matches the inline
/// <c>GetOrAdd</c> shape directly instead of (or in addition to) the named-helper call.
/// </para>
///
/// <para>
/// The scan is scoped to files that actually call <c>CacheFillGuard.TieToEntryLifetime</c> — a
/// <c>GuardFor</c>-named helper that never ties its guard to a cache entry's lifetime at all (e.g.
/// <c>OrgCacheEpochStore</c>'s persistent per-org epoch, which is deliberately never retired) is a
/// different pattern this gate does not require to reshape. That scoping is itself a coarse,
/// file-wide check — it does not confirm the SAME mint site's guard is the one later tied, only
/// that the file ties something to something somewhere.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class CacheFillGuardLifecycleComplianceTests
{
    private const string Marker = "fillguard-ok:";
    private const int MarkerWindow = 5;

    // Widest observed mint-to-RetireUnbound gap today is 57 lines (SubdomainTenantResolver, whose
    // try/finally wraps a full DB-open-and-branch-on-status block); this is headroom above that,
    // not an unbounded search — an unrelated RetireUnbound call 80+ lines away in the same file is
    // a coincidence code review, not this gate, is responsible for.
    private const int RetireWindow = 80;

    // How many source lines a single GuardFor(...) call is allowed to span when its argument list
    // (or, in principle, the rarely-legal whitespace between the method name and its open paren)
    // is broken across lines. Every known call site in this repo is one line; this is headroom,
    // matching ResponseHeaderPreserverComplianceTests' ClearCallJoinWindow, not an observed need.
    private const int CallJoinWindow = 4;

    // Green-but-blind guard, matching this family's convention (e.g.
    // BlockGateRequestConstructionComplianceTests, ResponseHeaderPreserverComplianceTests):
    // `scanned` counts FILES the source-root walk returned. This is a WEAKER guarantee than it
    // looks: it only catches the whole walk collapsing near zero (SourceRoots.RepoRoot()
    // resolution breaking, or the `src/Dependably*` glob matching nothing at all). It does NOT
    // catch a single project root silently vanishing while the others keep the total comfortably
    // above the floor — confirmed directly by renaming src/Dependably.Core out of the glob: the
    // total scanned count stays at 184 (Dependably + Dependably.Management + Dependably.Edge,
    // still >= MinimumFilesScanned) while 431 files, and five of the seven real CacheFillGuard
    // consumers living under Core, silently drop out of the scan. RequiredRootMinimums below (and
    // AssertRequiredRootsWereScanned) is the check that actually closes that gap, by naming the
    // specific roots this gate depends on and requiring each to contribute its own floor. A
    // regression in the matching regexes that silently stops matching real call sites within files
    // that ARE scanned is a separate concern, covered instead by the self-tests below, which
    // assert the regex/join logic still matches a known-good literal, independent of any real file.
    private const int MinimumFilesScanned = 50;

    // The project roots known to hold every current CacheFillGuard consumer (Core: six of seven —
    // BlocklistRepository, UserTokenVersionStore, SubdomainTenantResolver,
    // InstallScriptAllowlistService, ReservedNamespaceService; Management: the seventh,
    // JwtRevocationRepository and SystemAdminTokenVersionStore). Minimums are set well below each
    // root's actual current file count (431 / 182) so an unrelated file removed elsewhere in the
    // same root never trips this — it exists to catch the root itself silently disappearing from
    // SourceRoots.All(), not routine churn in file count.
    private static readonly IReadOnlyDictionary<string, int> RequiredRootMinimums =
        new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["Dependably.Core"] = 200,
            ["Dependably.Management"] = 80,
        };

    private readonly ITestOutputHelper _output;

    public CacheFillGuardLifecycleComplianceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void EveryGuardForMintHasATryAndARetireUnboundOnItsNonInstallingPath()
    {
        var violations = new List<string>();
        int scanned = 0;
        var scannedByRoot = new Dictionary<string, int>(StringComparer.Ordinal);

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string[] lines = File.ReadAllLines(file);
            scanned++;
            string rootName = Path.GetFileName(SourceRoots.OwningRoot(file));
            scannedByRoot[rootName] = scannedByRoot.GetValueOrDefault(rootName) + 1;

            // Scope to genuine CacheFillGuard consumers: a file whose own GuardFor-named helper
            // never calls CacheFillGuard.TieToEntryLifetime is a structurally different pattern
            // (e.g. OrgCacheEpochStore's persistent per-org epoch, which is never tied to a cache
            // entry's lifetime and is intentionally never retired) and is not required to reshape
            // into the mint/tie-or-retire discipline this gate enforces.
            if (!IsCacheFillGuardConsumer(lines))
            {
                continue;
            }

            for (int i = 0; i < lines.Length; i++)
            {
                // Prefilter on the identifier itself so a blank or comment line a few lines ahead
                // of a real mint site is never treated as its own (spurious) starting point — the
                // join in MatchesGuardForCallAt looks CallJoinWindow lines forward regardless of
                // what line it started from, so without this every line within that window before
                // a real call would independently "see" it and double-report the same call site.
                if (!CodeText(lines[i]).Contains("GuardFor", StringComparison.Ordinal)
                    || !MatchesGuardForCallAt(lines, i) || IsGuardForDeclarationAt(lines, i))
                {
                    continue;
                }

                if (HasWellFormedMarkerAbove(lines, i))
                {
                    continue;
                }

                bool hasTry = ForwardWindowContainsTry(lines, i);
                bool hasRetire = ForwardWindowContains(lines, i, "CacheFillGuard.RetireUnbound(");
                if (hasTry && hasRetire)
                {
                    continue;
                }

                string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
                string missing = (hasTry, hasRetire) switch
                {
                    (false, false) => "no try and no CacheFillGuard.RetireUnbound( nearby",
                    (false, true) => "no try nearby",
                    (true, false) => "no CacheFillGuard.RetireUnbound( nearby",
                    _ => "unreachable",
                };
                violations.Add(
                    $"{rel}:{i + 1} — GuardFor(...) mint with {missing}; wrap the DB read in a " +
                    "try/finally that calls CacheFillGuard.RetireUnbound on the non-installing path, " +
                    $"or opt out with '// {Marker} <reason>' in the {MarkerWindow} lines above");
            }
        }

        Assert.True(scanned >= MinimumFilesScanned,
            $"only {scanned} C# files scanned — the source-root walk likely regressed.");
        AssertRequiredRootsWereScanned(scannedByRoot);
        Report(violations, "GuardFor(...) mint(s) without a paired try/RetireUnbound");
    }

    [Fact]
    public void EveryFillguardOkMarkerCarriesAStatedReason()
    {
        var violations = new List<string>();
        int scanned = 0;
        var scannedByRoot = new Dictionary<string, int>(StringComparer.Ordinal);

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string[] lines = File.ReadAllLines(file);
            scanned++;
            string rootName = Path.GetFileName(SourceRoots.OwningRoot(file));
            scannedByRoot[rootName] = scannedByRoot.GetValueOrDefault(rootName) + 1;
            for (int i = 0; i < lines.Length; i++)
            {
                // Checked against the RAW line, deliberately never a whole-file or multi-line
                // string — File.ReadAllLines already split the file, so a bare marker with nothing
                // after it on its own line cannot have \s* in MarkerReasonRegex reach past a
                // newline and swallow the next line of code as its "reason".
                if (lines[i].Contains(Marker, StringComparison.Ordinal)
                    && !MarkerReasonRegex().IsMatch(lines[i]))
                {
                    string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
                    violations.Add(
                        $"{rel}:{i + 1} — bare '{Marker}' with no reason; a marker that states " +
                        "nothing is not a decision and is not honoured");
                }
            }
        }

        Assert.True(scanned >= MinimumFilesScanned,
            $"only {scanned} C# files scanned — the source-root walk likely regressed.");
        AssertRequiredRootsWereScanned(scannedByRoot);
        Report(violations, "malformed fillguard-ok marker(s)");
    }

    // ── Gate self-tests (synthetic in-memory lines, no real files touched) ──────

    /// <summary>Pins the forward window: inside it counts, one line beyond it does not.</summary>
    [Fact]
    public void RetireWindow_IsBounded_SelfTest()
    {
        var justInside = new List<string> { "var guardSource = GuardFor(key);" };
        justInside.AddRange(Enumerable.Repeat("", RetireWindow - 2));
        justInside.Add("try");
        justInside.Add("CacheFillGuard.RetireUnbound(_fillGuards, key, guardSource);");
        Assert.True(ForwardWindowContainsTry([.. justInside], 0));
        Assert.True(ForwardWindowContains([.. justInside], 0, "CacheFillGuard.RetireUnbound("));

        var justOutside = new List<string> { "var guardSource = GuardFor(key);" };
        justOutside.AddRange(Enumerable.Repeat("", RetireWindow));
        justOutside.Add("try");
        justOutside.Add("CacheFillGuard.RetireUnbound(_fillGuards, key, guardSource);");
        Assert.False(ForwardWindowContainsTry([.. justOutside], 0));
        Assert.False(ForwardWindowContains([.. justOutside], 0, "CacheFillGuard.RetireUnbound("));
    }

    [Fact]
    public void HasWellFormedMarkerAbove_RejectsABareMarker_SelfTest()
    {
        string[] bareMarkerThenCode =
        [
            $"// {Marker}",
            "var x = 1;",
            "var guardSource = GuardFor(key);",
        ];

        Assert.False(HasWellFormedMarkerAbove(bareMarkerThenCode, 2));
    }

    [Fact]
    public void MarkerReasonRegex_AcceptsAReason_RejectsBareOrWhitespaceOnly_SelfTest()
    {
        Assert.Matches(MarkerReasonRegex(), $"// {Marker} deliberately never installs — see caller");
        Assert.DoesNotMatch(MarkerReasonRegex(), $"// {Marker}");
        Assert.DoesNotMatch(MarkerReasonRegex(), $"// {Marker}   ");
    }

    /// <summary>
    /// A <c>GuardFor(</c> mentioned only in prose — this file's own doc comment, and
    /// <c>CacheFillGuard</c>'s, both describe the shape by name — must not be mistaken for a
    /// call site.
    /// </summary>
    [Fact]
    public void CodeText_StripsGuardForMentionedOnlyInAComment_SelfTest()
    {
        string commentLine = "        // Calls GuardFor(key) to snapshot the generation token.";

        Assert.DoesNotMatch(GuardForCallRegex(), CodeText(commentLine));
    }

    [Fact]
    public void CodeText_LeavesAnActualCallSiteMatchable_SelfTest()
    {
        string codeLine = "        var guardSource = GuardFor(orgId);";

        Assert.Matches(GuardForCallRegex(), CodeText(codeLine));
    }

    /// <summary>
    /// The <c>GuardFor(string key) =&gt;</c> declaration itself contains the token this gate scans
    /// for and must never be treated as a mint site — it would otherwise demand a try/RetireUnbound
    /// pair sitting next to a one-line factory method that has neither.
    /// </summary>
    [Fact]
    public void IsGuardForDeclarationAt_ExcludesTheDefinitionItself_SelfTest()
    {
        string[] declarationThenBody =
        [
            "    private CancellationTokenSource GuardFor(string orgId) =>",
            "        _fillGuards.GetOrAdd(orgId, static _ => new CancellationTokenSource());",
        ];

        Assert.True(MatchesGuardForCallAt(declarationThenBody, 0));
        Assert.True(IsGuardForDeclarationAt(declarationThenBody, 0));
    }

    /// <summary>
    /// Joins a call whose opening paren is split from the method name across a line break — the
    /// anchor-token-split shape that let a sibling gate in this family (matching <c>.Clear()</c>
    /// split from its <c>Response</c> qualifier) go green-but-blind until it started joining
    /// multi-line forms. A split mid-argument-list would still match on the first line alone,
    /// since <c>GuardFor(</c> is already complete there; only a break before the paren itself
    /// needs the join.
    /// </summary>
    [Fact]
    public void MatchesGuardForCallAt_JoinsACallSplitAcrossLines_SelfTest()
    {
        string[] splitBeforeParen = ["var guardSource = GuardFor", "    (orgId);"];
        Assert.True(MatchesGuardForCallAt(splitBeforeParen, 0));

        string[] singleLine = ["var guardSource = GuardFor(orgId);"];
        Assert.True(MatchesGuardForCallAt(singleLine, 0));

        // Beyond the join window: documented headroom-not-observed-need boundary, not a real call
        // shape anywhere in this repo today.
        string[] tooFarApart = ["var guardSource = GuardFor", "", "", "", "    (orgId);"];
        Assert.False(MatchesGuardForCallAt(tooFarApart, 0));
    }

    /// <summary>
    /// A <c>GuardFor</c>-named helper that never calls <c>CacheFillGuard.TieToEntryLifetime</c> is
    /// a different pattern (a persistent per-key epoch, not a per-fill generation guard tied to a
    /// cache entry's lifetime) and must not be forced into the mint/tie-or-retire shape — pins the
    /// <c>OrgCacheEpochStore</c> exclusion directly rather than only through a real file.
    /// </summary>
    [Fact]
    public void IsCacheFillGuardConsumer_ExcludesAGuardForHelperThatNeverTiesAnEntry_SelfTest()
    {
        string[] epochStoreShape =
        [
            "private CancellationTokenSource GuardFor(string orgId) =>",
            "    _epochs.GetOrAdd(orgId, static _ => new CancellationTokenSource());",
            "public IChangeToken GetToken(string orgId) => new CancellationChangeToken(GuardFor(orgId).Token);",
        ];
        Assert.False(IsCacheFillGuardConsumer(epochStoreShape));

        string[] realConsumerShape =
        [
            "var guardSource = GuardFor(orgId);",
            "CacheFillGuard.TieToEntryLifetime(options, _fillGuards, orgId, guardSource);",
        ];
        Assert.True(IsCacheFillGuardConsumer(realConsumerShape));
    }

    /// <summary>
    /// Pins the per-root floor directly: a scan tally missing (or short on) a required root must
    /// fail, independent of any real file — the scenario this exists to catch (Core silently
    /// vanishing from <c>SourceRoots.All()</c> while the flat total stays comfortably above
    /// <see cref="MinimumFilesScanned"/>) is exactly what a real-file reproduction cannot safely
    /// exercise without actually renaming a project directory mid-test-run.
    /// </summary>
    [Fact]
    public void AssertRequiredRootsWereScanned_FailsWhenARequiredRootIsMissingOrShort_SelfTest()
    {
        var missingCore = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["Dependably.Management"] = 200,
        };
        Assert.NotNull(Record.Exception(() => AssertRequiredRootsWereScanned(missingCore)));

        var shortCore = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["Dependably.Core"] = 1,
            ["Dependably.Management"] = 200,
        };
        Assert.NotNull(Record.Exception(() => AssertRequiredRootsWereScanned(shortCore)));

        var healthy = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["Dependably.Core"] = 431,
            ["Dependably.Management"] = 182,
        };
        Assert.Null(Record.Exception(() => AssertRequiredRootsWereScanned(healthy)));
    }

    // ── Scan helpers ─────────────────────────────────────────────────

    /// <summary>
    /// True when this file actually participates in the CacheFillGuard mint/tie/retire lifecycle —
    /// see the exclusion rationale at the Fact's call site.
    /// </summary>
    private static bool IsCacheFillGuardConsumer(string[] lines) =>
        lines.Any(l => l.Contains("CacheFillGuard.TieToEntryLifetime(", StringComparison.Ordinal));

    /// <summary>
    /// Fails when a project root named in <see cref="RequiredRootMinimums"/> contributed fewer
    /// files than its floor (including zero — a missing key reads as zero) — the check
    /// <c>MinimumFilesScanned</c> alone cannot make, since a single vanished root's files can be
    /// masked by the remaining roots' totals. See the field's doc for the demonstrated gap.
    /// </summary>
    private static void AssertRequiredRootsWereScanned(Dictionary<string, int> scannedByRoot)
    {
        foreach (var (root, minimum) in RequiredRootMinimums)
        {
            int actual = scannedByRoot.GetValueOrDefault(root);
            Assert.True(actual >= minimum,
                $"only {actual} C# file(s) scanned under {root} (expected at least {minimum}) — " +
                "that project root likely vanished from SourceRoots.All() while the flat " +
                $"{nameof(MinimumFilesScanned)} floor stayed satisfied by the other roots.");
        }
    }

    private static bool HasWellFormedMarkerAbove(string[] lines, int lineIndex)
    {
        for (int probe = Math.Max(0, lineIndex - MarkerWindow); probe <= lineIndex && probe < lines.Length; probe++)
        {
            if (lines[probe].Contains(Marker, StringComparison.Ordinal) && MarkerReasonRegex().IsMatch(lines[probe]))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ForwardWindowContains(string[] lines, int lineIndex, string needle)
    {
        int end = Math.Min(lines.Length - 1, lineIndex + RetireWindow);
        for (int probe = lineIndex; probe <= end; probe++)
        {
            if (lines[probe].Contains(needle, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ForwardWindowContainsTry(string[] lines, int lineIndex)
    {
        int end = Math.Min(lines.Length - 1, lineIndex + RetireWindow);
        for (int probe = lineIndex; probe <= end; probe++)
        {
            if (TryKeywordRegex().IsMatch(CodeText(lines[probe])))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// True if a <c>GuardFor(...)</c> call starts at <paramref name="startIndex"/>, joining the
    /// code portion of up to <see cref="CallJoinWindow"/> lines forward so a call split across a
    /// line break still matches. Stops joining at the first line whose code portion contains a
    /// <c>;</c> (inclusive) — a mint call is always a complete statement, so its own statement
    /// terminator is the end of the expression to consider.
    /// </summary>
    private static bool MatchesGuardForCallAt(string[] lines, int startIndex)
    {
        var joined = new System.Text.StringBuilder();
        int end = Math.Min(lines.Length, startIndex + CallJoinWindow);
        for (int i = startIndex; i < end; i++)
        {
            string code = CodeText(lines[i]);
            joined.Append(code).Append(' ');
            if (code.Contains(';', StringComparison.Ordinal))
            {
                break;
            }
        }

        return GuardForCallRegex().IsMatch(joined.ToString());
    }

    /// <summary>
    /// True if the statement starting at <paramref name="startIndex"/> (joined the same way as
    /// <see cref="MatchesGuardForCallAt"/>) is the <c>GuardFor</c> factory method's own
    /// declaration rather than a call site.
    /// </summary>
    private static bool IsGuardForDeclarationAt(string[] lines, int startIndex)
    {
        var joined = new System.Text.StringBuilder();
        int end = Math.Min(lines.Length, startIndex + CallJoinWindow);
        for (int i = startIndex; i < end; i++)
        {
            string code = CodeText(lines[i]);
            joined.Append(code).Append(' ');
            if (code.Contains(';', StringComparison.Ordinal) || code.Contains("=>", StringComparison.Ordinal))
            {
                break;
            }
        }

        return GuardForDeclarationRegex().IsMatch(joined.ToString());
    }

    /// <summary>
    /// Returns the code portion of a line — everything before the first <c>//</c> that is not
    /// inside a string literal — mirroring <c>ResponseHeaderPreserverComplianceTests.CodeText</c>
    /// (each gate in this family keeps its own copy rather than sharing one, matching the existing
    /// convention). Crude in the same documented way: ignores <c>//</c> inside a string, does not
    /// handle block comments (this codebase uses <c>//</c>/<c>///</c> almost exclusively).
    /// </summary>
    private static string CodeText(string line)
    {
        bool inString = false;
        char stringChar = '"';
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (inString)
            {
                if (c == '\\' && i + 1 < line.Length) { i++; continue; }
                if (c == stringChar) { inString = false; }
                continue;
            }

            if (c is '"' or '\'') { inString = true; stringChar = c; continue; }
            if (c == '/' && i + 1 < line.Length && line[i + 1] == '/')
            {
                return line[..i];
            }
        }

        return line;
    }

    private void Report(List<string> violations, string what)
    {
        if (violations.Count == 0)
        {
            return;
        }

        violations.Sort(StringComparer.Ordinal);
        violations.ForEach(_output.WriteLine);
        Assert.Fail($"{violations.Count} {what}. See test output for the full list.");
    }

    [GeneratedRegex(@"\bGuardFor\s*\(")]
    private static partial Regex GuardForCallRegex();

    [GeneratedRegex(@"\bCancellationTokenSource\s+GuardFor\s*\(")]
    private static partial Regex GuardForDeclarationRegex();

    [GeneratedRegex(@"^\s*try\b")]
    private static partial Regex TryKeywordRegex();

    [GeneratedRegex(@"\bfillguard-ok:\s*\S+")]
    private static partial Regex MarkerReasonRegex();
}
