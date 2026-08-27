using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Every <c>Response.Clear()</c> call under <c>src/**</c> must sit next to a
/// <c>ResponseHeaderPreserver</c> <c>Capture</c>/<c>Restore</c> pair, or carry a reasoned
/// <c>// clear-ok: &lt;reason&gt;</c> opt-out — the static-scan half of the fix
/// <c>ResponseHeaderPreserver</c> exists to make systematic rather than per-reviewer.
/// <c>Response.Clear()</c> wipes every header set earlier in the pipeline indiscriminately; a
/// refusal writer that reaches for it without this helper reopens the exact gap
/// <c>TenantNotReadyResponseWriter</c>, <c>TerminalExceptionHandler</c>, and the five typed
/// exception middlewares (<c>AirGappedExceptionMiddleware</c>, <c>StagingDiskFullExceptionMiddleware</c>,
/// <c>TenantStorageQuotaExceededExceptionMiddleware</c>, <c>UpstreamFetchFailedExceptionMiddleware</c>,
/// <c>SsrfBlockedExceptionMiddleware</c>) were fixed to close.
///
/// <para>
/// <b>Blind spots</b>, stated plainly rather than left implicit, same as every other regex gate in
/// this family: this proves ADJACENCY, not correctness. It cannot tell whether the nearby
/// <c>Capture()</c> runs against the same <see cref="HttpContext"/> the <c>Clear()</c> targets,
/// whether <c>Restore()</c> actually executes on every code path out of the method (an early
/// return between <c>Clear()</c> and <c>Restore()</c> still reads as paired), or whether a
/// <c>Capture</c>/<c>Restore</c> pair that happens to sit nearby for an unrelated reason
/// coincidentally satisfies a <c>Clear()</c> it has nothing to do with — a second, unrelated
/// unpaired <c>Response.Clear()</c> within <see cref="PairingWindow"/> lines of that pair passes.
/// It cannot see a <c>Response.Clear()</c> reached through a wrapper method, a compiled delegate,
/// or reflection; it does join a call split across up to <see cref="ClearCallJoinWindow"/> source
/// lines (<c>c.Response</c> / <c>.Clear();</c> on separate lines still matches), but not one built
/// from a string or emitted by a source generator.
/// </para>
///
/// <para>
/// <b>A whole other shape is structurally invisible: a middleware that refuses a request without
/// ever calling <c>Response.Clear()</c> at all.</b> This gate is keyed on the literal token
/// <c>Response.Clear()</c> — a middleware that short-circuits (returns without calling <c>_next</c>)
/// and writes a bare status/body has nothing for the scan to find, paired or not.
/// <c>UploadSizeLimitMiddleware</c> is exactly this shape (it returns a 413 with no
/// <c>Response.Clear()</c> anywhere in it) and was confirmed the only current instance in
/// <c>src/**</c> — <c>SubdomainTenantMiddleware</c> deliberately does not short-circuit, and
/// <c>OriginalPeerMiddleware</c>/<c>TenantEnrichmentMiddleware</c>/<c>TransparentInterceptMiddleware</c>
/// write no response at all. Extending this gate to also catch a bare short-circuit is
/// disproportionate (it would need to understand control flow, not just grep for a token), so the
/// fix for <c>UploadSizeLimitMiddleware</c> is registration order instead: <c>SecurityHeadersMiddleware</c>
/// is registered immediately before it in both composition roots, so its headers are already on the
/// response — set directly, not via this helper — by the time the short-circuit happens.
/// <c>UploadSizeLimitMiddlewareTests</c> pins that every 413 route still carries the full header
/// set; <c>TransparentInterceptMiddlewareTests</c> pins the ordering constraint that made the fix
/// non-trivial (<c>SecurityHeadersMiddleware</c> classifies CSP/Cache-Control off <c>Request.Path</c>
/// before <c>_next</c>, so it must run after <c>TransparentInterceptMiddleware</c>'s host→prefix
/// rewrite, not before it). A future middleware with this same short-circuit shape reopens this
/// exact blind spot, and only a reviewer — not this gate — closes it.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class ResponseHeaderPreserverComplianceTests
{
    private const string Marker = "clear-ok:";
    private const int MarkerWindow = 5;

    // Every known call site in this repo pairs within 14 lines (TenantNotReadyResponseWriter's
    // RetryAfter branch, the widest gap); this window is generous relative to that without being
    // unbounded — a Capture()/Restore() pair 20 lines away from an UNRELATED Clear() in the same
    // file would be a coincidence the surrounding code review, not this gate, is responsible for.
    private const int PairingWindow = 20;

    // How many source lines a single Response.Clear() call is allowed to span when split across
    // a method-chain line break (e.g. `context.Response\n    .Clear();`). Every known call site in
    // this repo is one line; this is headroom, not an observed need.
    private const int ClearCallJoinWindow = 4;

    // Green-but-blind guard, matching this family's convention (e.g.
    // BlockGateRequestConstructionComplianceTests, IndexDownloadParityPostureComplianceTests):
    // `scanned` counts FILES the source-root walk returned, so this only catches a moved/renamed
    // source root (SourceRoots.All() suddenly returning far fewer directories) — it says nothing
    // about whether the files that WERE scanned actually matched anything. A regression in
    // CodeText or ResponseClearRegex that silently stops matching real call sites is covered
    // instead by CodeText_LeavesAnActualCallSiteMatchable_SelfTest and
    // MatchesResponseClearAt_JoinsACallSplitAcrossLines_SelfTest, which assert the regex/join
    // logic still matches a known-good literal, independent of any real file.
    private const int MinimumFilesScanned = 50;

    private readonly ITestOutputHelper _output;

    public ResponseHeaderPreserverComplianceTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void EveryResponseClearIsPairedWithCaptureAndRestore()
    {
        var violations = new List<string>();
        int scanned = 0;

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string[] lines = File.ReadAllLines(file);
            scanned++;
            for (int i = 0; i < lines.Length; i++)
            {
                if (!CodeText(lines[i]).Contains("Response", StringComparison.Ordinal)
                    || !MatchesResponseClearAt(lines, i))
                {
                    continue;
                }

                if (HasWellFormedMarkerAbove(lines, i))
                {
                    continue;
                }

                bool hasCapture = WindowContains(lines, i, "ResponseHeaderPreserver.Capture(");
                bool hasRestore = WindowContains(lines, i, "ResponseHeaderPreserver.Restore(");
                if (hasCapture && hasRestore)
                {
                    continue;
                }

                string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
                string missing = (hasCapture, hasRestore) switch
                {
                    (false, false) => "no Capture() or Restore() nearby",
                    (false, true) => "no Capture() nearby",
                    (true, false) => "no Restore() nearby",
                    _ => "unreachable",
                };
                violations.Add(
                    $"{rel}:{i + 1} — Response.Clear() with {missing}; wrap it with " +
                    "ResponseHeaderPreserver.Capture()/.Restore(), or opt out with " +
                    $"'// {Marker} <reason>' in the {MarkerWindow} lines above");
            }
        }

        Assert.True(scanned >= MinimumFilesScanned,
            $"only {scanned} C# files scanned — the source-root walk likely regressed.");
        Report(violations, "Response.Clear() call(s) not paired with ResponseHeaderPreserver");
    }

    [Fact]
    public void EveryClearOkMarkerCarriesAStatedReason()
    {
        var violations = new List<string>();
        int scanned = 0;

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string[] lines = File.ReadAllLines(file);
            scanned++;
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
        Report(violations, "malformed clear-ok marker(s)");
    }

    // ── Gate self-tests (synthetic in-memory lines, no real files touched) ──────

    /// <summary>Pins the marker window: inside it counts, one line beyond it does not.</summary>
    [Fact]
    public void MarkerWindow_IsBounded_SelfTest()
    {
        var justInside = new List<string> { $"// {Marker} a stated reason" };
        justInside.AddRange(Enumerable.Repeat("", MarkerWindow - 1));
        justInside.Add("context.Response.Clear();");
        Assert.True(HasWellFormedMarkerAbove([.. justInside], justInside.Count - 1));

        var justOutside = new List<string> { $"// {Marker} a stated reason" };
        justOutside.AddRange(Enumerable.Repeat("", MarkerWindow));
        justOutside.Add("context.Response.Clear();");
        Assert.False(HasWellFormedMarkerAbove([.. justOutside], justOutside.Count - 1));
    }

    /// <summary>
    /// A bare marker (no reason on its own line) must not count as an opt-out — this is the
    /// specific failure mode a whole-file \s* regex can get wrong by matching across the newline
    /// into the next line's code and reading THAT as the "reason". Checking line-by-line, as this
    /// gate does, makes that impossible: <c>lines[i]</c> never contains a newline to match across.
    /// </summary>
    [Fact]
    public void HasWellFormedMarkerAbove_RejectsABareMarker_SelfTest()
    {
        string[] bareMarkerThenCode =
        [
            $"// {Marker}",
            "context.Response.StatusCode = 500;",
            "context.Response.Clear();",
        ];

        Assert.False(HasWellFormedMarkerAbove(bareMarkerThenCode, 2));
    }

    [Fact]
    public void MarkerReasonRegex_AcceptsAReason_RejectsBareOrWhitespaceOnly_SelfTest()
    {
        Assert.Matches(MarkerReasonRegex(), $"// {Marker} genuinely not a refusal writer");
        Assert.DoesNotMatch(MarkerReasonRegex(), $"// {Marker}");
        Assert.DoesNotMatch(MarkerReasonRegex(), $"// {Marker}   ");
    }

    /// <summary>
    /// A <c>Response.Clear()</c> mentioned only in prose — this file's own doc comments, and
    /// <c>ResponseHeaderPreserver</c>'s, both describe the method by name repeatedly — must not be
    /// mistaken for a call site.
    /// </summary>
    [Fact]
    public void CodeText_StripsResponseClearMentionedOnlyInAComment_SelfTest()
    {
        string commentLine = "        // Response.Clear() drops every header set on the way in.";

        Assert.DoesNotMatch(ResponseClearRegex(), CodeText(commentLine));
    }

    [Fact]
    public void CodeText_LeavesAnActualCallSiteMatchable_SelfTest()
    {
        string codeLine = "            context.Response.Clear();";

        Assert.Matches(ResponseClearRegex(), CodeText(codeLine));
    }

    /// <summary>
    /// Verified against the branch: before <see cref="MatchesResponseClearAt"/> existed, a call
    /// split across a method-chain line break — <c>c.Response</c> on one line, <c>.Clear();</c> on
    /// the next — matched neither line's <see cref="ResponseClearRegex"/> on its own, so the scan
    /// stayed green over a real unpaired clear. This pins the fix directly, independent of the two
    /// facts above (which exercise it only through a real file).
    /// </summary>
    [Fact]
    public void MatchesResponseClearAt_JoinsACallSplitAcrossLines_SelfTest()
    {
        string[] splitAcrossTwoLines = ["c.Response", "    .Clear();"];
        Assert.True(MatchesResponseClearAt(splitAcrossTwoLines, 0));

        string[] splitAcrossThreeLines = ["ctx", "    .Response", "    .Clear();"];
        Assert.True(MatchesResponseClearAt(splitAcrossThreeLines, 1));

        string[] singleLine = ["context.Response.Clear();"];
        Assert.True(MatchesResponseClearAt(singleLine, 0));

        // Beyond the join window: documented headroom-not-observed-need boundary, not a real call
        // shape anywhere in this repo today.
        string[] tooFarApart = ["c.Response", "", "", "", "    .Clear();"];
        Assert.False(MatchesResponseClearAt(tooFarApart, 0));
    }

    [Fact]
    public void WindowContains_FindsAPairWithinRange_ButNotBeyondIt_SelfTest()
    {
        var lines = new List<string> { "ResponseHeaderPreserver.Capture(context);" };
        lines.AddRange(Enumerable.Repeat("", PairingWindow - 1));
        lines.Add("context.Response.Clear();");
        lines.AddRange(Enumerable.Repeat("", PairingWindow - 1));
        lines.Add("ResponseHeaderPreserver.Restore(context, snapshot);");
        int clearIndex = PairingWindow;

        Assert.True(WindowContains([.. lines], clearIndex, "ResponseHeaderPreserver.Capture("));
        Assert.True(WindowContains([.. lines], clearIndex, "ResponseHeaderPreserver.Restore("));

        var tooFar = new List<string> { "ResponseHeaderPreserver.Capture(context);" };
        tooFar.AddRange(Enumerable.Repeat("", PairingWindow));
        tooFar.Add("context.Response.Clear();");
        Assert.False(WindowContains([.. tooFar], PairingWindow + 1, "ResponseHeaderPreserver.Capture("));
    }

    // ── Scan helpers ─────────────────────────────────────────────────

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

    private static bool WindowContains(string[] lines, int lineIndex, string needle)
    {
        int start = Math.Max(0, lineIndex - PairingWindow);
        int end = Math.Min(lines.Length - 1, lineIndex + PairingWindow);
        for (int probe = start; probe <= end; probe++)
        {
            if (lines[probe].Contains(needle, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// True if a <c>Response.Clear()</c> call starts at <paramref name="startIndex"/>, joining the
    /// code portion of up to <see cref="ClearCallJoinWindow"/> lines forward so a call split across
    /// a method-chain line break still matches. Stops joining at the first line whose code portion
    /// contains a <c>;</c> (inclusive) — this call takes no arguments, so its own statement
    /// terminator is always the end of the expression, and stopping there keeps the join from
    /// pulling in unrelated code on a busy line.
    /// </summary>
    private static bool MatchesResponseClearAt(string[] lines, int startIndex)
    {
        var joined = new System.Text.StringBuilder();
        int end = Math.Min(lines.Length, startIndex + ClearCallJoinWindow);
        for (int i = startIndex; i < end; i++)
        {
            string code = CodeText(lines[i]);
            joined.Append(code).Append(' ');
            if (code.Contains(';', StringComparison.Ordinal))
            {
                break;
            }
        }

        return ResponseClearRegex().IsMatch(joined.ToString());
    }

    /// <summary>
    /// Returns the code portion of a line — everything before the first <c>//</c> that is not
    /// inside a string literal — so a <c>Response.Clear()</c> mentioned in prose inside a comment
    /// (this file's own doc comments, or <c>ResponseHeaderPreserver</c>'s, both describe the method
    /// by name repeatedly) is never mistaken for a call site. Mirrors
    /// <see cref="CommentProvenanceComplianceTests"/>'s <c>CommentText</c>, inverted: that returns
    /// the comment, this returns what is left when the comment is removed. Never returns null — a
    /// line with no comment marker returns unchanged — unlike <c>CommentText</c>, which legitimately
    /// returns null for "no comment on this line", a state <c>CodeText</c> has no equivalent of:
    /// every line has code-or-nothing, so "no comment" and "the whole line" are the same case here.
    /// Crude in the same way as <c>CommentText</c>: ignores <c>//</c> inside a string, does not
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

    [GeneratedRegex(@"\bResponse\s*\.\s*Clear\s*\(\s*\)")]
    private static partial Regex ResponseClearRegex();

    [GeneratedRegex(@"\bclear-ok:\s*\S+")]
    private static partial Regex MarkerReasonRegex();
}
