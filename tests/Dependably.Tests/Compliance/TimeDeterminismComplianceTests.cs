using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check: production code never reads the wall clock directly. All "now" reads go
/// through the DI-registered <see cref="TimeProvider"/> (ctor-injected; static helpers take
/// the timestamp as a parameter). Direct wall-clock reads make time-window logic, generated
/// content (ETags, checksum sidecars), and the tests that exercise them nondeterministic —
/// results change across second/midnight/year boundaries and leap days.
///
/// Banned tokens: the static now/today properties of the BCL date types (UTC and local
/// forms; the local forms are additionally wrong for a UTC-everywhere server).
///
/// <para>
/// Reading the clock is only half of it. Production code must also not <em>wait on</em> or
/// <em>measure with</em> the real clock: raw <c>Task.Delay</c>, <c>Thread.Sleep</c>,
/// <c>Stopwatch</c>, and the timer constructors are invisible to a <see cref="TimeProvider"/>
/// substitute, so a test advancing a fake clock past a deadline observes the deadline not
/// firing at all. That failure mode is worse than a wrong <c>DateTime</c>: the test sees
/// nothing happen rather than the wrong value, so the suite stays green over semantics that
/// do not work. <c>TimeProvider</c> has an equivalent for each — <c>Task.Delay(delay,
/// timeProvider, ct)</c>, <c>CreateTimer</c>, <c>GetTimestamp</c>/<c>GetElapsedTime</c> —
/// and the TimeProvider-aware overloads are recognised and pass.
/// </para>
///
/// Opt-out: a deliberate wall-clock read or real-time wait annotates with
/// <c>// now-ok: &lt;reason&gt;</c> on the same line or within the 5 lines above (the same
/// window as <c>// rawsql:</c> / <c>// xtenant:</c>).
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class TimeDeterminismComplianceTests
{
    private readonly ITestOutputHelper _output;
    public TimeDeterminismComplianceTests(ITestOutputHelper output) => _output = output;

    // The optional group between the type name and the member keeps this pattern from
    // matching its own source text.
    [GeneratedRegex(@"\bDateTime(Offset)?\s*\.\s*(UtcNow|Now|Today)\b", RegexOptions.None)]
    private static partial Regex WallClockRegex();

    [Fact]
    public void SrcUsesInjectedTimeProvider()
    {
        string repoRoot = SourceRoots.RepoRoot();

        // One combined scan across every src/Dependably* source root, so a wall-clock read that
        // moves into Core/Management/Edge is still caught. Paths remain repo-root-relative.
        var violations = new List<string>();
        foreach (string root in SourceRoots.All())
        {
            violations.AddRange(ScanTree(root, repoRoot));
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} direct wall-clock read(s) in src. Inject TimeProvider " +
                        "(or take the timestamp as a parameter in static helpers); a deliberate " +
                        "wall-clock read needs `// now-ok: <reason>`. See test output for the list.");
        }
    }

    [Fact]
    public void TestsUseFakeTimeProvider()
    {
        string repoRoot = SourceRoots.RepoRoot();

        var violations = ScanTree(Path.Combine(repoRoot, "tests"), repoRoot);

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} direct wall-clock read(s) in tests. Use a frozen " +
                        "FakeTimeProvider / TestTime.KnownNow (fixed instants make assertions exact " +
                        "and immune to second/midnight/leap-day boundaries); a deliberate real-clock " +
                        "read (e.g. a polling deadline awaiting actual async completion) needs " +
                        "`// now-ok: <reason>`. See test output for the list.");
        }
    }

    /// <summary>
    /// The wait/measure half of the rule, over <c>src/**</c> only. Tests legitimately wait on
    /// and poll the real clock while awaiting genuine async completion, and already opt those
    /// out one by one where they read the clock; holding the whole test tree to the
    /// TimeProvider overloads would be noise, not signal.
    /// </summary>
    [Fact]
    public void SrcUsesTimeProviderForWaitsTimersAndElapsedTime()
    {
        string repoRoot = SourceRoots.RepoRoot();

        var violations = new List<string>();
        foreach (string root in SourceRoots.All())
        {
            violations.AddRange(ScanTreeForRealTimeDependencies(root, repoRoot));
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} real-time dependency/dependencies in src. Use the " +
                        "TimeProvider equivalent (Task.Delay(delay, timeProvider, ct), " +
                        "TimeProvider.CreateTimer, TimeProvider.GetTimestamp/GetElapsedTime) so a " +
                        "FakeTimeProvider can drive them; a deliberate real-time wait needs " +
                        "`// now-ok: <reason>`. See test output for the list.");
        }
    }

    private List<string> ScanTree(string root, string repoRoot)
    {
        var violations = new List<string>();
        foreach (string file in EnumerateSource(root))
        {
            // The scanner's own file documents the banned tokens.
            if (Path.GetFileName(file) == nameof(TimeDeterminismComplianceTests) + ".cs")
            {
                continue;
            }

            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                // Comment-only lines can name the APIs (docs, examples) without reading them.
                if (lines[i].TrimStart().StartsWith("//"))
                {
                    continue;
                }

                if (WallClockRegex().IsMatch(lines[i]) && !HasNowOk(lines, i))
                {
                    violations.Add(
                        $"{Path.GetRelativePath(repoRoot, file)}:{i + 1}: direct wall-clock read — " +
                        $"use the injected TimeProvider or annotate `// now-ok: <reason>`. {lines[i].Trim()}");
                }
            }
        }

        return violations;
    }

    // ── real-time waits, timers and elapsed-time measurement ─────────────────────────────

    // Call sites that always depend on the real clock, with no TimeProvider-aware overload:
    // Thread.Sleep blocks the OS thread; every Stopwatch form reads the machine's monotonic
    // counter, which no substitute clock can move.
    private static readonly (string Token, string Fix)[] UnconditionalRealTimeCalls =
    {
        ("Thread.Sleep(", "blocks on the real clock — await Task.Delay(delay, timeProvider, ct)"),
        ("Stopwatch.StartNew(", "measures against the machine clock — use TimeProvider.GetTimestamp/GetElapsedTime"),
        ("Stopwatch.GetTimestamp(", "reads the machine clock — use TimeProvider.GetTimestamp"),
        ("new Stopwatch(", "measures against the machine clock — use TimeProvider.GetTimestamp/GetElapsedTime"),
        ("new Timer(", "schedules on the real clock — use TimeProvider.CreateTimer"),
        ("new System.Threading.Timer(", "schedules on the real clock — use TimeProvider.CreateTimer"),
        ("new Threading.Timer(", "schedules on the real clock — use TimeProvider.CreateTimer"),
    };

    // A TimeProvider argument. The only expressions that can legally occupy the slot examined
    // below are a CancellationToken or a TimeProvider, and no cancellation-token identifier in
    // this codebase contains "time" or "clock" — so matching on those roots separates the two
    // without needing type information.
    [GeneratedRegex(@"(^|[^A-Za-z])(_?time|_?timeProvider|_?clock|TimeProvider)\b", RegexOptions.IgnoreCase)]
    private static partial Regex TimeProviderArgRegex();

    private List<string> ScanTreeForRealTimeDependencies(string root, string repoRoot)
    {
        var violations = new List<string>();
        foreach (string file in EnumerateSource(root))
        {
            // The scanner's own file documents the banned tokens.
            if (Path.GetFileName(file) == nameof(TimeDeterminismComplianceTests) + ".cs")
            {
                continue;
            }

            string text = File.ReadAllText(file);
            string[] lines = File.ReadAllLines(file);

            foreach (var (index, message) in FindRealTimeDependencies(text))
            {
                int lineIndex = text.AsSpan(0, index).Count('\n');

                // Comment-only lines can name the APIs (docs, examples) without calling them.
                if (lineIndex >= lines.Length || lines[lineIndex].TrimStart().StartsWith("//"))
                {
                    continue;
                }

                if (HasNowOk(lines, lineIndex))
                {
                    continue;
                }

                violations.Add(
                    $"{Path.GetRelativePath(repoRoot, file)}:{lineIndex + 1}: {message}. " +
                    $"{lines[lineIndex].Trim()}");
            }
        }

        return violations;
    }

    private static IEnumerable<(int Index, string Message)> FindRealTimeDependencies(string text)
    {
        foreach (var (token, fix) in UnconditionalRealTimeCalls)
        {
            for (int at = text.IndexOf(token, StringComparison.Ordinal); at >= 0;
                 at = text.IndexOf(token, at + 1, StringComparison.Ordinal))
            {
                // `new System.Threading.Timer(` also matches the bare `new Timer(` probe on the
                // qualified tail; report the qualified form once, from its own token.
                if (token == "new Timer(" && at >= 1 && text[at - 1] == '.')
                {
                    continue;
                }

                yield return (at, $"{token.TrimEnd('(')} {fix}");
            }
        }

        // Task.Delay overloads: (TimeSpan|int), (TimeSpan|int, CancellationToken),
        // (TimeSpan, TimeProvider) and (TimeSpan, TimeProvider, CancellationToken). Three
        // arguments therefore identify the TimeProvider form outright; with two, the second
        // slot is either the token (raw) or the provider (correct).
        foreach (int at in Occurrences(text, "Task.Delay("))
        {
            var args = ArgumentsAt(text, at + "Task.Delay(".Length - 1);
            bool viaTimeProvider = args.Count == 3
                || (args.Count == 2 && TimeProviderArgRegex().IsMatch(args[1]));

            if (!viaTimeProvider)
            {
                yield return (at, "Task.Delay waits on the real clock — pass the injected " +
                                  "TimeProvider: Task.Delay(delay, timeProvider, ct)");
            }
        }

        // PeriodicTimer(TimeSpan) is real-time; PeriodicTimer(TimeSpan, TimeProvider) is not.
        foreach (int at in Occurrences(text, "new PeriodicTimer("))
        {
            var args = ArgumentsAt(text, at + "new PeriodicTimer(".Length - 1);
            if (args.Count < 2 || !TimeProviderArgRegex().IsMatch(args[1]))
            {
                yield return (at, "PeriodicTimer ticks on the real clock — pass the injected " +
                                  "TimeProvider: new PeriodicTimer(period, timeProvider)");
            }
        }
    }

    private static IEnumerable<int> Occurrences(string text, string token)
    {
        for (int at = text.IndexOf(token, StringComparison.Ordinal); at >= 0;
             at = text.IndexOf(token, at + 1, StringComparison.Ordinal))
        {
            yield return at;
        }
    }

    /// <summary>
    /// Splits the argument list whose opening parenthesis sits at <paramref name="openParen"/>
    /// into its top-level arguments, so a nested call (<c>Task.Delay(TimeSpan.FromSeconds(5),
    /// ct)</c>) is counted as two arguments rather than three. String and character literals
    /// are skipped so a comma or parenthesis inside one cannot split an argument.
    /// </summary>
    private static List<string> ArgumentsAt(string text, int openParen)
    {
        var args = new List<string>();
        int depth = 0;
        int start = openParen + 1;

        for (int i = openParen; i < text.Length; i++)
        {
            char c = text[i];

            if (c is '"' or '\'')
            {
                i = SkipLiteral(text, i);
                continue;
            }

            if (c is '(' or '[')
            {
                depth++;
            }
            else if (c is ')' or ']')
            {
                depth--;
                if (depth == 0)
                {
                    AddArgument(args, text, start, i);
                    return args;
                }
            }
            else if (c == ',' && depth == 1)
            {
                AddArgument(args, text, start, i);
                start = i + 1;
            }
        }

        return args;
    }

    private static void AddArgument(List<string> args, string text, int start, int end)
    {
        string arg = text[start..end].Trim();
        if (arg.Length > 0 || args.Count > 0)
        {
            args.Add(arg);
        }
    }

    // Returns the index of the literal's closing quote, honouring backslash escapes.
    private static int SkipLiteral(string text, int openQuote)
    {
        char quote = text[openQuote];
        for (int i = openQuote + 1; i < text.Length; i++)
        {
            if (text[i] == '\\')
            {
                i++;
                continue;
            }

            if (text[i] == quote)
            {
                return i;
            }
        }

        return text.Length - 1;
    }

    // The marker may sit on the flagged line or within the 5 lines above it (matching the
    // rawsql/xtenant opt-out window, since expressions often span wrapped lines).
    private static bool HasNowOk(string[] lines, int lineIndex)
    {
        for (int probe = Math.Max(0, lineIndex - 5); probe <= lineIndex && probe < lines.Length; probe++)
        {
            if (lines[probe].Contains("now-ok:", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static IEnumerable<string> EnumerateSource(string root)
    {
        foreach (string file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
        {
            string p = file.Replace('\\', '/');
            if (p.Contains("/obj/") || p.Contains("/bin/"))
            {
                continue;
            }

            yield return file;
        }
    }
}
