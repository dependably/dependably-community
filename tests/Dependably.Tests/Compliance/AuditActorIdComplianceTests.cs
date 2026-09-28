using System.Text;
using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check enforcing that an audit write which characterizes its actor as a token's
/// <c>ActorKind</c> also identifies that actor with the same token's <c>AuditActorId</c> — never
/// its <c>UserId</c>.
///
/// <para><b>The defect this closes.</b> A service token has no owning user:
/// <c>TokenRepository.ResolveAsync</c> selects <c>NULL AS user_id</c> for the service branch. A
/// call site pairing <c>actorId: token.UserId</c> with <c>actorKind: token.ActorKind</c> therefore
/// writes a NULL actor under a <c>'service'</c> discriminator. The list queries resolve a service
/// actor through <c>LEFT JOIN service_tokens st ON st.id = a.actor_id</c>, which cannot match a
/// NULL, so <c>'service:' || st.name</c> yields NULL and the row renders as anonymous —
/// indistinguishable from a genuinely unauthenticated request. <c>Schema.sql</c> already declares
/// the contract this violates ("Set explicitly by every new write so service-token actors render
/// as 'service:&lt;name&gt;' instead of being indistinguishable from anonymous"); the read side
/// honoured it and the writers did not.</para>
///
/// <para><b>Why a gate rather than a convention.</b> The failure is silent in every direction
/// that normally catches things. It compiles, because <c>UserId</c> is a valid nullable string in
/// the <c>actorId</c> slot. It passes <see cref="AuditAttributionComplianceTests"/>, because that
/// gate proves an argument was <em>supplied</em>, not that its value is right. And it passed the
/// existing unit coverage, because <c>ActorKindAttributionTests</c> supplies <c>actor_id</c> by
/// hand and exercises only the read query — so it stayed green over writers that never produced
/// that input. Nothing but this scan distinguishes the correct pairing from the broken one.</para>
///
/// <para><b>What this gate cannot see.</b> It matches the receiver identifier textually, so it
/// catches <c>token.UserId</c> + <c>token.ActorKind</c> but not a pairing threaded through two
/// differently-named locals, nor one assembled inside a request record built elsewhere (the
/// <c>BlockGateRequest</c> / <c>ProxyFetchRequest</c> shape). Those are reviewer-enforced, and the
/// record-construction sites are where the value must be correct. Like every gate in this family
/// it proves a spelling, never that the value flowing in is the right principal.</para>
///
/// <para><b>Rule 2: an actor label comes from a derived accessor.</b> <c>audit_log.actor_label</c>
/// and <c>activity.actor_label</c> hold a service actor's display name, and nothing else: a
/// user's display name is an email, and the member-removal and retention scrubs clear a fixed
/// column list this column is not on. So every <c>actorLabel:</c> argument and every
/// <c>AuditActorLabel</c> record argument or assignment in <c>src/</c>, plus the positional
/// <c>actorLabel</c> slot of <c>LogAsync</c>, <c>LogActivityAsync</c> and <c>LogSystemAsync</c>,
/// must be <c>null</c>, a member access ending in <c>.AuditActorLabel</c> or <c>.Label</c>, or a
/// parameter of the same name passed straight through. The accessors are the producers that
/// return a label for a service actor only: <c>TokenRecord.AuditActorLabel</c>,
/// <c>SystemActor.Label</c> and <c>ResolvedActor.Label</c>. A pass-through parameter is accepted
/// because its own callers are held to the same rule, which makes the check transitive over
/// factories such as <c>BlockGateRequest.ForProxy*</c>. The rule is on the producer, not on the
/// paired <c>actorKind</c>: <c>token.ActorKind</c> is <c>user</c> for a personal token on the
/// correct call sites, and the label there is safe only because its producer returns NULL.</para>
///
/// <para><b>What rule 2 cannot see.</b> It proves the label was read through a derived accessor,
/// not that the accessor is correct: a new <c>.Label</c> property that returns an email passes.
/// Producer unit tests (<c>AuditActorLabelProducerTests</c>) pin the accessors that exist, and
/// <c>AuditRepository</c> drops any label paired with a non-service <c>actorKind</c> at write
/// time. The parameter check is textual: it accepts an identifier whose nearest preceding
/// declaration reads as a parameter, so a label smuggled through a field, or through a helper
/// whose parameter shares the name, is reviewer-enforced. A positional argument is only read
/// on the three <c>Log*</c> calls; <c>LogSystemAsync</c>'s connection overload is told apart by
/// its first argument not looking like an action.</para>
///
/// <para>Opt out with <c>// audit-actor-ok: &lt;reason&gt;</c> in the 5 lines above the call (for
/// rule 2, above or on the line carrying the label). A bare marker with no reason after the
/// colon is not honoured, matching the convention in <see cref="AuditAttributionComplianceTests"/>
/// and <c>// xtenant:</c>.</para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed partial class AuditActorIdComplianceTests
{
    private readonly ITestOutputHelper _output;

    public AuditActorIdComplianceTests(ITestOutputHelper output) => _output = output;

    private const string OptOut = "audit-actor-ok:";

    private static readonly string[] Markers = [".LogAsync(", ".LogActivityAsync(", ".LogSystemAsync("];

    // 0-based positional slot of `actorLabel`, derived from AuditRepository's own declarations
    // rather than hard-coded: a reordered parameter list would otherwise move the check onto the
    // wrong argument and keep passing. LogSystemAsync's connection overload prepends (conn, tx).
    private static readonly Lazy<LabelSlots> Slots = new(ReadLabelSlots);

    private sealed record LabelSlots(int LogAsync, int LogActivityAsync, int LogSystemAsync, int LogSystemAsyncConnection);

    private static LabelSlots ReadLabelSlots()
    {
        string file = SourceRoots.AllCSharpFiles()
            .Single(f => Path.GetFileName(f) == "AuditRepository.cs");
        // Comments inside a parameter list carry commas and parentheses of their own.
        string text = CommentText().Replace(File.ReadAllText(file), "");

        int SlotOf(string method, bool connectionOverload)
        {
            foreach (Match decl in Regex.Matches(text, @"public\s+(?:async\s+)?Task\s+" + method + @"\s*\(([^)]*)\)"))
            {
                string[] parameters = decl.Groups[1].Value.Split(',');
                bool isConnection = parameters[0].TrimStart().StartsWith("DbConnection", StringComparison.Ordinal);
                if (isConnection != connectionOverload)
                {
                    continue;
                }

                int slot = Array.FindIndex(parameters, p => ActorLabelWord().IsMatch(p));
                if (slot >= 0)
                {
                    return slot;
                }
            }

            throw new InvalidOperationException(
                $"AuditRepository.{method} (connection overload: {connectionOverload}) declares no actorLabel parameter; the positional rule cannot be applied.");
        }

        return new LabelSlots(
            SlotOf("LogAsync", connectionOverload: false),
            SlotOf("LogActivityAsync", connectionOverload: false),
            SlotOf("LogSystemAsync", connectionOverload: false),
            SlotOf("LogSystemAsync", connectionOverload: true));
    }

    // Receiver of a `.ActorKind` / `.UserId` / `.AuditActorId` member access — `token`,
    // `token?`, `args.Token`, `ctx.Token?`. Normalized by stripping `?` so the nullable and
    // non-nullable spellings of the same receiver compare equal.
    [GeneratedRegex(@"([A-Za-z_][\w.?]*)\.ActorKind\b")]
    private static partial Regex ActorKindRef();

    [GeneratedRegex(@"([A-Za-z_][\w.?]*)\.UserId\b")]
    private static partial Regex UserIdRef();

    // Line and block comments, which carry commas and parentheses of their own.
    [GeneratedRegex(@"//[^\n]*|/\*.*?\*/", RegexOptions.Singleline)]
    private static partial Regex CommentText();

    [GeneratedRegex(@"\bactorLabel\b")]
    private static partial Regex ActorLabelWord();

    // The `name:` prefix of a named argument, excluding a `::` alias qualifier.
    [GeneratedRegex(@"^([A-Za-z_]\w*)\s*:(?!:)")]
    private static partial Regex NamedArgumentPrefix();

    [Fact]
    public void AuditWritesIdentifyATokenActorByAuditActorIdNotUserId()
    {
        var violations = new List<string>();

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                string? marker = Markers.FirstOrDefault(m => lines[i].Contains(m, StringComparison.Ordinal));
                if (marker is null)
                {
                    continue;
                }

                string call = ReadCallExpression(lines, i, marker);
                var kindReceivers = Receivers(ActorKindRef(), call);
                if (kindReceivers.Count == 0)
                {
                    continue;
                }

                var offenders = Receivers(UserIdRef(), call).Intersect(kindReceivers, StringComparer.Ordinal).ToList();
                if (offenders.Count == 0 || HasOptOutAbove(lines, i))
                {
                    continue;
                }

                string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
                violations.Add(
                    $"{rel}:{i + 1}: audit write pairs `{offenders[0]}.UserId` with " +
                    $"`{offenders[0]}.ActorKind`. A service token has no UserId, so this records a " +
                    $"NULL actor under a 'service' kind and the row reads as anonymous. Use " +
                    $"`{offenders[0]}.AuditActorId`, or opt out with `// {OptOut} <reason>`.");
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} audit write(s) identify a token actor by UserId. See test output.");
        }
    }

    /// <summary>
    /// The gate is worthless if its own matcher does not fire, and a scan that silently matches
    /// nothing is the "green-but-blind" failure this family exists to avoid. These pin the
    /// detector against the broken and the fixed spelling directly.
    /// </summary>
    [Fact]
    public void DetectorMatchesTheBrokenPairingAndAcceptsTheFixedOne()
    {
        string[] broken = ["await _audit.LogActivityAsync(orgId, \"oci\", purl, \"push\", actorId: token?.UserId, actorKind: token?.ActorKind, ct: ct);"];
        string call = ReadCallExpression(broken, 0, ".LogActivityAsync(");
        Assert.Contains("token", Receivers(UserIdRef(), call).Intersect(Receivers(ActorKindRef(), call), StringComparer.Ordinal));

        string[] fixedUp = ["await _audit.LogActivityAsync(orgId, \"oci\", purl, \"push\", actorId: token?.AuditActorId, actorKind: token?.ActorKind, ct: ct);"];
        string fixedCall = ReadCallExpression(fixedUp, 0, ".LogActivityAsync(");
        Assert.Empty(Receivers(UserIdRef(), fixedCall).Intersect(Receivers(ActorKindRef(), fixedCall), StringComparer.Ordinal));
    }

    /// <summary>
    /// A different receiver supplying the user id is not this defect — a call may legitimately
    /// name a JWT-session user while characterizing the kind from a constant. The gate must not
    /// fire on that, or it trains people to add markers to correct code.
    /// </summary>
    [Fact]
    public void DetectorIgnoresDifferentReceivers()
    {
        string[] fine = ["await _audit.LogAsync(\"user.password_reset\", orgId, actorId: consumed.UserId, actorKind: token.ActorKind, ct: ct);"];
        string call = ReadCallExpression(fine, 0, ".LogAsync(");
        Assert.Empty(Receivers(UserIdRef(), call).Intersect(Receivers(ActorKindRef(), call), StringComparer.Ordinal));
    }

    [Fact]
    public void OptOutMarkerRequiresAReason()
    {
        Assert.True(LineCarriesReasonedMarker($"// {OptOut} JWT-session caller; actor is the user"));
        Assert.False(LineCarriesReasonedMarker($"// {OptOut}"));
        Assert.False(LineCarriesReasonedMarker($"// {OptOut}   "));
    }

    [Fact]
    public void AuditActorLabelsComeFromADerivedAccessor()
    {
        var violations = new List<string>();
        int scanned = 0;

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string[] lines = File.ReadAllLines(file);
            var findings = FindUnderivedLabels(lines, out int sites);
            scanned += sites;
            string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
            foreach (var (line, value) in findings)
            {
                violations.Add(
                    $"{rel}:{line + 1}: actor label `{value}` is not read from a derived accessor. " +
                    $"actor_label holds a service actor's name only; pass `null`, " +
                    $"`token.AuditActorLabel`, `actor.Label` (SystemActor / ResolvedActor), or a " +
                    $"same-named parameter, or opt out with `// {OptOut} <reason>`.");
            }
        }

        // Green-but-blind guard: the tree writes labels at dozens of sites, so a scan that saw
        // none has stopped matching rather than found the tree clean.
        _output.WriteLine($"Rule 2 inspected {scanned} label site(s).");
        Assert.True(scanned > 20, $"Rule 2 inspected only {scanned} label site(s); the matcher has stopped firing.");

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} actor label(s) bypass a derived accessor. See test output.");
        }
    }

    [Theory]
    [InlineData("await _audit.LogAsync(\"x\", orgId, actorId: user.Id, actorKind: ActorKinds.User, actorLabel: user.Email, ct: ct);")]
    [InlineData("await _audit.LogAsync(\"x\", orgId, actorLabel: \"alice@example.com\", ct: ct);")]
    [InlineData("await _audit.LogSystemAsync(action: \"x\", actorId: admin.Id, actorLabel: admin.Name, ct: ct);")]
    [InlineData("await _audit.LogActivityAsync(orgId, \"npm\", purl, \"push\", actorId, kind, detail, ip, user.Email, ct);")]
    [InlineData("await _audit.LogAsync(\"x\", orgId, actorId, kind, \"npm\", purl, detail, ip, \"alice\", ct);")]
    [InlineData("await _audit.LogSystemAsync(\"x\", actorId, orgId, detail, ip, kind, user.Email, ct);")]
    [InlineData("await _audit.LogSystemAsync(conn, tx, \"x\", actorId, orgId, detail, ip, kind, user.Email, ct);")]
    [InlineData("var req = new BlockGateRequest(orgId, eco, purl, AuditActorLabel: user.Email);")]
    [InlineData("var req = gate with { AuditActorLabel = user.Email };")]
    [InlineData("await _audit.LogAsync(\"x\", orgId, actorLabel: token?.AuditActorLabel ?? user.Email, ct: ct);")]
    [InlineData("await _audit.LogAsync(\"x\", orgId, actorLabel: GetLabel(), ct: ct);")]
    public void Rule2RejectsALabelNotReadFromADerivedAccessor(string snippet)
    {
        var findings = FindUnderivedLabels([snippet], out _);
        Assert.Single(findings);
    }

    [Theory]
    [InlineData("await _audit.LogAsync(\"x\", orgId, actorId: token?.AuditActorId, actorKind: token?.ActorKind, actorLabel: token?.AuditActorLabel, ct: ct);")]
    [InlineData("await _audit.LogAsync(\"x\", orgId, actorLabel: token.AuditActorLabel, ct: ct);")]
    [InlineData("await _audit.LogAsync(\"x\", orgId, actorLabel: ctx.Token?.AuditActorLabel, ct: ct);")]
    [InlineData("await _audit.LogSystemAsync(action: \"x\", actorId: actor.Id, actorKind: actor.Kind, actorLabel: actor.Label, ct: ct);")]
    [InlineData("await _audit.LogAsync(\"x\", orgId, actorLabel: actor?.Label, ct: ct);")]
    [InlineData("await _audit.LogAsync(\"x\", orgId, actorLabel: null, ct: ct);")]
    [InlineData("await _audit.LogActivityAsync(orgId, \"npm\", purl, \"push\", actorId, kind, detail, ip, token?.AuditActorLabel, ct);")]
    [InlineData("await _audit.LogActivityAsync(orgId, \"npm\", purl, \"push\", actorId, kind, detail, ip, null, ct);")]
    [InlineData("await _audit.LogSystemAsync(conn, tx, \"x\", actorId, orgId, detail, ip, actor.Kind, actor.Label, ct);")]
    [InlineData("var req = new BlockGateRequest(orgId, eco, purl, AuditActorLabel: request.AuditActorLabel);")]
    [InlineData("public sealed record ProxyContext(string OrgId, string? AuditActorLabel = null);")]
    public void Rule2AcceptsADerivedLabel(string snippet)
    {
        var findings = FindUnderivedLabels([snippet], out int sites);
        Assert.Empty(findings);
        Assert.True(sites > 0, "The snippet carries a label, so the scanner must have inspected it.");
    }

    /// <summary>
    /// A parameter passed straight through is accepted because its own callers are checked; a
    /// local that merely shares the name is not, since nothing upstream of it is checked. The
    /// deconstructed local is the shape the SBOM controllers used before
    /// <c>ResolveActorAsync</c> returned a <see cref="Dependably.Infrastructure.ResolvedActor"/>.
    /// </summary>
    [Fact]
    public void Rule2AcceptsAPassThroughParameterButNotALocalOfTheSameName()
    {
        string[] parameter =
        [
            "public static BlockGateRequest ForProxy(",
            "    string orgId, string? userId, string? actorKind, string? actorLabel,",
            "    CancellationToken ct = default) => new(",
            "    OrgId: orgId, AuditActorLabel: actorLabel);",
        ];
        Assert.Empty(FindUnderivedLabels(parameter, out _));

        string[] defaulted =
        [
            "private Task WriteAsync(string action, string? actorLabel = null)",
            "{",
            "    return _audit.LogAsync(action, actorLabel: actorLabel);",
            "}",
        ];
        Assert.Empty(FindUnderivedLabels(defaulted, out _));

        string[] deconstructed =
        [
            "(string? actorKind, string? actorLabel) = actorId is null",
            "    ? (null, null)",
            "    : await _ingest.ResolveActorAsync(orgId, actorId, ct);",
            "await _audit.LogAsync(\"x\", orgId, actorKind: actorKind, actorLabel: actorLabel, ct: ct);",
        ];
        Assert.Single(FindUnderivedLabels(deconstructed, out _));

        string[] local =
        [
            "string? actorLabel = user.Email;",
            "await _audit.LogAsync(\"x\", orgId, actorLabel: actorLabel, ct: ct);",
        ];
        Assert.Single(FindUnderivedLabels(local, out _));

        string[] unrelated =
        [
            "string? name = user.Email;",
            "await _audit.LogAsync(\"x\", orgId, actorLabel: name, ct: ct);",
        ];
        Assert.Single(FindUnderivedLabels(unrelated, out _));
    }

    [Fact]
    public void Rule2HonoursAReasonedMarkerAndIgnoresABareOne()
    {
        string[] reasoned =
        [
            $"// {OptOut} the label is a fixed system name, not personal data",
            "await _audit.LogAsync(\"x\", orgId, actorLabel: \"scheduler\", ct: ct);",
        ];
        Assert.Empty(FindUnderivedLabels(reasoned, out _));

        string[] bare =
        [
            $"// {OptOut}",
            "await _audit.LogAsync(\"x\", orgId, actorLabel: \"scheduler\", ct: ct);",
        ];
        Assert.Single(FindUnderivedLabels(bare, out _));
    }

    /// <summary>
    /// A label spelled only in a comment, a string or a doc reference is not a write, and the
    /// scanner must not read it as one, or it trains people to add markers to correct code.
    /// </summary>
    [Fact]
    public void Rule2IgnoresCommentsStringsAndNonLabelMembers()
    {
        string[] noise =
        [
            "/// Non-null for a service token only: <c>TokenRecord.AuditActorLabel</c> derives it.",
            "// actorLabel: user.Email would put an email in the column",
            "_logger.LogWarning(\"actorLabel: {Value}\", value);",
            "string username = token.AuditActorLabel ?? fallback;",
            "bool same = req.AuditActorLabel == other.AuditActorLabel;",
            "public string? AuditActorLabel => Source switch",
        ];
        Assert.Empty(FindUnderivedLabels(noise, out int sites));
        Assert.Equal(0, sites);
    }

    // `actorLabel:` / `AuditActorLabel:` named arguments and `AuditActorLabel =` assignments
    // (object initializers, `with` expressions, record parameter defaults). The negative
    // lookbehind keeps `foo.actorLabel:` and `xAuditActorLabel:` out; the lookahead keeps `::`,
    // `==` and `=>` out.
    [GeneratedRegex(@"(?<![\w.])(?:(?<name>actorLabel|AuditActorLabel):(?!:)|(?<name>AuditActorLabel)\s*=(?![=>]))")]
    private static partial Regex LabelSite();

    // A member access ending in a derived label accessor: `token.AuditActorLabel`,
    // `ctx.Token?.AuditActorLabel`, `actor.Label`, `actor?.Label`.
    [GeneratedRegex(@"^[A-Za-z_]\w*(?:[?!]?\.[A-Za-z_]\w*)*[?!]?\.(?:AuditActorLabel|Label)$")]
    private static partial Regex DerivedAccessor();

    private static readonly HashSet<string> PassThroughNames = new(StringComparer.Ordinal) { "actorLabel", "AuditActorLabel" };

    /// <summary>
    /// Every label site in <paramref name="rawLines"/> whose value is not a derived accessor,
    /// <c>null</c>, or a pass-through parameter, as (0-based line, value). <paramref name="sites"/>
    /// counts every label site inspected, so a caller can tell a clean scan from a blind one.
    /// </summary>
    private static List<(int Line, string Value)> FindUnderivedLabels(string[] rawLines, out int sites)
    {
        string[] lines = rawLines.Select(BlankStringsAndComment).ToArray();
        int[] lineStarts = new int[lines.Length];
        var text = new StringBuilder();
        for (int i = 0; i < lines.Length; i++)
        {
            lineStarts[i] = text.Length;
            text.Append(lines[i]).Append('\n');
        }

        string joined = text.ToString();
        var findings = new List<(int, string)>();
        var seen = new HashSet<int>();
        sites = 0;

        foreach (Match m in LabelSite().Matches(joined))
        {
            int valueStart = m.Index + m.Length;
            string value = ReadArgumentValue(joined, valueStart);
            int line = LineOf(lineStarts, m.Index);
            sites++;
            seen.Add(valueStart);
            if (!IsDerived(value, joined, m.Index) && !HasOptOutNear(rawLines, line))
            {
                findings.Add((line, value));
            }
        }

        // The positional slot on the three Log* writers, read through the call-expression reader.
        for (int i = 0; i < rawLines.Length; i++)
        {
            string? marker = Markers.FirstOrDefault(mk => lines[i].Contains(mk, StringComparison.Ordinal));
            if (marker is null)
            {
                continue;
            }

            string call = ReadCallExpression(lines, i, marker);
            var args = SplitTopLevelArgs(call, marker);
            int slot = marker switch
            {
                ".LogAsync(" => Slots.Value.LogAsync,
                ".LogActivityAsync(" => Slots.Value.LogActivityAsync,
                _ => IsConnectionOverload(args) ? Slots.Value.LogSystemAsyncConnection : Slots.Value.LogSystemAsync,
            };

            if (args.Count <= slot || args[slot].Name is not null)
            {
                continue;
            }

            sites++;
            int callStart = lineStarts[i] + lines[i].IndexOf(marker, StringComparison.Ordinal);
            if (!IsDerived(args[slot].Value, joined, callStart) && !HasOptOutNear(rawLines, i))
            {
                findings.Add((i, args[slot].Value));
            }
        }

        return findings;
    }

    private static bool IsDerived(string value, string text, int siteIndex)
    {
        string v = value.Trim();
        return v == "null"
            || DerivedAccessor().IsMatch(v)
            || (PassThroughNames.Contains(v) && NearestDeclarationIsParameter(text, v, siteIndex));
    }

    // `LogSystemAsync(conn, tx, action, …)` versus `LogSystemAsync(action, …)`: an action is a
    // string literal, an AuditActions constant, or a local named for it; a connection is not.
    private static bool IsConnectionOverload(List<(string? Name, string Value)> args)
    {
        if (args.Count < 3 || args[0].Name is not null)
        {
            return false;
        }

        string first = args[0].Value;
        bool looksLikeAction = first.StartsWith('"') || first.StartsWith("$\"", StringComparison.Ordinal)
            || first.StartsWith("@\"", StringComparison.Ordinal)
            || first.Contains("AuditActions.", StringComparison.Ordinal)
            || first.Contains("action", StringComparison.OrdinalIgnoreCase);
        return !looksLikeAction;
    }

    private static readonly HashSet<string> NonTypeKeywords = new(StringComparer.Ordinal)
    {
        "return", "await", "is", "as", "new", "in", "out", "ref", "case", "yield", "throw", "else",
        "when", "and", "or", "not", "var", "using", "nameof", "typeof", "default",
    };

    /// <summary>
    /// True when the nearest declaration of <paramref name="name"/> before
    /// <paramref name="siteIndex"/> is a method, constructor, lambda or record parameter — a
    /// typed name followed by <c>,</c>, <c>)</c> or a default value that ends at one, inside a
    /// parenthesized list that is not a deconstruction. A local (<c>string? x = …;</c>), a
    /// deconstruction (<c>(string? a, string? x) = …</c>), a <c>var (…)</c> tuple, an
    /// <c>out</c> or pattern variable, or no declaration at all is not a parameter.
    /// </summary>
    private static bool NearestDeclarationIsParameter(string text, string name, int siteIndex)
    {
        var decl = new Regex(@"(?<![\w.])(?<type>[A-Za-z_][\w.]*(?:<[^<>;{}]*>)?\??(?:\[\])?)\s+" + Regex.Escape(name) + @"(?![\w])");
        var varTuple = new Regex(@"\bvar\s*\([^;)]*(?<![\w.])" + Regex.Escape(name) + @"(?![\w])");

        Match? best = null;
        foreach (Match m in decl.Matches(text[..siteIndex]))
        {
            if (!NonTypeKeywords.Contains(m.Groups["type"].Value))
            {
                best = m;
            }
        }

        var tuple = varTuple.Matches(text[..siteIndex]).LastOrDefault();
        if (best is null || (tuple is not null && tuple.Index > best.Index))
        {
            return false;
        }

        string before = text[..best.Index].TrimEnd();
        if (before.EndsWith("out", StringComparison.Ordinal) || before.EndsWith("is", StringComparison.Ordinal))
        {
            return false;
        }

        int i = best.Index + best.Length;
        i = SkipWhitespace(text, i);
        if (i < text.Length && text[i] == '=' && i + 1 < text.Length && text[i + 1] is not ('=' or '>'))
        {
            int valueStart = SkipWhitespace(text, i + 1);
            i = SkipWhitespace(text, valueStart + ReadArgumentValue(text, valueStart).Length);
        }

        if (i >= text.Length || text[i] is not (',' or ')'))
        {
            return false;
        }

        int close = MatchingCloseParen(text, i);
        if (close < 0)
        {
            return false;
        }

        int after = SkipWhitespace(text, close + 1);
        bool deconstruction = after < text.Length && text[after] == '='
            && (after + 1 >= text.Length || text[after + 1] is not ('=' or '>'));
        return !deconstruction;
    }

    private static int SkipWhitespace(string text, int i)
    {
        while (i < text.Length && char.IsWhiteSpace(text[i]))
        {
            i++;
        }

        return i;
    }

    // Index of the `)` closing the parenthesized list that position `from` sits in, or -1.
    private static int MatchingCloseParen(string text, int from)
    {
        int depth = 0;
        for (int i = from; i < text.Length; i++)
        {
            char c = text[i];
            if (c is '(' or '[' or '{')
            {
                depth++;
            }
            else if (c is ']' or '}')
            {
                depth--;
            }
            else if (c == ')')
            {
                if (depth == 0)
                {
                    return i;
                }

                depth--;
            }
            else if (c == ';' && depth == 0)
            {
                return -1;
            }
        }

        return -1;
    }

    // The argument or initializer value starting at `start`, up to the top-level `,`, `)`, `}`,
    // `]` or `;` that ends it.
    private static string ReadArgumentValue(string text, int start)
    {
        int depth = 0;
        int i = start;
        for (; i < text.Length; i++)
        {
            char c = text[i];
            if (c is '(' or '[' or '{')
            {
                depth++;
            }
            else if (c is ')' or ']' or '}')
            {
                if (depth == 0)
                {
                    break;
                }

                depth--;
            }
            else if ((c == ',' || c == ';') && depth == 0)
            {
                break;
            }
        }

        return text[start..i].Trim();
    }

    private static int LineOf(int[] lineStarts, int index)
    {
        int line = Array.BinarySearch(lineStarts, index);
        return line >= 0 ? line : ~line - 1;
    }

    private static bool HasOptOutNear(string[] lines, int index)
    {
        for (int i = Math.Max(0, index - 5); i <= index && i < lines.Length; i++)
        {
            if (LineCarriesReasonedMarker(lines[i]))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Replaces the contents of <c>"…"</c> string literals with spaces and drops a trailing
    /// <c>//</c> comment, so a label spelled inside a string, a log template or a doc comment is
    /// never read as a write. Literals keep their quotes, so a literal label value still reads as
    /// a literal. A raw or multi-line string is approximated line by line, which is enough for
    /// the argument lists this gate reads.
    /// </summary>
    private static string BlankStringsAndComment(string line)
    {
        var sb = new StringBuilder(line.Length);
        bool inString = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (!inString && c == '/' && i + 1 < line.Length && line[i + 1] == '/')
            {
                break;
            }

            if (c == '"' && (i == 0 || line[i - 1] != '\\'))
            {
                inString = !inString;
                sb.Append(c);
            }
            else
            {
                sb.Append(inString ? ' ' : c);
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Splits the argument list of a call expression read by <see cref="ReadCallExpression"/>
    /// into top-level (name, value) pairs, respecting nested brackets, so a comma inside a nested
    /// call or initializer does not split an argument in two.
    /// </summary>
    private static List<(string? Name, string Value)> SplitTopLevelArgs(string call, string marker)
    {
        int open = call.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
        var result = new List<(string?, string)>();
        int i = open;
        while (i < call.Length)
        {
            string raw = ReadArgumentValue(call, i);
            int end = i + (call[i..].Length - call[i..].TrimStart().Length) + raw.Length;
            end = SkipWhitespace(call, end);
            if (raw.Length > 0)
            {
                var named = NamedArgumentPrefix().Match(raw);
                result.Add(named.Success
                    ? (named.Groups[1].Value, raw[named.Length..].Trim())
                    : (null, raw));
            }

            if (end >= call.Length || call[end] != ',')
            {
                break;
            }

            i = end + 1;
        }

        return result;
    }

    private static HashSet<string> Receivers(Regex pattern, string call)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match m in pattern.Matches(call))
        {
            set.Add(m.Groups[1].Value.Replace("?", "", StringComparison.Ordinal));
        }

        return set;
    }

    private static bool HasOptOutAbove(string[] lines, int index)
    {
        for (int i = Math.Max(0, index - 5); i < index; i++)
        {
            if (LineCarriesReasonedMarker(lines[i]))
            {
                return true;
            }
        }

        return false;
    }

    private static bool LineCarriesReasonedMarker(string line)
    {
        int at = line.IndexOf(OptOut, StringComparison.Ordinal);
        return at >= 0 && line[(at + OptOut.Length)..].Trim().Length > 0;
    }

    private static string ReadCallExpression(string[] lines, int start, string marker)
    {
        int depth = 0;
        bool started = false;
        var buf = new StringBuilder();
        for (int i = start; i < lines.Length; i++)
        {
            string line = i == start ? lines[i][lines[i].IndexOf(marker, StringComparison.Ordinal)..] : lines[i];
            line = StripLineComment(line);
            buf.Append(line).Append('\n');

            foreach (char c in line)
            {
                if (c == '(')
                {
                    depth++;
                    started = true;
                }
                else if (c == ')')
                {
                    depth--;
                }
            }

            if (started && depth <= 0)
            {
                break;
            }
        }

        return buf.ToString();
    }

    // Strips a trailing line comment so a marker or a member access quoted inside a comment
    // cannot be read as part of the call's argument list.
    private static string StripLineComment(string line)
    {
        int at = line.IndexOf("//", StringComparison.Ordinal);
        return at >= 0 ? line[..at] : line;
    }
}
