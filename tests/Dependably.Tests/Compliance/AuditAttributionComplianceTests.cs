using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check enforcing that every audit write carries actor origin (<c>source_ip</c>) and,
/// where there is an actor to characterize, its kind (<c>actor_kind</c>) — so a SOC correlating
/// <c>audit_log</c>/<c>activity</c> rows can rely on both fields being populated rather than
/// discovering, row by row, which call sites bothered.
///
/// <para>
/// Covers <c>AuditRepository.LogAsync</c> and <c>LogActivityAsync</c> in full, and
/// <c>LogSystemAsync</c> (both overloads) for <c>sourceIp</c> only. The <c>actorKind</c> pairing
/// below is deliberately not applied to <c>LogSystemAsync</c>: most <c>scope='system'</c> rows are
/// written by a system_admin JWT session, whose kind is NULL by <c>AuditRepository</c>'s contract
/// (the system audit list joins <c>system_admins</c>, not <c>users</c>), or by the platform itself,
/// so requiring an <see cref="Dependably.Infrastructure.ActorKinds"/> value there would force a
/// fabricated one on the common case. A system-token actor's kind and label reach those rows
/// through <c>SystemActor</c>, which a reviewer, not this gate, holds call sites to.
/// </para>
///
/// <para><b>The rule, deliberately asymmetric:</b></para>
/// <list type="bullet">
///   <item><c>sourceIp</c> is required on every covered call. A request-scoped call site always
///   has one (<c>HttpContext.GetNormalizedRemoteIp()</c> — the full address, never the
///   rate-limit-partition form that collapses IPv6 to a /64); a genuinely actor-less background
///   path (a scheduled sweep, a startup migration) has none, and says so with the opt-out
///   marker below rather than silently omitting the argument.</item>
///   <item><c>actorKind</c> is required only when the call also supplies a real (non-null)
///   <c>actorId</c>, and never on <c>LogSystemAsync</c>. A call with no actor at all (an anonymous login-failure or lockout row, an
///   allowlist block on an unauthenticated pull) is not missing an attribution argument — NULL
///   actor_kind is the documented, correct value for "no actor", exactly as
///   <see cref="Dependably.Infrastructure.ActorKinds"/> spells out. Requiring a kind for those
///   rows would force a fabricated value, which is worse than the current state: it would make
///   an absent actor look like a recorded one. The moment a call names an actor, though, its kind
///   must be recorded alongside it — that pairing is what the SOC needs to resolve "who" from
///   "user or service token".</item>
/// </list>
///
/// <para>
/// Opt out a call that genuinely cannot supply one or both arguments — a scheduled background
/// pass, a single-flight upstream fetch shared by several concurrent callers with no one caller
/// to attribute the shared outcome to — with <c>// audit-attribution-ok: &lt;reason&gt;</c> in the
/// 5 lines above the call. A bare marker with no reason text after the colon is not honoured: the
/// reason is what makes the decision reviewable, the same convention as <c>// xtenant:</c> and
/// <c>// authz-ok:</c>.
/// </para>
///
/// <para>
/// <b>What this gate cannot see:</b> it proves an argument was SUPPLIED, not that its value is
/// correct. A call passing <c>sourceIp: "unknown"</c> or <c>actorKind: ActorKinds.Service</c> for
/// an action a user actually took would still pass — only a reviewer catches a wrong value
/// (this retrofit found and fixed one such bug: <c>ClaimsController</c> was passing its
/// <c>ecosystem</c> string positionally into the <c>actorKind</c> slot). It also cannot verify
/// that a value threaded through a local variable or an object property (<c>request.SourceIp</c>,
/// <c>ctx.SourceIp</c>) ultimately originates from the inbound request rather than a stale or
/// mis-plumbed field — data flow, like <c>OrgIdFilteringComplianceTests</c>' <c>@orgId</c> gap, is
/// outside a static scan's reach. Detection is substring-first (<c>Contains("sourceIp:")</c> /
/// <c>Contains("actorKind:")</c> / <c>Contains("actorId:")</c>), matching the family convention in
/// <see cref="AuditOrgIdComplianceTests"/>, with a positional-argument fallback for the handful of
/// call sites that pass these tersely; comments are stripped from each source line before the
/// positional split runs; a comment containing the literal text of a marker string, however, would
/// pass the substring check for that argument same as everywhere else in this family.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed class AuditAttributionComplianceTests
{
    private readonly ITestOutputHelper _output;
    public AuditAttributionComplianceTests(ITestOutputHelper output) => _output = output;

    private const string OptOut = "audit-attribution-ok:";
    private const int MarkerWindow = 5;

    // Positional slot indices, 0-based, matching AuditRepository's declared parameter order.
    // LogAsync(action, orgId, actorId, actorKind, ecosystem, purl, detail, sourceIp, actorLabel, ct)
    // LogActivityAsync(orgId, ecosystem, purl, eventType, actorId, actorKind, detail, sourceIp, actorLabel, ct)
    // LogSystemAsync(action, actorId, orgId, detail, sourceIp, actorKind, actorLabel, ct)
    // LogSystemAsync(conn, tx, action, …) — the same slots shifted by ConnectionOverloadShift.
    // Each signature appends new optional parameters after sourceIp, deliberately: inserting one
    // mid-signature shifts sourceIp's index and silently blinds the positional fallback below.
    private sealed record MethodShape(int ActorIdIndex, int ActorKindIndex, int SourceIpIndex, bool RequireKindWithActor = true);

    private const string LogSystemMarker = ".LogSystemAsync(";
    private const int ConnectionOverloadShift = 2;

    private static readonly Dictionary<string, MethodShape> Targets = new(StringComparer.Ordinal)
    {
        [".LogAsync("] = new MethodShape(ActorIdIndex: 2, ActorKindIndex: 3, SourceIpIndex: 7),
        [".LogActivityAsync("] = new MethodShape(ActorIdIndex: 4, ActorKindIndex: 5, SourceIpIndex: 7),
        [LogSystemMarker] = new MethodShape(ActorIdIndex: 1, ActorKindIndex: 5, SourceIpIndex: 4, RequireKindWithActor: false),
    };

    [Fact]
    public void EveryAuditWriteCarriesSourceIpAndPairsActorKindWithActorId()
    {
        var violations = new List<string>();

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                string? marker = MatchTarget(lines[i]);
                if (marker is null)
                {
                    continue;
                }

                string call = ReadCallExpression(lines, i, marker);
                string? reason = Evaluate(call, marker);
                if (reason is null || HasOptOutAbove(lines, i))
                {
                    continue;
                }

                string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
                string remedy = Targets[marker].RequireKindWithActor
                    ? "Pass sourceIp (HttpContext.GetNormalizedRemoteIp()) and, when an actorId is present, actorKind"
                    : "Pass sourceIp (HttpContext.GetNormalizedRemoteIp())";
                violations.Add(
                    $"{rel}:{i + 1}: {marker.TrimEnd('(')} call omits attribution ({reason}) — " +
                    $"a SOC cannot resolve origin/actor-kind for this row. {remedy} — or opt out " +
                    $"with `// {OptOut} <reason>` for a genuine background/shared-fetch path.");
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} audit write(s) omit attribution. See test output.");
        }
    }

    /// <summary>
    /// A bare marker with no reason after the colon must not be honoured — otherwise the opt-out
    /// becomes a way to silence the gate without writing down why, which defeats the point of
    /// making the decision reviewable.
    /// </summary>
    [Fact]
    public void OptOutMarkerRequiresAReason()
    {
        Assert.True(LineCarriesReasonedMarker($"// {OptOut} scheduled sweep — no request context"));
        Assert.False(LineCarriesReasonedMarker($"// {OptOut}"));
        Assert.False(LineCarriesReasonedMarker($"// {OptOut}   "));
    }

    /// <summary>
    /// The rule applied to snippets rather than the tree, so its shape is pinned independently of
    /// whichever call sites happen to exist: <c>LogSystemAsync</c> is held to <c>sourceIp</c> on
    /// both overloads without the <c>actorKind</c> pairing, which stays on the other two writers.
    /// </summary>
    [Theory]
    [InlineData("await _audit.LogSystemAsync(action: \"x\", actorId: sub, detail: d, ct: ct);", "missing sourceIp")]
    [InlineData("await _audit.LogSystemAsync(action: \"x\", actorId: sub, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);", null)]
    [InlineData("await _audit.LogSystemAsync(\"x\", sub, null, d, ip, ct: ct);", null)]
    [InlineData("await _audit.LogSystemAsync(\"x\", sub, null, d, null, ct: ct);", "missing sourceIp")]
    [InlineData("await _audit.LogSystemAsync(conn, tx, \"x\", actorId, orgId, detail, ip, ct);", null)]
    [InlineData("await _audit.LogSystemAsync(conn, tx, \"x\", actorId, orgId, detail, null, ct);", "missing sourceIp")]
    [InlineData("await _audit.LogSystemAsync(conn, tx, action: \"x\", orgId: orgId, ct: ct);", "missing sourceIp")]
    [InlineData("await _audit.LogAsync(\"x\", orgId, actorId: u.Id, sourceIp: ip, ct: ct);", "actorId is supplied but actorKind is not")]
    [InlineData("await _audit.LogActivityAsync(orgId, eco, purl, \"x\", actorId: u.Id, sourceIp: ip, ct: ct);", "actorId is supplied but actorKind is not")]
    [InlineData("await _audit.LogAsync(\"x\", orgId, actorId: u.Id, actorKind: k, sourceIp: ip, ct: ct);", null)]
    public void RuleShape(string snippet, string? expectedReason)
    {
        string? marker = MatchTarget(snippet);
        Assert.NotNull(marker);
        Assert.Equal(expectedReason, Evaluate(ReadCallExpression([snippet], 0, marker), marker));
    }

    /// <summary>
    /// The violation reason for one call expression, or null when it carries its attribution.
    /// </summary>
    private static string? Evaluate(string call, string marker)
    {
        var shape = Targets[marker];
        var args = SplitTopLevelArgs(call, marker);
        int shift = marker == LogSystemMarker && IsConnectionOverload(args) ? ConnectionOverloadShift : 0;

        string? actorId = ResolveArg(args, "actorId", shape.ActorIdIndex + shift);
        string? actorKind = ResolveArg(args, "actorKind", shape.ActorKindIndex + shift);
        string? sourceIp = ResolveArg(args, "sourceIp", shape.SourceIpIndex + shift);

        if (!IsRealValue(sourceIp))
        {
            return "missing sourceIp";
        }

        bool kindSatisfied = !shape.RequireKindWithActor || IsRealValue(actorKind) || !IsRealValue(actorId);
        return kindSatisfied ? null : "actorId is supplied but actorKind is not";
    }

    // `LogSystemAsync(conn, tx, action, …)` versus `LogSystemAsync(action, …)`: an action is a
    // string literal, an AuditActions constant, a local named for it, or passed as `action:`; a
    // connection is none of those. The same discrimination AuditActorIdComplianceTests applies.
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

    private static string? MatchTarget(string line)
    {
        foreach (string marker in Targets.Keys)
        {
            if (line.Contains(marker, StringComparison.Ordinal))
            {
                return marker;
            }
        }

        return null;
    }

    /// <summary>
    /// Accumulates the full call expression from its opening line until the parentheses balance,
    /// stripping each line's trailing <c>//</c> comment first (when it sits outside a string on
    /// that line) so a doc comment sitting between two named arguments cannot be mistaken for a
    /// positional argument value.
    /// </summary>
    private static string ReadCallExpression(string[] lines, int start, string marker)
    {
        int depth = 0;
        bool started = false;
        var buf = new System.Text.StringBuilder();
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

    /// <summary>
    /// Strips a trailing <c>//</c> comment from a source line, unless the <c>//</c> sits inside a
    /// string literal (approximated by requiring an even count of unescaped <c>"</c> before it —
    /// good enough for the argument lists this gate reads, which do not embed raw <c>//</c> inside
    /// string literals).
    /// </summary>
    private static string StripLineComment(string line)
    {
        int quoteCount = 0;
        for (int i = 0; i < line.Length - 1; i++)
        {
            if (line[i] == '"' && (i == 0 || line[i - 1] != '\\'))
            {
                quoteCount++;
            }
            else if (line[i] == '/' && line[i + 1] == '/' && quoteCount % 2 == 0)
            {
                return line[..i];
            }
        }

        return line;
    }

    /// <summary>
    /// Splits the argument list of the call expression into top-level (unnamed or named) tokens,
    /// respecting nested <c>()</c>/<c>{}</c>/<c>[]</c> and <c>"..."</c> so a comma inside a nested
    /// object initializer or interpolated string does not split an argument in two.
    /// </summary>
    private static List<(string? Name, string Value)> SplitTopLevelArgs(string call, string marker)
    {
        int open = call.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
        string rest = open <= call.Length ? call[open..] : string.Empty;

        var parts = new List<string>();
        int depth = 0;
        bool inString = false;
        var current = new System.Text.StringBuilder();
        foreach (char c in rest)
        {
            if (c == '"')
            {
                inString = !inString;
            }

            if (!inString)
            {
                if (c is '(' or '{' or '[')
                {
                    depth++;
                }
                else if (c is ')' or '}' or ']')
                {
                    if (depth == 0)
                    {
                        break;
                    }

                    depth--;
                }
                else if (c == ',' && depth == 0)
                {
                    parts.Add(current.ToString());
                    current.Clear();
                    continue;
                }
            }

            current.Append(c);
        }

        if (current.Length > 0)
        {
            parts.Add(current.ToString());
        }

        var result = new List<(string?, string)>();
        foreach (string raw in parts)
        {
            string trimmed = raw.Trim();
            int colon = NamedArgColonIndex(trimmed);
            if (colon > 0)
            {
                result.Add((trimmed[..colon].Trim(), trimmed[(colon + 1)..].Trim()));
            }
            else
            {
                result.Add((null, trimmed));
            }
        }

        return result;
    }

    /// <summary>
    /// Index of the <c>:</c> that makes <paramref name="arg"/> a named argument
    /// (<c>identifier: value</c>), or -1. Requires the identifier to start at position 0 (after
    /// trimming) so a ternary (<c>cond ? a : b</c>) or a nested object's own <c>key: value</c>
    /// deeper in the token is never mistaken for the argument's own name — those never start the
    /// trimmed token at position 0 with a bare identifier immediately before the colon.
    /// </summary>
    private static int NamedArgColonIndex(string arg)
    {
        int i = 0;
        while (i < arg.Length && (char.IsLetterOrDigit(arg[i]) || arg[i] == '_'))
        {
            i++;
        }

        if (i == 0 || i >= arg.Length)
        {
            return -1;
        }

        int j = i;
        while (j < arg.Length && char.IsWhiteSpace(arg[j]))
        {
            j++;
        }

        return j < arg.Length && arg[j] == ':' && (j + 1 >= arg.Length || arg[j + 1] != ':') ? j : -1;
    }

    /// <summary>
    /// Resolves an argument's value by name first (wherever it appears in the argument list —
    /// C# named arguments may appear in any order after the positional prefix), falling back to
    /// the positional slot at <paramref name="positionalIndex"/> when no named form is present.
    /// </summary>
    private static string? ResolveArg(List<(string? Name, string Value)> args, string name, int positionalIndex)
    {
        foreach (var (argName, value) in args)
        {
            if (argName is not null && string.Equals(argName, name, StringComparison.Ordinal))
            {
                return value;
            }
        }

        int position = 0;
        foreach (var (argName, value) in args)
        {
            if (argName is not null)
            {
                continue;
            }

            if (position == positionalIndex)
            {
                return value;
            }

            position++;
        }

        return null;
    }

    private static bool IsRealValue(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Trim() != "null";

    private static bool HasOptOutAbove(string[] lines, int index)
    {
        for (int i = Math.Max(0, index - MarkerWindow); i <= index; i++)
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
        int idx = line.IndexOf(OptOut, StringComparison.Ordinal);
        return idx >= 0 && line[(idx + OptOut.Length)..].Trim().Length > 0;
    }
}
