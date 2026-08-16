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
/// <para>Opt out with <c>// audit-actor-ok: &lt;reason&gt;</c> in the 5 lines above the call. A
/// bare marker with no reason after the colon is not honoured, matching the convention in
/// <see cref="AuditAttributionComplianceTests"/> and <c>// xtenant:</c>.</para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed class AuditActorIdComplianceTests
{
    private readonly ITestOutputHelper _output;

    public AuditActorIdComplianceTests(ITestOutputHelper output) => _output = output;

    private const string OptOut = "audit-actor-ok:";

    private static readonly string[] Markers = [".LogAsync(", ".LogActivityAsync("];

    // Receiver of a `.ActorKind` / `.UserId` / `.AuditActorId` member access — `token`,
    // `token?`, `args.Token`, `ctx.Token?`. Normalized by stripping `?` so the nullable and
    // non-nullable spellings of the same receiver compare equal.
    private static readonly Regex ActorKindRef = new(@"([A-Za-z_][\w.?]*)\.ActorKind\b", RegexOptions.Compiled);
    private static readonly Regex UserIdRef = new(@"([A-Za-z_][\w.?]*)\.UserId\b", RegexOptions.Compiled);

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
                var kindReceivers = Receivers(ActorKindRef, call);
                if (kindReceivers.Count == 0)
                {
                    continue;
                }

                var offenders = Receivers(UserIdRef, call).Intersect(kindReceivers, StringComparer.Ordinal).ToList();
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
        Assert.Contains("token", Receivers(UserIdRef, call).Intersect(Receivers(ActorKindRef, call), StringComparer.Ordinal));

        string[] fixedUp = ["await _audit.LogActivityAsync(orgId, \"oci\", purl, \"push\", actorId: token?.AuditActorId, actorKind: token?.ActorKind, ct: ct);"];
        string fixedCall = ReadCallExpression(fixedUp, 0, ".LogActivityAsync(");
        Assert.Empty(Receivers(UserIdRef, fixedCall).Intersect(Receivers(ActorKindRef, fixedCall), StringComparer.Ordinal));
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
        Assert.Empty(Receivers(UserIdRef, call).Intersect(Receivers(ActorKindRef, call), StringComparer.Ordinal));
    }

    [Fact]
    public void OptOutMarkerRequiresAReason()
    {
        Assert.True(LineCarriesReasonedMarker($"// {OptOut} JWT-session caller; actor is the user"));
        Assert.False(LineCarriesReasonedMarker($"// {OptOut}"));
        Assert.False(LineCarriesReasonedMarker($"// {OptOut}   "));
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
