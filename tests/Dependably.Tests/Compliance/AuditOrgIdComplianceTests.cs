using Xunit.Abstractions;

namespace Dependably.Tests.Compliance;

/// <summary>
/// Static check enforcing the rule that every tenant-scoped audit row carries an org.
///
/// <para>
/// <c>AuditRepository.LogAsync</c> writes <c>audit_log</c> at <c>scope='tenant'</c> and its
/// <c>orgId</c> parameter is optional, so omitting it compiles cleanly and silently writes
/// <c>org_id = NULL</c>. Both tenant read surfaces filter on the column —
/// <c>ListAuditAsync</c> (<c>WHERE org_id = @orgId</c>) and the SIEM export
/// <c>ListAuthEventsAsync</c> (<c>AND (@orgId IS NULL OR org_id = @orgId)</c>) — so a NULL-org
/// row is written to the database and then reachable from nowhere: invisible on the tenant
/// audit page AND dropped from that tenant's SIEM feed. The failure is silent in exactly the
/// place silence is most expensive, which is why it is a gate and not a review checklist item.
/// </para>
///
/// <para>
/// A genuinely org-less event belongs in the system realm: call <c>LogSystemAsync</c>
/// (<c>scope='system'</c>), which the operator audit page reads. That is the correct sink for
/// system-admin actions, which have no tenant by construction.
/// </para>
///
/// <para>
/// Opt out a deliberate NULL-org tenant row with <c>// audit-orgid-ok: &lt;reason&gt;</c> in the
/// 5 lines above the call.
/// </para>
/// </summary>
[Trait("Category", "Compliance")]
public sealed class AuditOrgIdComplianceTests
{
    private readonly ITestOutputHelper _output;
    public AuditOrgIdComplianceTests(ITestOutputHelper output) => _output = output;

    private const string OptOut = "audit-orgid-ok:";

    [Fact]
    public void EveryTenantAuditWritePassesOrgId()
    {
        var violations = new List<string>();

        foreach (string file in SourceRoots.AllCSharpFiles())
        {
            string[] lines = File.ReadAllLines(file);
            for (int i = 0; i < lines.Length; i++)
            {
                if (!IsTenantLogCall(lines[i]))
                {
                    continue;
                }

                string call = ReadCallExpression(lines, i);
                if (PassesOrgId(call) || HasOptOutAbove(lines, i))
                {
                    continue;
                }

                string rel = Path.GetRelativePath(SourceRoots.OwningRoot(file), file);
                violations.Add(
                    $"{rel}:{i + 1}: LogAsync writes a scope='tenant' audit row without orgId — " +
                    $"the row lands with org_id=NULL and is unreachable from both the tenant audit " +
                    $"page and the tenant SIEM feed. Pass orgId, or use LogSystemAsync if the event " +
                    $"is genuinely org-less.");
            }
        }

        if (violations.Count > 0)
        {
            foreach (string v in violations)
            {
                _output.WriteLine(v);
            }

            Assert.Fail($"{violations.Count} tenant audit write(s) omit orgId. See test output.");
        }
    }

    /// <summary>
    /// True for a <c>LogAsync(</c> invocation on an audit repository. Matches the member name
    /// rather than a receiver name so it holds regardless of whether the field is <c>_audit</c>,
    /// a local, or an injected parameter. <c>LogSystemAsync</c> and <c>LogActivityAsync</c> both
    /// end in <c>LogAsync</c>'s suffix only by coincidence of naming, so they are excluded
    /// explicitly — neither writes a tenant-scoped audit_log row that this rule governs.
    /// </summary>
    private static bool IsTenantLogCall(string line) =>
        line.Contains(".LogAsync(", StringComparison.Ordinal)
        && !line.Contains(".LogSystemAsync(", StringComparison.Ordinal)
        && !line.Contains(".LogActivityAsync(", StringComparison.Ordinal);

    /// <summary>
    /// Accumulates the full call expression from its opening line until the parentheses balance,
    /// so arguments spread across several lines (the norm here) are inspected as one string.
    /// </summary>
    private static string ReadCallExpression(string[] lines, int start)
    {
        int depth = 0;
        var buf = new System.Text.StringBuilder();
        for (int i = start; i < lines.Length; i++)
        {
            buf.Append(lines[i]).Append(' ');
            foreach (char c in lines[i])
            {
                if (c == '(')
                {
                    depth++;
                }
                else if (c == ')')
                {
                    depth--;
                }
            }

            if (depth <= 0)
            {
                break;
            }
        }

        return buf.ToString();
    }

    /// <summary>
    /// The org is supplied either by name (<c>orgId:</c>) or positionally as the second argument
    /// — <c>LogAsync(action, orgId, actorId, …)</c>. A positional second argument is recognised
    /// as any token that is not itself a named argument.
    /// </summary>
    private static bool PassesOrgId(string call)
    {
        if (call.Contains("orgId:", StringComparison.Ordinal))
        {
            return true;
        }

        int open = call.IndexOf(".LogAsync(", StringComparison.Ordinal) + ".LogAsync(".Length;
        string args = call[open..];

        // Split the top-level argument list on commas that are not nested inside (), {} or "".
        var parts = new List<string>();
        int depth = 0;
        bool inString = false;
        var current = new System.Text.StringBuilder();
        foreach (char c in args)
        {
            if (c == '"')
            {
                inString = !inString;
            }

            if (!inString)
            {
                if (c is '(' or '{')
                {
                    depth++;
                }
                else if (c is ')' or '}')
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

        parts.Add(current.ToString());

        // parts[0] is the action; parts[1], if present and unnamed, is the positional orgId.
        return parts.Count >= 2 && !parts[1].Contains(':', StringComparison.Ordinal)
                                && parts[1].Trim().Length > 0;
    }

    private static bool HasOptOutAbove(string[] lines, int index)
    {
        for (int i = Math.Max(0, index - 5); i <= index; i++)
        {
            if (lines[i].Contains(OptOut, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
