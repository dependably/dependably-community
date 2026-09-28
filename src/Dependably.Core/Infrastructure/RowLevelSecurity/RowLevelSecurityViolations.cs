using Dependably.Infrastructure.Observability;
using Npgsql;

namespace Dependably.Infrastructure.RowLevelSecurity;

/// <summary>
/// Recognises a statement refused by the row-level security backstop and counts it on
/// <see cref="DependablyMeter.RowLevelSecurityViolations"/>. Called from the two places an
/// unhandled failure surfaces — the request pipeline's terminal handler and a background job's
/// failed tick — so a missing tenant context is alertable instead of just another logged error.
/// </summary>
public static class RowLevelSecurityViolations
{
    // insufficient_privilege: Postgres reports a WITH CHECK failure under this state, with the
    // "violates row-level security policy" message distinguishing it from a missing grant.
    private const string InsufficientPrivilegeSqlState = "42501";

    /// <summary>The bounded <c>reason</c> for an RLS refusal anywhere in the chain, or null.</summary>
    public static string? Classify(Exception? exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is not PostgresException pg)
            {
                continue;
            }

            string? reason = pg.SqlState switch
            {
                PostgresRowLevelSecurityInstaller.NoTenantContextSqlState => "no_tenant_context",
                PostgresRowLevelSecurityInstaller.SessionMismatchSqlState => "session_mismatch",
                InsufficientPrivilegeSqlState when pg.MessageText.Contains("row-level security", StringComparison.Ordinal)
                    => "policy_violation",
                // The WITH CHECK refusal shares its SQLSTATE with a missing grant and is told apart
                // only by message text. Counting an unrecognised 42501 under its own reason keeps a
                // reworded server message from silently dropping refusals out of the metric.
                InsufficientPrivilegeSqlState => "insufficient_privilege",
                _ => null,
            };
            if (reason is not null)
            {
                return reason;
            }
        }

        return null;
    }

    /// <summary>Counts <paramref name="exception"/> when it is an RLS refusal; returns whether it was.</summary>
    public static bool Record(Exception? exception)
    {
        if (Classify(exception) is not { } reason)
        {
            return false;
        }

        DependablyMeter.RowLevelSecurityViolations.Add(1, new KeyValuePair<string, object?>("reason", reason));
        return true;
    }
}
