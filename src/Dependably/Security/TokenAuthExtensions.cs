using System.Text;
using Dependably.Infrastructure;

namespace Dependably.Security;

/// <summary>
/// Helpers for extracting and resolving registry auth tokens from HTTP requests.
/// npm uses Bearer; PyPI and NuGet use Basic (token as password, username ignored).
/// </summary>
public static class TokenAuthExtensions
{
    /// <summary>
    /// Resolves the token from the request's Authorization header and verifies it belongs
    /// to <paramref name="expectedOrgId"/>. Cross-tenant tokens (presented with a value
    /// resolving to a different org) are returned as <c>null</c> — same shape as "no token
    /// at all", so existing <c>token is null</c> branches in the controllers respect
    /// <c>AnonymousPull</c> consistently for both anonymous and wrong-org requests.
    /// Use this for any read path; publish paths should resolve the token and then assert
    /// <c>token.OrgId == orgId</c> explicitly so the rejection is 401 with WWW-Authenticate.
    /// </summary>
    public static async Task<TokenRecord?> ResolveTokenAsync(
        this HttpRequest request,
        TokenRepository tokens,
        string expectedOrgId,
        CancellationToken ct = default)
    {
        var token = await request.ResolveTokenAsync(tokens, ct);
        return token is null ? null : token.OrgId == expectedOrgId ? token : null;
    }

    /// <summary>
    /// Resolves the token from the request's Authorization header (Bearer or Basic).
    /// Returns null if no token is present or it cannot be resolved.
    /// Does NOT enforce tenant binding — callers that proceed to write or to serve
    /// tenant-scoped data must call the org-scoped overload or check
    /// <c>token.OrgId == orgId</c> themselves.
    /// </summary>
    public static async Task<TokenRecord?> ResolveTokenAsync(
        this HttpRequest request,
        TokenRepository tokens,
        CancellationToken ct = default)
    {
        string? auth = request.Headers.Authorization.FirstOrDefault();
        if (auth is null)
        {
            Dependably.Infrastructure.Observability.DependablyMeter.TokenAuthRequests.Add(
                1, new KeyValuePair<string, object?>("outcome", "no_auth"));
            return null;
        }

        string? raw = null;

        if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            raw = auth["Bearer ".Length..].Trim();
        }
        else if (auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            string encoded = auth["Basic ".Length..].Trim();
            try
            {
                string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                // format is user:token — take everything after the first colon as the token
                int colonIdx = decoded.IndexOf(':');
                if (colonIdx >= 0)
                {
                    raw = decoded[(colonIdx + 1)..];
                }
            }
            catch
            {
                Dependably.Infrastructure.Observability.DependablyMeter.TokenAuthRequests.Add(
                    1, new KeyValuePair<string, object?>("outcome", "invalid"));
                return null;
            }
        }

        if (string.IsNullOrEmpty(raw))
        {
            Dependably.Infrastructure.Observability.DependablyMeter.TokenAuthRequests.Add(
                1, new KeyValuePair<string, object?>("outcome", "invalid"));
            return null;
        }

        var resolved = await tokens.ResolveAsync(raw, ct);
        Dependably.Infrastructure.Observability.DependablyMeter.TokenAuthRequests.Add(
            1, new KeyValuePair<string, object?>("outcome", resolved is null ? "invalid" : "success"));
        if (resolved is not null && tokens.ShouldTouchLastUsed(resolved.LastUsedAt))
        {
            // Update last_used_at only when the value carried on the resolved record is stale
            // enough to matter. Registry hot paths like npm/pypi install fire many authenticated
            // requests in a tight burst; skipping the write in-process when the timestamp is
            // fresh keeps the semantic no-op from opening a WAL write transaction and queueing
            // behind the single SQLite writer. The in-SQL throttle stays as the cross-process
            // race guard for the write that does go through.
            await tokens.TouchLastUsedAsync(resolved.Id, resolved.Source, ct: ct);
        }
        return resolved;
    }

    /// <summary>
    /// Capability-style permission check. Reads the JSON
    /// <see cref="TokenRecord.Capabilities"/> column as the only source of truth —
    /// issuance always populates it explicitly (see
    /// <c>Capabilities.NormalizeAndAuthorize</c>), so NULL or malformed values
    /// are treated as deny-all.
    /// Honors wildcards (<c>publish:*</c> grants <c>publish:npm</c>; <c>*</c> grants
    /// anything) via <see cref="Capabilities.Grants"/>.
    /// </summary>
    public static bool HasCapability(this TokenRecord token, string required)
    {
        // Reads the per-token cached capability set — parses the underlying JSON exactly
        // once per resolved TokenRecord regardless of how many capability checks a
        // controller action fans out into. Deny-all on NULL/malformed JSON is enforced by
        // TokenRecord.CapabilitySet returning an empty set.
        return Capabilities.Grants(token.CapabilitySet, required);
    }
}
