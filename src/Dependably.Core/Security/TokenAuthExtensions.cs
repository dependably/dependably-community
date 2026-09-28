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
        if (token is null)
        {
            // The inner overload already counted this as a rejection — a second record here
            // would double-count the same refusal under two reasons.
            return null;
        }

        // A live credential aimed at somebody else's tenant. The denial is recorded under the
        // TARGET org, because that is the tenant being probed and the one whose SOC needs to see
        // it — and it is recorded actor-less, with an IP partition rather than a token reference,
        // so the presenting tenant's token id and service-token name never appear in this
        // tenant's audit trail or SIEM feed. Same call the hosted-write paths make from their own
        // inline org checks, so the two shapes cannot drift apart.
        AuthDenialRecorder.RecordTenantMismatch(request.HttpContext, token, expectedOrgId);
        return token.OrgId == expectedOrgId ? token : null;
    }

    /// <summary>
    /// Resolves the token from the request's Authorization header (Bearer, Basic, or the bare
    /// scheme-less form; see <see cref="ExtractAuthorizationToken"/>).
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

        string? raw = ExtractAuthorizationToken(auth);

        if (string.IsNullOrEmpty(raw))
        {
            Dependably.Infrastructure.Observability.DependablyMeter.TokenAuthRequests.Add(
                1, new KeyValuePair<string, object?>("outcome", "invalid"));
            RecordRejection(request);
            return null;
        }

        var resolved = TakePreResolved(request.HttpContext, raw) ?? await tokens.ResolveAsync(raw, ct);
        Dependably.Infrastructure.Observability.DependablyMeter.TokenAuthRequests.Add(
            1, new KeyValuePair<string, object?>("outcome", resolved is null ? "invalid" : "success"));
        if (resolved is null)
        {
            RecordRejection(request);
        }

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
    /// Extracts the raw credential from an <c>Authorization</c> header value in every form
    /// <see cref="ResolveTokenAsync(HttpRequest, TokenRepository, CancellationToken)"/> accepts:
    /// <c>Bearer &lt;token&gt;</c> (npm), <c>Basic base64(user:&lt;token&gt;)</c> (PyPI, NuGet),
    /// and the bare, scheme-less <c>&lt;token&gt;</c> that Cargo and Hex clients send. Returns
    /// null for a malformed Basic value or a value in some other scheme. The resolver and
    /// <see cref="TenantBudgetAttributionMiddleware"/> both read through this one method, so the
    /// credentials the rate-limit attribution recognizes are exactly the ones the protocol
    /// handlers resolve.
    /// </summary>
    internal static string? ExtractAuthorizationToken(string auth)
    {
        if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return auth["Bearer ".Length..].Trim();
        }

        if (auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            string encoded = auth["Basic ".Length..].Trim();
            try
            {
                string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                // format is user:token — take everything after the first colon as the token
                int colonIdx = decoded.IndexOf(':');
                return colonIdx >= 0 ? decoded[(colonIdx + 1)..] : null;
            }
            catch (FormatException)
            {
                return null;
            }
        }

        // Cargo and Hex clients send the credential as the whole header value with no scheme
        // ("authorization: <token>", hex_core's repo_key / api_key, cargo's registry token). A
        // value with a space is some other scheme this resolver does not speak, so the bare form
        // is accepted only when it is exactly one token.
        return auth.Contains(' ', StringComparison.Ordinal) ? null : auth.Trim();
    }

    /// <summary>
    /// The resolution <see cref="TenantBudgetAttributionMiddleware"/> already made for this
    /// request, when it resolved the very credential this overload extracted. It is consumed on
    /// first use, so a later call in the same request resolves afresh. Only a live credential is
    /// ever recorded, so an unresolved one always reaches the repository and its refusal is
    /// counted here as usual.
    /// </summary>
    private static TokenRecord? TakePreResolved(HttpContext context, string raw)
    {
        if (context.Items[TenantBudgetAttributionMiddleware.ResolvedTokenItemKey]
            is not TenantBudgetAttributionMiddleware.PreResolvedToken pre)
        {
            return null;
        }

        context.Items.Remove(TenantBudgetAttributionMiddleware.ResolvedTokenItemKey);
        return string.Equals(pre.RawToken, raw, StringComparison.Ordinal) ? pre.Token : null;
    }

    /// <summary>
    /// Folds one unresolved-credential rejection into the denial accumulator. The counterpart to
    /// the <c>outcome=invalid</c> metric increment beside every call: the meter says how many, and
    /// this says from where and against which route, which is the part a leaked-token
    /// investigation needs. The metric stays — it is the cheap aggregate, and the per-source
    /// record is deliberately the coalesced one.
    /// </summary>
    private static void RecordRejection(HttpRequest request) =>
        AuthDenialRecorder.RecordTokenRejected(
            request.HttpContext, reason: AuthDenialRecorder.ReasonInvalid);

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
