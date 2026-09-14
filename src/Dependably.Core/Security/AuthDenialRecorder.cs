using Microsoft.AspNetCore.Routing;

namespace Dependably.Security;

/// <summary>
/// The one place a protocol-plane credential or capability refusal is turned into a counted
/// denial. Every seam calls a method here; none of them build an <see cref="AuthDenialKey"/> or
/// reach for <see cref="AuthDenialAuditCoalescer"/> themselves, because the three decisions that
/// make these rows safe — which org they are attributed to, what goes in the partition, and that
/// the route is a template and not a path — are decisions that must be made identically at
/// seventeen call sites across eight handlers.
///
/// <para>
/// <b>Nothing is written here.</b> A call folds one denial into the open accumulation window and
/// returns; <c>AuthDenialAuditFlushService</c> writes one row per key per window. That is what
/// keeps an unauthenticated caller from choosing the audit write rate, and it is why every method
/// returns void and swallows a missing service rather than failing: the 401/403 is the security
/// decision and it has already been made.
/// </para>
///
/// <para>
/// <b>A rejection is "a credential was presented and did not resolve", not "a 401 was produced".</b>
/// With <c>AnonymousPull</c> on, an unresolved token is served 200 as anonymous — the request
/// succeeds and the credential was still refused, which is exactly the leaked-PAT-still-being-retried
/// case these events exist to make visible.
/// </para>
///
/// <para>
/// <b>Reason vocabulary is <c>invalid</c> and <c>tenant_mismatch</c> only.</b> The token lookup
/// folds expiry and owner account status into its predicate, so an expired token, a disabled
/// owner and a garbage string are indistinguishable at every seam — they all return null. A
/// separate <c>expired</c> name would be one no writer could ever emit, and an event name nobody
/// writes is worse than an absent one: a rule built on it reads as covered while matching nothing.
/// </para>
/// </summary>
public static class AuthDenialRecorder
{
    /// <summary>A credential was presented on a protocol route and did not resolve to a usable token.</summary>
    public const string TokenRejectedAction = "auth.token.rejected";

    /// <summary>A resolved credential lacked the capability the route demanded.</summary>
    public const string CapabilityDeniedAction = "auth.capability.denied";

    /// <summary>The presented secret resolved to nothing — unknown, revoked, expired or malformed.</summary>
    public const string ReasonInvalid = "invalid";

    /// <summary>The secret resolved to a live token belonging to a different tenant.</summary>
    public const string ReasonTenantMismatch = "tenant_mismatch";

    /// <summary>The credential resolved and was refused on its capability set.</summary>
    public const string ReasonInsufficientCapability = "insufficient_capability";

    /// <summary>
    /// Route value for a denial raised where no endpoint has been selected. Never a request path
    /// — a path carries a package name, which is tenant data inside an attacker-controlled write
    /// and would give the coalescing key one value per package.
    /// </summary>
    internal const string UnknownRoute = "unknown";

    /// <summary>Granted-capability rendering for a credential that carries none.</summary>
    internal const string NoCapabilities = "none";

    /// <summary>
    /// Marks that this request presented a credential the token scheme could not resolve. The
    /// authenticate step sets it and writes nothing: on a dual-scheme management route ASP.NET
    /// runs both schemes against the same <c>Authorization: Bearer</c> header, so the token
    /// scheme fails on every JWT-session request while the request itself succeeds. Only the
    /// challenge step — reached solely when the request really does end unauthorized — turns the
    /// flag into a denial.
    /// </summary>
    private const string UnresolvedCredentialItemKey = "Dependably.AuthDenial.UnresolvedCredential";

    /// <summary>
    /// Records that a presented credential did not resolve. <paramref name="orgId"/> is the
    /// tenant whose feed the denial belongs in — for a cross-tenant presentation that is the
    /// <em>target</em> org, and the row is actor-less by construction so the presenting tenant's
    /// token id and service-token name never land in the target tenant's audit trail.
    /// </summary>
    public static void RecordTokenRejected(
        HttpContext? http,
        string reason,
        string? ecosystem = null,
        string? orgId = null)
    {
        var coalescer = Coalescer(http);
        if (coalescer is null)
        {
            return;
        }

        string route = RouteTemplate(http);
        coalescer.Record(
            new AuthDenialKey
            {
                Action = TokenRejectedAction,
                OrgId = orgId ?? ResolveOrgId(http),
                // The IP partition, never a token reference: the only rejection that has a
                // resolved token behind it is the cross-tenant one, and naming that token under
                // the target org is the leak this whole family has to avoid.
                Partition = Partition(http),
                Ecosystem = ecosystem ?? EcosystemPathResolver.ForPath(route),
                Reason = reason,
                Route = route,
            },
            sourceIp: http.GetNormalizedRemoteIp());
    }

    /// <summary>
    /// Records a cross-tenant presentation for a call site that resolved the credential without
    /// a tenant and then makes its own <c>token.OrgId != orgId</c> decision — the shape the whole
    /// hosted-write plane uses, because a publish path wants a 401 with a challenge header rather
    /// than the read paths' "same as no token at all" null.
    ///
    /// <para>
    /// It is a no-op on a null token and on a matching org, which is what makes it safe to call
    /// from inside the combined <c>token is null || token.OrgId != orgId</c> branch those sites
    /// are written as: the null arm was already counted as a rejection by the resolver itself, and
    /// counting it again here would double every count a rule thresholds on. Recording the
    /// distinction is the caller's only job; deciding whether there is one is this method's.
    /// </para>
    /// </summary>
    public static void RecordTenantMismatch(
        HttpContext? http,
        TokenRecord? token,
        string expectedOrgId,
        string? ecosystem = null)
    {
        if (token is null || token.OrgId == expectedOrgId)
        {
            return;
        }

        RecordTokenRejected(
            http,
            reason: ReasonTenantMismatch,
            ecosystem: ecosystem,
            orgId: expectedOrgId);
    }

    /// <summary>
    /// Records that a resolved credential was refused on its capability set.
    /// <paramref name="required"/> is the capability (or the human-readable either/or label a
    /// two-capability gate demands); the granted set is read off the token, which is the same
    /// credential the row is attributed to, so it discloses nothing across a tenant boundary.
    /// </summary>
    public static void RecordCapabilityDenied(
        HttpContext? http,
        TokenRecord? token,
        string required,
        string? ecosystem = null,
        string? orgId = null)
    {
        var coalescer = Coalescer(http);
        if (coalescer is null)
        {
            return;
        }

        string route = RouteTemplate(http);
        coalescer.Record(
            new AuthDenialKey
            {
                Action = CapabilityDeniedAction,
                // The request's tenant, never the token's. A capability check is only reached
                // after the token resolved into this tenant, so the two agree here — deriving it
                // from the request keeps that true by construction if a future gate changes order.
                OrgId = orgId ?? ResolveOrgId(http),
                Partition = token is null ? Partition(http) : "token:" + TokenReference(token.Id),
                Ecosystem = ecosystem ?? EcosystemPathResolver.ForPath(route),
                Reason = ReasonInsufficientCapability,
                Required = required,
                Granted = FormatGranted(token?.CapabilitySet),
                Route = route,
            },
            sourceIp: http.GetNormalizedRemoteIp());
    }

    /// <summary>
    /// Records the capability denial behind an ASP.NET <c>Forbid</c> on the API-token scheme,
    /// reading the required capability from the endpoint's <c>RequireCapability</c> metadata and
    /// the granted set from the principal's <c>cap</c> claims. Does nothing for any other
    /// principal kind: a JWT-session caller reaches the same forbid handler on the dual-scheme
    /// management routes, and its refusals belong to the management plane's own audit surface.
    /// </summary>
    internal static void RecordCapabilityDeniedForScheme(HttpContext? http, string schemeName)
    {
        if (http?.User is null
            || !http.User.Identities.Any(i => i.AuthenticationType == schemeName))
        {
            return;
        }

        var coalescer = Coalescer(http);
        if (coalescer is null)
        {
            return;
        }

        string route = RouteTemplate(http);
        string[] granted = http.User.FindAll("cap")
            .Select(c => c.Value)
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .ToArray();

        coalescer.Record(
            new AuthDenialKey
            {
                Action = CapabilityDeniedAction,
                OrgId = ResolveOrgId(http),
                Partition = Partition(http),
                Ecosystem = EcosystemPathResolver.ForPath(route),
                Reason = ReasonInsufficientCapability,
                Required = RequiredCapability(http),
                Granted = FormatGranted(granted),
                Route = route,
            },
            sourceIp: http.GetNormalizedRemoteIp());
    }

    /// <summary>
    /// Flags this request as having presented a credential the token scheme could not resolve.
    /// Deliberately separate from recording it — see <see cref="UnresolvedCredentialItemKey"/>.
    /// </summary>
    internal static void FlagUnresolvedCredential(HttpContext? http) =>
        http?.Items.TryAdd(UnresolvedCredentialItemKey, true);

    /// <summary>
    /// True once, when this request presented a credential the token scheme could not resolve.
    /// Clears the flag so two challenges on one request cannot double-count a single refusal.
    /// </summary>
    internal static bool ConsumeUnresolvedCredential(HttpContext? http)
    {
        return http is not null
            && http.Items.Remove(UnresolvedCredentialItemKey, out object? flag)
            && flag is true;
    }

    private static AuthDenialAuditCoalescer? Coalescer(HttpContext? http) =>
        http?.RequestServices?.GetService<AuthDenialAuditCoalescer>();

    /// <summary>
    /// The endpoint's route template. Falls back to <see cref="UnknownRoute"/> rather than to the
    /// request path when no endpoint was selected — the fallback has to stay free of tenant data
    /// and free of unbounded key cardinality just as much as the happy path does.
    ///
    /// <para>
    /// The leading <c>/</c> is added when the pattern lacks it, because attribute routes are
    /// declared both ways (<c>[HttpGet("/npm/{*path}")]</c> and <c>[HttpGet("npm/{*path}")]</c>)
    /// and the raw text keeps whichever was written. Two spellings of one route are two
    /// accumulator keys, two audit rows and two things for a SOC rule to match, so every writer
    /// of the <c>route</c> field — the credential/capability seams here and
    /// <c>RateLimitDenialAuditRecorder</c> — resolves it through this method.
    /// </para>
    /// </summary>
    internal static string RouteTemplate(HttpContext? http)
    {
        return http?.GetEndpoint() is RouteEndpoint endpoint
            && endpoint.RoutePattern.RawText is { Length: > 0 } raw
            ? raw.StartsWith('/') ? raw : "/" + raw
            : UnknownRoute;
    }

    /// <summary>
    /// Resolved tenant, or null for an apex/system-scope request — which flushes as a
    /// system-scope row rather than as a tenant row with a NULL org, because that row would be
    /// readable from neither the tenant audit page nor that tenant's SIEM feed.
    /// </summary>
    private static string? ResolveOrgId(HttpContext? http) =>
        http?.Items[Dependably.Infrastructure.TenantContext.HttpItemsKey]
            is Dependably.Infrastructure.TenantContext { IsTenant: true } ctx
            ? ctx.TenantId
            : null;

    /// <summary>
    /// The rate-limit partition form of the remote address: a routed IPv6 <c>/64</c> is one
    /// subject, so an attacker cannot mint a fresh key per source address inside their own
    /// allocation and spray the accumulator's map to its cap. The full address still reaches the
    /// row's <c>source_ip</c> column, which is where forensics reads it.
    ///
    /// <para>
    /// <b>The partition field carries two namespaces, and the prefix is what tells them apart.</b>
    /// <c>ip:</c> is this form; <c>token:</c> is a truncated credential id, emitted by the inline
    /// capability gates, which hold the resolved token. The attribute path cannot emit the token
    /// form: its principal carries <c>sub</c>, which is the token <em>owner's</em> user id for a
    /// PAT, so using it would name a person rather than a credential and would fold two of one
    /// user's tokens into one key. A reader must branch on the prefix rather than parse the value
    /// as an address.
    /// </para>
    /// </summary>
    private static string Partition(HttpContext? http) =>
        "ip:" + (http.GetRateLimitPartitionIp() ?? "unknown");

    /// <summary>
    /// The leading segment of a token's database id — enough to tell two credentials apart,
    /// short enough that the payload is not republishing a whole internal key.
    /// </summary>
    private static string TokenReference(string tokenId) =>
        tokenId.Length <= 8 ? tokenId : tokenId[..8];

    private static string FormatGranted(IEnumerable<string>? granted)
    {
        if (granted is null)
        {
            return NoCapabilities;
        }

        string[] ordered = granted.OrderBy(c => c, StringComparer.Ordinal).ToArray();
        return ordered.Length == 0 ? NoCapabilities : string.Join(", ", ordered);
    }

    /// <summary>
    /// The capability the selected endpoint demands, from its <c>RequireCapability</c> metadata.
    /// Null when the endpoint is gated by a plain <c>[Authorize]</c> instead — the denial is
    /// still real and still counted; only the required-capability field is unknown.
    /// </summary>
    private static string? RequiredCapability(HttpContext http)
    {
        var required = http.GetEndpoint()?.Metadata
            .GetOrderedMetadata<RequireCapabilityAttribute>();
        return required is null || required.Count == 0
            ? null
            : string.Join(", ", required.Select(r => r.Capability).Distinct(StringComparer.Ordinal));
    }

}
