using Microsoft.Extensions.Configuration;

namespace Dependably.Security;

/// <summary>
/// Resolves the GlobalLimiter's two per-minute ceilings from configuration: the management
/// per-principal limit (<c>MANAGEMENT_RATE_LIMIT_PERMITS</c>) applied to authenticated
/// <c>/api/v1/*</c> traffic with no more specific policy, and the default-deny protocol limit
/// (<c>PROTOCOL_DEFAULT_RATE_LIMIT_PERMITS</c>) the GlobalLimiter applies to a controller action
/// that declares no explicit policy (protocol registry routes, plus non-<c>/api/v1</c> management
/// routes such as <c>/saml/*</c>).
///
/// <para>
/// Both are env-configurable rather than a boolean disable switch (a production footgun): a bounded
/// internal client — e.g. a DAST scan that authenticates as one system principal and fires thousands
/// of requests — can be handed a very high limit for the duration of the scan. A high (not infinite)
/// limit still bounds a real DoS while leaving a bounded scan unthrottled, so the scanner probes
/// every endpoint instead of hitting a 429 flood that both perturbs the active scan (spurious
/// findings) and leaves real endpoints unprobed.
/// </para>
/// </summary>
internal static class RateLimitCeilings
{
    /// <summary>Default per-principal ceiling (requests/min) for authenticated <c>/api/v1/*</c>.</summary>
    internal const int DefaultManagementPermitLimit = 300;

    /// <summary>Default-deny ceiling (requests/min per IP) for a policy-less controller action.</summary>
    internal const int DefaultProtocolPermitLimit = 300;

    internal static int ResolveManagementPermitLimit(IConfiguration cfg) =>
        int.TryParse(cfg["MANAGEMENT_RATE_LIMIT_PERMITS"], out int m) ? m : DefaultManagementPermitLimit;

    internal static int ResolveProtocolDefaultPermitLimit(IConfiguration cfg) =>
        int.TryParse(cfg["PROTOCOL_DEFAULT_RATE_LIMIT_PERMITS"], out int pd) ? pd : DefaultProtocolPermitLimit;
}
