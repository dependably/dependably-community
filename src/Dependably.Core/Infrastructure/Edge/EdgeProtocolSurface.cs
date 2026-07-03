namespace Dependably.Infrastructure.Edge;

/// <summary>
/// Which deployment surface a controller belongs to. The classification is explicit and
/// compile-time-visible (not a route-prefix heuristic) so a new controller cannot silently
/// leak onto an edge node: the <c>EdgeControllerClassificationComplianceTests</c> gate fails
/// the build until every non-abstract controller is classified Protocol or Management.
/// </summary>
public enum EdgeSurface
{
    /// <summary>
    /// Registry protocol surface (npm, PyPI, NuGet, Maven, RPM, Cargo, Go, OCI, and their
    /// download routes). Kept on an edge node — this is what a cache serves.
    /// </summary>
    Protocol,

    /// <summary>
    /// Management/control plane (org and tenant admin, auth/login/MFA/session issuance, SAML,
    /// system operator, bootstrap, dashboards/stats for the SPA). Stripped from routing on an
    /// edge node so it 404s.
    /// </summary>
    Management,
}

/// <summary>
/// The canonical set of protocol-surface controllers — the source of truth for what an edge
/// cache serves. All eight protocol controllers are Core types, so this classification lives
/// in Core and ships in every host (including the protocol-only edge root). The management-side
/// registry references this set rather than restating the controller list, keeping one source
/// of truth for the Protocol⊂Core invariant.
/// </summary>
public static class EdgeProtocolSurface
{
    // Registry protocol surfaces + download routes an edge cache serves. Every entry is a
    // controller (or a partial's primary type) that routes exclusively to a protocol path.
    private static readonly HashSet<Type> ProtocolControllers = new()
    {
        typeof(Api.PyPiController),
        typeof(Api.NpmController),
        typeof(Api.NuGetController),
        typeof(Api.MavenController),
        typeof(Api.RpmController),
        typeof(Api.CargoController),
        typeof(Api.GoController),
        typeof(Api.OciController),
    };

    /// <summary>True when the controller is a kept protocol surface on an edge node.</summary>
    public static bool IsProtocol(Type controllerType) =>
        ProtocolControllers.Contains(controllerType);
}
