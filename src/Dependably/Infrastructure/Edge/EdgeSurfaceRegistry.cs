using Microsoft.AspNetCore.Mvc;

namespace Dependably.Infrastructure.Edge;

/// <summary>
/// Which deployment surface a controller belongs to. The classification is explicit and
/// compile-time-visible (not a route-prefix heuristic) so a new controller cannot silently
/// leak onto an edge node: the <c>EdgeControllerClassificationComplianceTests</c> gate fails
/// the build until every non-abstract controller appears in <see cref="EdgeSurfaceRegistry"/>.
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
    /// edge node by <see cref="EdgeManagementStrippingConvention"/> so it 404s.
    /// </summary>
    Management,
}

/// <summary>
/// The single, central classification of every MVC controller into a <see cref="EdgeSurface"/>.
/// This is the fail-closed source of truth the edge routing convention consults: only controllers
/// classified <see cref="EdgeSurface.Protocol"/> are mapped in edge mode.
///
/// The classification is by controller <see cref="Type"/> rather than by route prefix on purpose:
/// a route-prefix heuristic is a fail-open denylist (a mislabeled or unprefixed route slips
/// through), whereas an explicit registry plus the compliance gate is fail-closed — an
/// unclassified controller is a red build, not a reachable edge endpoint.
/// </summary>
public static class EdgeSurfaceRegistry
{
    // Registry protocol surfaces + health/download routes an edge cache serves. Every entry is a
    // controller (or a partial's primary type) that routes exclusively to a protocol path.
    private static readonly IReadOnlySet<Type> ProtocolControllers = new HashSet<Type>
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

    // Management/control-plane controllers — everything under /api/v1/ plus SAML. Stripped in edge
    // mode. Listed explicitly (not "everything not in ProtocolControllers") so a brand-new
    // controller is unclassified until deliberately placed, and the gate flags it.
    private static readonly IReadOnlySet<Type> ManagementControllers = new HashSet<Type>
    {
        typeof(Api.AuthController),
        typeof(Api.MfaController),
        typeof(Api.SamlController),
        typeof(Api.BootstrapController),
        typeof(Api.SystemController),
        typeof(Api.SystemMfaController),
        typeof(Api.SystemBannersController),
        typeof(Api.InstanceController),
        typeof(Api.OrgController),
        typeof(Api.OrgSettingsController),
        typeof(Api.OrgUsersController),
        typeof(Api.OrgTokensController),
        typeof(Api.OrgListsController),
        typeof(Api.OrgAuditController),
        typeof(Api.OrgInvitesController),
        typeof(Api.OrgAuthConfigController),
        typeof(Api.BannersController),
        typeof(Api.QuarantineController),
        typeof(Api.TrustAnchorController),
        typeof(Api.UpstreamRegistryController),
        typeof(Api.WebhookController),
        typeof(Api.SiemController),
        typeof(Api.ImportController),
        typeof(Api.SearchController),
        typeof(Api.ClaimsController),
        typeof(Api.VulnerabilityController),
        typeof(Api.LicenseController),
        typeof(Api.LicensesController),
        typeof(Api.SpdxLicenseController),
    };

    /// <summary>
    /// Returns the surface for <paramref name="controllerType"/>, or <c>null</c> when the
    /// controller is not classified. A null result is a bug the compliance gate catches — the
    /// routing convention treats an unclassified controller as management (fail closed) so an
    /// unclassified surface never leaks onto an edge even if the gate is somehow bypassed.
    /// </summary>
    public static EdgeSurface? Classify(Type controllerType) =>
        ProtocolControllers.Contains(controllerType) ? EdgeSurface.Protocol
        : ManagementControllers.Contains(controllerType) ? EdgeSurface.Management
        : null;

    /// <summary>True when the controller is a kept protocol surface on an edge node.</summary>
    public static bool IsProtocol(Type controllerType) =>
        Classify(controllerType) == EdgeSurface.Protocol;
}

/// <summary>
/// Registered only in edge mode. Strips every management-classified controller from the
/// application model so its routes 404 on an edge node — the fail-closed alternative to a
/// separate composition root. Protocol controllers are left mapped unchanged.
///
/// An unclassified controller (one absent from <see cref="EdgeSurfaceRegistry"/>) is treated as
/// management and stripped, so a new surface fails closed on an edge; the compliance gate turns
/// that latent risk into a build error.
/// </summary>
public sealed class EdgeManagementStrippingConvention : Microsoft.AspNetCore.Mvc.ApplicationModels.IApplicationModelConvention
{
    public void Apply(Microsoft.AspNetCore.Mvc.ApplicationModels.ApplicationModel application)
    {
        var kept = application.Controllers
            .Where(c => EdgeSurfaceRegistry.IsProtocol(c.ControllerType.AsType()))
            .ToList();

        application.Controllers.Clear();
        foreach (var controller in kept)
        {
            application.Controllers.Add(controller);
        }
    }
}
