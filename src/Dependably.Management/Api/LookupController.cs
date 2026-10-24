using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Pre-adoption package lookup: "check a package before you add it". Read-only — resolves
/// upstream metadata and OSV advisories for a candidate (ecosystem, name, version) and
/// evaluates it against the org's block/license policy without ingesting anything (nothing is
/// written to the blob store, <c>package_versions</c>, or <c>cache_artifact</c>).
///
/// Authorized on <see cref="Capabilities.ReadPackages"/> — any regular member can run a lookup;
/// policy configuration itself stays behind <see cref="Capabilities.TenantConfigure"/> on the
/// settings endpoints. All logic beyond request validation and HTTP mapping lives in
/// <see cref="PackageLookupService"/> so it stays reachable from a future CLI/IDE surface
/// without duplicating the evaluation.
/// </summary>
[ApiController]
[Authorize]
public sealed class LookupController : OrgScopedControllerBase
{
    private readonly PackageLookupService _lookup;
    private readonly OrgAccessGuard _guard;
    private readonly ProblemResults _problems;

    public LookupController(PackageLookupService lookup, OrgAccessGuard guard, ProblemResults problems)
    {
        _lookup = lookup;
        _guard = guard;
        _problems = problems;
    }

    /// <summary>
    /// GET /api/v1/lookup?ecosystem=&amp;name=&amp;version=[&amp;distro=] — tenant-scoped, read-only
    /// package verdict. <c>distro</c> scopes an apk or rpm lookup to a release (<c>v3.20</c>,
    /// <c>Rocky Linux:9</c>) and is ignored for every other ecosystem; oci takes the image digest
    /// as <c>version</c>.
    /// </summary>
    // Read-only: accepts a PAT/service token carrying read:packages.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [EndpointDescription(
        "Read-only verdict for a candidate package. advisorySource says where the advisory answer came from: "
        + "status checked (an empty list means none), unavailable (the source could not be consulted, so an empty "
        + "list says nothing; see reason), or not_applicable (the ecosystem has no advisory source, as for terraform). "
        + "A not_applicable lookup that passes the other checks has verdict allowed: it is not a failed check.")]
    [HttpGet("api/v1/lookup")]
    public async Task<IActionResult> Get(
        [FromQuery] string? ecosystem,
        [FromQuery] string? name,
        [FromQuery] string? version,
        [FromQuery] string? distro,
        CancellationToken ct)
    {
        var denied = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (denied is not null)
        {
            return denied;
        }

        var request = new PackageLookupRequest(CurrentTenantId(), ecosystem, name, version, distro);
        var outcome = await _lookup.LookupAsync(request, ct);

        return outcome.Status switch
        {
            PackageLookupStatus.Ok => Ok(outcome.Result),
            PackageLookupStatus.UnsupportedEcosystem => _problems.ValidationErrorActionKey(
                "ecosystem", "error.common.mustBeOneOf", string.Join(", ", PackageLookupService.SupportedEcosystems)),
            PackageLookupStatus.InvalidInput => _problems.ValidationErrorActionKey(
                outcome.Field ?? "name", InvalidInputResourceKey(outcome.Reason)),
            PackageLookupStatus.VersionRequired => _problems.ValidationErrorActionKey(
                "version", "error.lookup.versionRequired", outcome.Reason ?? ""),
            // A definitively-absent package is an ANSWER to the lookup query, not a failed
            // request — a mistyped name is the common path here. Served 200 with found=false so
            // the caller renders a "no such package" verdict rather than an error, and so the
            // browser does not log every typo as a failed request in its console.
            PackageLookupStatus.UpstreamNotFound => Ok(outcome.NotFound),
            // A reserved name, an ecosystem with no upstream, and an org with proxy passthrough off
            // are standing operator choices, not outages: retrying never changes the answer, so
            // they are not 503. Each is the
            // same request problem as an air-gapped lookup (no latest version can be resolved,
            // so the caller has to name one), served as a 422 on "version" with its own detail
            // and a machine-readable reason.
            PackageLookupStatus.Reserved => _problems.ValidationErrorActionKeyWithReason(
                "version", "name_reserved", "error.lookup.reservedVersionRequired", outcome.Reason ?? ""),
            PackageLookupStatus.UpstreamNotConfigured => _problems.ValidationErrorActionKeyWithReason(
                "version", "upstream_not_configured", "error.lookup.upstreamNotConfigured", outcome.Reason ?? ""),
            PackageLookupStatus.PassthroughOff => _problems.ValidationErrorActionKeyWithReason(
                "version", "passthrough_off", "error.lookup.passthroughOffVersionRequired", outcome.Reason ?? ""),
            PackageLookupStatus.UpstreamUnavailable => _problems.ServiceUnavailableActionKey(
                "error.lookup.upstreamUnavailable", outcome.Reason ?? ""),
            _ => _problems.ServiceUnavailableActionKey("error.lookup.upstreamUnavailable", outcome.Reason ?? ""),
        };
    }

    // Maps the service's machine-readable invalid-input reason code to its SharedResource key.
    // Kept as a table lookup (not a direct resx-key reason) so the service layer never needs to
    // know resx key names — it returns domain codes, the controller owns localization.
    private static string InvalidInputResourceKey(string? reason) => reason switch
    {
        "name.required" => "error.lookup.nameRequired",
        "maven.coordinateInvalid" => "error.lookup.mavenCoordinateInvalid",
        "version.invalid" => "error.lookup.versionInvalid",
        "oci.digestRequired" => "error.lookup.ociDigestRequired",
        "distro.invalid" => "error.lookup.distroInvalid",
        "version.releaseRequired" => "error.lookup.releaseRequired",
        _ => "error.lookup.nameInvalid",
    };
}
