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

    /// <summary>GET /api/v1/lookup?ecosystem=&amp;name=&amp;version= — tenant-scoped, read-only package verdict.</summary>
    [HttpGet("api/v1/lookup")]
    public async Task<IActionResult> Get(
        [FromQuery] string? ecosystem,
        [FromQuery] string? name,
        [FromQuery] string? version,
        CancellationToken ct)
    {
        var denied = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (denied is not null)
        {
            return denied;
        }

        var request = new PackageLookupRequest(CurrentTenantId(), ecosystem, name, version);
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
            PackageLookupStatus.UpstreamNotFound => _problems.NotFoundActionKey("error.lookup.packageNotFound"),
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
        _ => "error.lookup.nameInvalid",
    };
}
