using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// The stored scan detail of one OCI image. A separate controller from <see cref="OrgController"/>
/// because a class's coupling is measured per class, and the scan detail pulls in its own reader,
/// outcome and problem types; the route is unchanged.
/// </summary>
[ApiController]
[Authorize]
public sealed class OrgOciScanController : OrgScopedControllerBase
{
    // A manifest digest as the scan rows store it. \z, not $: .NET's $ admits a trailing newline.
    private static readonly System.Text.RegularExpressions.Regex OciDigestPattern = new(
        @"^sha256:[0-9a-f]{64}\z",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    private readonly OrgAccessGuard _guard;
    private readonly ProblemResults _problems;
    private readonly Dependably.Infrastructure.OciScan.OciScanDetailReader? _detail;

    public OrgOciScanController(
        OrgAccessGuard guard,
        ProblemResults problems,
        Dependably.Infrastructure.OciScan.OciScanDetailReader? detail = null)
    {
        _guard = guard;
        _problems = problems;
        _detail = detail;
    }

    /// <summary>Whether <paramref name="digest"/> is a manifest digest the scan-detail read accepts.</summary>
    internal static bool IsOciDigest(string digest) => OciDigestPattern.IsMatch(digest);

    /// <summary>
    /// GET /api/v1/packages/oci/{name}/{digest}/scan — one OCI image's stored scan detail for the
    /// caller's org: every platform's coverage and gaps, one platform's components a page at a
    /// time, and each component's findings with their reachability verdicts.
    ///
    /// <para>The image's owner is resolved by existence, as its version row's status badge is: a
    /// hosted row with no result reads unscanned even when a proxied result exists for the digest.
    /// An unknown repository, an unknown or malformed digest, a digest the org has neither hosted
    /// nor pulled, and another org's image are all the same 404.</para>
    /// </summary>
    // Read-only: accepts a PAT/service token carrying read:packages.
    // ratelimit-ok: management default limiter; the response is bounded by paging (limit at most 500 components) and by the 50-finding cap per component, so a reader cannot pull an unbounded body.
    [Authorize(AuthenticationSchemes = "Bearer," + TokenAuthenticationDefaults.Scheme)]
    [HttpGet("api/v1/packages/oci/{name}/{digest}/scan")]
    [ProducesResponseType(typeof(Dependably.Infrastructure.OciScan.OciScanDetail), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status422UnprocessableEntity)]
    public async Task<IActionResult> GetOciScan(
        string name,
        string digest,
        [FromQuery] string? platform = null,
        [FromQuery] bool affectedOnly = true,
        [FromQuery] int offset = 0,
        [FromQuery] int limit = Dependably.Infrastructure.OciScan.OciScanDetailReader.DefaultLimit,
        CancellationToken ct = default)
    {
        var result = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadPackages, ct);
        if (result is not null)
        {
            return result;
        }

        if (_detail is null || !IsOciDigest(digest))
        {
            return NotFound();
        }

        string orgId = CurrentTenantId();
        var (outcome, detail) = await _detail.ReadAsync(
            orgId, OrgController.AsPurlName("oci", name), digest, platform, affectedOnly, offset, limit, ct);
        return outcome switch
        {
            Dependably.Infrastructure.OciScan.OciScanDetailOutcome.Found => Ok(detail),
            Dependably.Infrastructure.OciScan.OciScanDetailOutcome.UnknownPlatform
                => _problems.ValidationErrorActionKey("platform", "error.ociScan.platformUnknown"),
            _ => NotFound(),
        };
    }
}
