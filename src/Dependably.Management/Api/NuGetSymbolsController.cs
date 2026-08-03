using System.Security.Claims;
using Dependably.Api.NuGetProtocol;
using Dependably.Infrastructure;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Management-plane repair for the NuGet symbol server.
///
/// <para>
/// Symbol indexing at push time is best-effort by design: the <c>package_versions</c> row is
/// already committed when it runs, so a corrupt PDB entry or a transient I/O error is logged and
/// swallowed rather than failing an otherwise good push. What that leaves behind is a
/// <c>.snupkg</c> that downloads fine but whose PDBs never resolve by debug-id, and re-pushing the
/// same coordinate is itself policy-gated — so without a repair path the failure is permanent.
/// </para>
/// </summary>
[ApiController]
[Authorize]
public sealed class NuGetSymbolsController(
    OrgAccessGuard guard,
    PackageRepository packages,
    PackageVersionFilesRepository versionFiles,
    NuGetSymbolIndexer symbolIndexer,
    AuditRepository audit) : ControllerBase
{
    /// <summary>
    /// POST /api/v1/packages/nuget/{name}/{version}/reindex-symbols
    ///
    /// Re-reads the version's stored <c>.snupkg</c> and rebuilds its symbol index, returning the
    /// number of Portable PDBs recorded. Idempotent: the indexer replaces the version's rows
    /// rather than appending, so running it twice yields the same set.
    ///
    /// <para>
    /// A response of <c>indexedPdbCount: 0</c> is the actionable case the operator previously had
    /// to dig out of the server log — the symbol package stored fine but held no PDB this build
    /// can read, native/Windows PDBs being out of scope.
    /// </para>
    /// </summary>
    [HttpPost("api/v1/packages/nuget/{name}/{version}/reindex-symbols")]
    public async Task<IActionResult> ReindexSymbols(
        string name, string version, CancellationToken ct = default)
    {
        // Explicit authorization decision: a repair action that reads stored artifacts and
        // rewrites index state is operator work, matching the other maintenance endpoints.
        var authResult = await guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = ((TenantContext)HttpContext.Items[TenantContext.HttpItemsKey]!).TenantId!;

        // Org-scoped lookups throughout, and NotFound on every miss so a cross-tenant coordinate
        // is indistinguishable from an absent one.
        var pkg = await packages.GetByPurlNameAsync(orgId, "nuget", name.ToLowerInvariant(), ct);
        if (pkg is null)
        {
            return NotFound();
        }

        var ver = await packages.GetVersionAsync(pkg.Id, NuGetNormalization.NormalizeVersion(version), ct);
        if (ver is null)
        {
            return NotFound();
        }

        var symbolFile = await versionFiles.GetByExtensionAsync(
            ver.Id, MultiFileEcosystems.NuGetSymbolExtension, ct);
        if (symbolFile is null)
        {
            return NotFound();
        }

        int? indexed = await symbolIndexer.ReindexFromBlobAsync(orgId, ver.Id, symbolFile.BlobKey, ct);
        if (indexed is null)
        {
            // The row names a blob the store no longer holds; re-indexing cannot repair that, and
            // saying so beats reporting a successful re-index of nothing.
            return NotFound();
        }

        string? actorId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        await audit.LogActivityAsync(orgId, "nuget", ver.Purl, "reindex-symbols", actorId,
            actorKind: ActorKinds.User, sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return Ok(new { indexedPdbCount = indexed.Value });
    }
}
