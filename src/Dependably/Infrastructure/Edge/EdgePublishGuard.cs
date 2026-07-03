using Dependably.Infrastructure.Publish;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Infrastructure.Edge;

/// <summary>
/// The single shared fail-closed publish guard for edge mode. A headless edge is a pull-through
/// cache with no durable registry tier — any publish/push/import must fail fast rather than write
/// a local artifact that can never replicate to the master.
///
/// Every non-OCI publish funnels through <c>PackagePublishService</c> (npm/PyPI/NuGet/Maven/RPM
/// push and bulk import), which consults <see cref="RejectPublish"/> at its entry. Mutation and
/// delete paths that write DB rows or blobs directly — bypassing that service — call
/// <see cref="UploadRejection"/> at the top of their action: OCI upload-initiation (POST
/// blobs/uploads), chunk PATCH, manifest PUT and manifest DELETE; NuGet unlist; npm publish/
/// deprecate PUT, dist-tag PUT/DELETE and unpublish DELETE; and Cargo yank/unyank. All surface
/// the same RFC-7807 405 with the title below, ahead of any lookup so the guard beats a 404.
/// </summary>
public sealed class EdgePublishGuard
{
    /// <summary>Problem title returned for every blocked publish on an edge node.</summary>
    public const string Title = "This node is a cache edge — publish to the master registry.";

    private const string Detail =
        "This dependably node runs as a headless cache edge (DEPLOYMENT_MODE=edge) and holds no "
        + "durable registry tier. Publish, push, and import are disabled here — target the central "
        + "master registry instead.";

    private readonly IEdgeMode _edge;

    public EdgePublishGuard(IEdgeMode edge) => _edge = edge;

    /// <summary>True when this node is an edge and publishing is refused.</summary>
    public bool IsEdge => _edge.IsEdge;

    /// <summary>
    /// Returns a <see cref="PublishResult.Rejected"/> (405) when publishing is refused on an edge
    /// node, or <c>null</c> when publishing is allowed. Called at the top of the shared publish
    /// service so every ecosystem's push path fails closed uniformly.
    /// </summary>
    public PublishResult.Rejected? RejectPublish() =>
        _edge.IsEdge ? new PublishResult.Rejected(405, "edge_read_only", Title) : null;

    /// <summary>
    /// Returns a 405 <see cref="IActionResult"/> problem for publish, mutation, and delete paths
    /// that write storage or DB rows directly rather than through the shared publish service
    /// (Maven PUT, RPM upload, OCI upload/manifest/delete, NuGet unlist, npm publish/deprecate/
    /// dist-tag/unpublish, and Cargo yank/unyank), or <c>null</c> when publishing is allowed.
    /// </summary>
    public IActionResult? UploadRejection() =>
        _edge.IsEdge
            ? new ObjectResult(new ProblemDetails
            {
                Status = StatusCodes.Status405MethodNotAllowed,
                Title = Title,
                Detail = Detail,
            })
            {
                StatusCode = StatusCodes.Status405MethodNotAllowed,
            }
            : null;
}
