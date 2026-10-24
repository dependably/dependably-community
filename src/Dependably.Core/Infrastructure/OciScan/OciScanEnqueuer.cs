namespace Dependably.Infrastructure.OciScan;

/// <summary>
/// Queues an OCI image for its org's scanner when a tag push or a tenant's first proxied pull
/// catalogues it. A no-op while scanning is disabled, and on an edge node, which hosts no scan
/// API for a scanner to drain the queue through. Best effort: a failure here is logged and never
/// fails the push or the pull, and the <c>oci-scan-sweep</c> job queues whatever it missed.
/// </summary>
public sealed class OciScanEnqueuer
{
    private readonly OciScanOptions _options;
    private readonly OciScanRepository _repo;
    private readonly TimeProvider _time;
    private readonly ILogger<OciScanEnqueuer> _logger;
    private readonly bool _isEdge;

    public OciScanEnqueuer(
        OciScanOptions options, OciScanRepository repo, TimeProvider time, ILogger<OciScanEnqueuer> logger,
        IEdgeMode? edge = null)
    {
        _options = options;
        _repo = repo;
        _time = time;
        _logger = logger;
        _isEdge = edge?.IsEdge == true;
    }

    public async Task EnqueueAsync(
        string orgId, OciScanOwner owner, string repository, string digest, CancellationToken ct = default)
    {
        if (!_options.Enabled || _isEdge)
        {
            return;
        }

        try
        {
            await _repo.EnqueueAsync(orgId, owner, repository, digest, _time.GetUtcNow().ToUtcIsoMillis(), ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "Could not queue {Repository}@{Digest} for scanning (org {OrgId}); the oci-scan-sweep job will queue it.",
                repository, digest, orgId);
        }
    }
}
