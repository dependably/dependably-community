using System.Globalization;

namespace Dependably.Infrastructure.OciScan;

/// <summary>
/// Whether OCI has a vulnerability feed for an org right now. <see cref="Protocol.OsvFeedCoverage"/>
/// lists OCI as having none, and that stays true for every org without a live scanner: an image
/// nobody can scan must read <c>no_feed</c>, never <c>unscanned</c> and never clean.
/// </summary>
public interface IOciScanCoverage
{
    /// <summary>True when scanning is enabled for the instance.</summary>
    bool Enabled { get; }

    /// <summary>
    /// True only while scanning is enabled and <paramref name="orgId"/>'s scanner has called the
    /// scan API within <c>OCI_SCAN_HEARTBEAT_WINDOW</c>. A scanner that stops calling drops its
    /// org back to <c>no_feed</c> for every image without a stored result.
    /// </summary>
    Task<bool> IsCoveredAsync(string orgId, CancellationToken ct = default);
}

/// <inheritdoc />
public sealed class OciScanCoverage : IOciScanCoverage
{
    private readonly OciScanOptions _options;
    private readonly OciScanRepository _repo;
    private readonly TimeProvider _time;

    public OciScanCoverage(OciScanOptions options, OciScanRepository repo, TimeProvider time)
    {
        _options = options;
        _repo = repo;
        _time = time;
    }

    public bool Enabled => _options.Enabled;

    public async Task<bool> IsCoveredAsync(string orgId, CancellationToken ct = default)
    {
        if (!_options.Enabled)
        {
            return false;
        }

        string? lastSeen = await _repo.GetScannerLastSeenAsync(orgId, ct);
        return lastSeen is not null
            && DateTimeOffset.TryParse(lastSeen, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var seen)
            && _time.GetUtcNow() - seen <= _options.HeartbeatWindow;
    }
}
