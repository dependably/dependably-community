namespace Dependably.Infrastructure.Usage;

/// <summary>
/// The meters a usage cap can be set on: the <c>org_usage_caps.meter</c> literals, whose CHECK
/// constraint enumerates them. Caps are quantities in each meter's own unit. Community decides
/// nothing about which of them is billed; whoever sets the caps does.
/// </summary>
public static class UsageCapMeters
{
    /// <summary>Artefact egress bytes this UTC month, summed from <c>usage_hourly</c>.</summary>
    public const string EgressBytes = UsageMeters.EgressBytes;

    /// <summary>Metadata egress bytes this UTC month, summed from <c>usage_hourly</c>.</summary>
    public const string EgressMetadataBytes = UsageMeters.EgressMetadataBytes;

    /// <summary>Billable storage bytes in the latest <c>storage_snapshot</c>.</summary>
    public const string StorageBytes = UsageMeters.StorageBytes;

    /// <summary>
    /// Uploaded artefacts in the latest <c>storage_snapshot</c>
    /// (<see cref="StorageSnapshotRow.ArtifactCount"/>).
    /// </summary>
    public const string ArtifactCount = "artifact_count";

    /// <summary>Every cappable meter, in a stable order.</summary>
    public static readonly IReadOnlyList<string> All =
        [EgressBytes, EgressMetadataBytes, StorageBytes, ArtifactCount];

    public static bool IsKnown(string meter) => meter is EgressBytes or EgressMetadataBytes or StorageBytes or ArtifactCount;

    /// <summary>The meters whose overage throttles downloads as well as refusing uploads.</summary>
    public static bool IsEgress(string meter) => meter is EgressBytes or EgressMetadataBytes;
}

/// <summary>The <c>orgs.usage_posture</c> literals.</summary>
public static class UsagePostures
{
    /// <summary>No capped meter has reached its cap, or the org has no caps.</summary>
    public const string Normal = "normal";

    /// <summary>A capped meter is at or above 100 % of its cap: protocol-plane writes are refused.</summary>
    public const string UploadsRefused = "uploads_refused";

    /// <summary>
    /// A capped egress meter is at or above 110 % of its cap: writes are refused and protocol-plane
    /// requests draw on the small tenant-throttled rate-limit budget.
    /// </summary>
    public const string DownloadsThrottled = "downloads_throttled";

    /// <summary>Whether <paramref name="posture"/> refuses protocol-plane writes.</summary>
    public static bool RefusesUploads(string? posture) => posture is UploadsRefused or DownloadsThrottled;
}

/// <summary>An org's measured usage for each cappable meter, as the posture evaluation reads it.</summary>
public sealed record UsageMeasurements(
    long EgressBytes,
    long EgressMetadataBytes,
    long StorageBytes,
    long ArtifactCount)
{
    public static UsageMeasurements None { get; } = new(0, 0, 0, 0);

    public long For(string meter) => meter switch
    {
        UsageCapMeters.EgressBytes => EgressBytes,
        UsageCapMeters.EgressMetadataBytes => EgressMetadataBytes,
        UsageCapMeters.StorageBytes => StorageBytes,
        UsageCapMeters.ArtifactCount => ArtifactCount,
        _ => throw new ArgumentOutOfRangeException(nameof(meter), meter, "Not a cappable meter."),
    };
}

/// <summary>
/// Turns an org's caps and measured usage into its <c>usage_posture</c>. Pure, so every threshold
/// is unit-testable at its exact boundary.
/// <list type="bullet">
///   <item>Any capped egress meter at or above 110 % of its cap: <see cref="UsagePostures.DownloadsThrottled"/>.</item>
///   <item>Otherwise any capped meter at or above 100 %: <see cref="UsagePostures.UploadsRefused"/>.</item>
///   <item>Otherwise, and always for an org with no caps: <see cref="UsagePostures.Normal"/>.</item>
/// </list>
/// The comparison is exact integer arithmetic in 128 bits, so a cap near <see cref="long.MaxValue"/>
/// neither overflows nor rounds.
/// </summary>
public static class UsagePostureEvaluator
{
    public static string Evaluate(IReadOnlyDictionary<string, long> caps, UsageMeasurements usage)
    {
        ArgumentNullException.ThrowIfNull(caps);
        ArgumentNullException.ThrowIfNull(usage);

        bool atCap = false;
        foreach (var (meter, cap) in caps)
        {
            if (!UsageCapMeters.IsKnown(meter) || cap <= 0)
            {
                continue;
            }

            Int128 used = usage.For(meter);
            if (UsageCapMeters.IsEgress(meter) && used * 10 >= (Int128)cap * 11)
            {
                return UsagePostures.DownloadsThrottled;
            }

            if (used >= cap)
            {
                atCap = true;
            }
        }

        return atCap ? UsagePostures.UploadsRefused : UsagePostures.Normal;
    }
}
