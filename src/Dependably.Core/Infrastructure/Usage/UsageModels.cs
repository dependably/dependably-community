namespace Dependably.Infrastructure.Usage;

/// <summary>
/// The metered quantities. Every meter defined today counts bytes. The values are the
/// <c>meter</c> column literals in <c>usage_events</c>, <c>usage_hourly</c>, and
/// <c>usage_daily</c>, whose CHECK constraints enumerate them.
/// </summary>
public static class UsageMeters
{
    /// <summary>Artifact response bodies: tarballs, wheels, jars, layers, and the like.</summary>
    public const string EgressBytes = "egress_bytes";

    /// <summary>
    /// Package metadata responses: packuments, simple indexes, registration pages,
    /// <c>maven-metadata.xml</c>, repodata, tag lists. Recorded separately from artifact egress
    /// so that whatever rates the rollups can decide whether metadata is billable.
    /// </summary>
    public const string EgressMetadataBytes = "egress_metadata_bytes";

    /// <summary>
    /// The day's high-water mark of billable storage. Appears in <c>usage_daily</c> only; it is
    /// captured from <c>storage_snapshot</c>, never from events.
    /// </summary>
    public const string StorageBytes = "storage_bytes";

    /// <summary>The meters an event may carry.</summary>
    public static bool IsEventMeter(string meter) => meter is EgressBytes or EgressMetadataBytes;
}

/// <summary>How a metered response's bytes reached the client.</summary>
public static class UsageDelivery
{
    /// <summary>The application wrote the body itself.</summary>
    public const string Streamed = "streamed";

    /// <summary>
    /// The application answered with a redirect to the object store or CDN. The event records the
    /// object's full size at the moment the redirect is issued; a redirect authorizes a download
    /// but does not prove one completed.
    /// </summary>
    public const string Redirect = "redirect";

    public static bool IsKnown(string delivery) => delivery is Streamed or Redirect;
}

/// <summary>
/// One metered response, as stored in <c>usage_events</c>. Construct through
/// <see cref="Create"/>, which validates the enumerated fields and formats the timestamp at the
/// millisecond precision every range bound over <c>occurred_at</c> is written at.
/// </summary>
public sealed record UsageEvent(
    string EventId,
    string OrgId,
    string Meter,
    string Delivery,
    long Quantity,
    string Source,
    string? ObjectRef,
    string OccurredAt)
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "The validating factory for this record takes its eight positional fields one-to-one; bundling them would re-create the record.")]
    public static UsageEvent Create(
        Guid eventId,
        string orgId,
        string meter,
        string delivery,
        long quantity,
        string source,
        string? objectRef,
        DateTimeOffset occurredAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(orgId);
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        if (!UsageMeters.IsEventMeter(meter))
        {
            throw new ArgumentOutOfRangeException(nameof(meter), meter, "Not an event meter.");
        }

        if (!UsageDelivery.IsKnown(delivery))
        {
            throw new ArgumentOutOfRangeException(nameof(delivery), delivery, "Unknown delivery.");
        }

        ArgumentOutOfRangeException.ThrowIfNegative(quantity);

        return new UsageEvent(
            eventId.ToString(),
            orgId,
            meter,
            delivery,
            quantity,
            source,
            objectRef,
            occurredAt.ToUtcIsoMillis());
    }
}

/// <summary>One row of <c>usage_daily</c>.</summary>
public sealed class UsageDailyRow
{
    public string OrgId { get; init; } = "";
    public string Meter { get; init; } = "";
    public string Bucket { get; init; } = "";
    public long Quantity { get; init; }
    public long RedirectQuantity { get; init; }

    /// <summary>
    /// The number of metered events in the bucket: an operator capacity signal, never a billed
    /// meter. HEAD, 304 and error responses emit no event, so this counts metered requests, not
    /// every request. Buckets rolled up before the column existed read 0.
    /// </summary>
    public long RequestCount { get; init; }
    public string ComputedAt { get; init; } = "";
}

/// <summary>One row of <c>usage_hourly</c>.</summary>
public sealed class UsageHourlyRow
{
    public string OrgId { get; init; } = "";
    public string Meter { get; init; } = "";
    public string Bucket { get; init; } = "";
    public long Quantity { get; init; }
    public long RedirectQuantity { get; init; }

    /// <summary>
    /// The number of metered events in the bucket: an operator capacity signal, never a billed
    /// meter. HEAD, 304 and error responses emit no event, so this counts metered requests, not
    /// every request. Buckets rolled up before the column existed read 0.
    /// </summary>
    public long RequestCount { get; init; }
    public string ComputedAt { get; init; } = "";
}

/// <summary>One row of <c>storage_snapshot</c>.</summary>
public sealed class StorageSnapshotRow
{
    public string OrgId { get; init; } = "";
    public string DayUtc { get; init; } = "";
    public long HostedBytes { get; init; }
    public long OciUploadedBytes { get; init; }
    public long CacheAttributedBytes { get; init; }
    public long BillableBytes { get; init; }

    /// <summary>Uploaded non-OCI package versions.</summary>
    public long HostedVersionCount { get; init; }

    /// <summary>Uploaded OCI manifests and indexes.</summary>
    public long OciManifestCount { get; init; }

    /// <summary>Uploaded OCI blobs that are not manifests: layers and configs.</summary>
    public long OciBlobCount { get; init; }

    /// <summary>Proxy-cache entries the org reaches.</summary>
    public long CacheEntryCount { get; init; }

    /// <summary>
    /// Rows across <see cref="StorageSnapshotRepository.DbFootprintTables"/>, the org-scoped
    /// growth tables.
    /// </summary>
    public long DbRowCount { get; init; }

    public string CapturedAt { get; init; } = "";

    /// <summary>
    /// The org's artefact count: uploaded non-OCI package versions plus uploaded OCI manifests.
    /// This is the one definition every reader of an artefact count uses; nothing recounts it.
    /// </summary>
    public long ArtifactCount => CountArtifacts(HostedVersionCount, OciManifestCount);

    /// <summary>The artefact-count definition <see cref="ArtifactCount"/> applies.</summary>
    public static long CountArtifacts(long hostedVersionCount, long ociManifestCount) =>
        hostedVersionCount + ociManifestCount;
}
