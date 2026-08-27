namespace Dependably.Infrastructure.VulnTracker;

/// <summary>
/// A resolved connection to the external vulnerability tracker that supplies the NVD-band and
/// SSVC enrichment overlay. There is exactly one of these per deployment: the connection is
/// instance-level state owned by the operator, and every tenant is served over it. Tenants
/// configure what the deployment does with the signals (the per-org block-gate thresholds),
/// never how the signals are fetched — the same split
/// <see cref="Dependably.Infrastructure.Mail.SmtpTransportSettings"/> draws for mail.
///
/// <para>
/// Never serialized to a client directly: <see cref="Token"/> is a bearer credential, so
/// callers project the fields they need and report the token only as a "one is set" boolean.
/// </para>
/// </summary>
public sealed record VulnTrackerSettings(
    string? BaseUrl,
    string? Token,
    int MaxStalenessHours,
    int BatchSize)
{
    /// <summary>
    /// Default enforcement horizon, in hours. Sized off the two ingest legs it has to clear:
    /// the producer ingests NVD and Vulnrichment on a daily batch, and dependably's own rescan
    /// pass is daily, so ordinary operation is already up to ~48h stale end to end. Seven days
    /// leaves room for a weekend-long producer outage before enrichment starts reading as
    /// unknown, while still being a bound rather than an open-ended one.
    /// </summary>
    public const int DefaultMaxStalenessHours = 168;

    /// <summary>
    /// Default purls per lookup request, matching <c>VulnerabilityScanService</c>'s own OSV
    /// batch size so enrichment never widens the fan-out of the scan pass it rides on.
    /// </summary>
    public const int DefaultBatchSize = 100;

    /// <summary>
    /// The producer's published per-request cap. A batch over this is rejected by the producer
    /// rather than truncated — a silently dropped tail would read as "no vulnerabilities" for
    /// every purl in it — so the write surface refuses to store a size the producer will refuse
    /// to serve, instead of letting every pass fail at request time.
    /// </summary>
    public const int MaxBatchSize = 1000;

    /// <summary>Upper bound on the staleness horizon: one year, in hours.</summary>
    public const int MaxStalenessHoursCeiling = 8760;

    /// <summary>
    /// True when enough of the connection is present to attempt a lookup. Deliberately only the
    /// base URL: a tracker reachable without a credential is a legitimate self-hosted shape, and
    /// a tracker that *does* require one answers 401, which the client treats as unreached —
    /// stamps do not advance and nothing is recorded as checked-and-clean. So a missing token
    /// degrades to "no enrichment", never to "enrichment says fine".
    /// </summary>
    public bool IsConfigured => TryParseBaseUrl(BaseUrl, out _);

    /// <summary>
    /// Parses <paramref name="baseUrl"/> as the absolute HTTP(S) URI the client will call.
    /// A relative URI, a non-HTTP scheme (<c>file:</c>, <c>ftp:</c>, <c>gopher:</c>) or an
    /// unparseable string is rejected here rather than at request time — a scheme allowlist,
    /// not a denylist, so a scheme this code has never seen fails closed.
    /// </summary>
    public static bool TryParseBaseUrl(string? baseUrl, out Uri? parsed)
    {
        parsed = null;
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            return false;
        }

        if (!Uri.TryCreate(baseUrl.Trim(), UriKind.Absolute, out var uri))
        {
            return false;
        }

        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
        {
            return false;
        }

        parsed = uri;
        return true;
    }

    /// <summary>
    /// Validates the fields the write surface accepts. Returns the first failing field name and
    /// its SharedResource key, or <c>(null, null)</c> when everything supplied is valid. The
    /// token is an opaque string with no format to check here. An empty base URL is valid — it
    /// is how an operator clears the connection and turns the feature off.
    /// </summary>
    public static (string? Field, string? ResourceKey) Validate(
        string? baseUrl, int? maxStalenessHours, int? batchSize)
    {
        if (!string.IsNullOrWhiteSpace(baseUrl) && !TryParseBaseUrl(baseUrl, out _))
        {
            return ("baseUrl", "error.vulnTracker.invalidBaseUrl");
        }

        if (maxStalenessHours is { } hours && (hours < 1 || hours > MaxStalenessHoursCeiling))
        {
            return ("maxStalenessHours", "error.vulnTracker.invalidStaleness");
        }

        if (batchSize is { } size && (size < 1 || size > MaxBatchSize))
        {
            return ("batchSize", "error.vulnTracker.invalidBatchSize");
        }

        return (null, null);
    }
}
