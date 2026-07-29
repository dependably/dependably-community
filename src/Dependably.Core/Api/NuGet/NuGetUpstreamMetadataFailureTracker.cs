using Dependably.Protocol;

namespace Dependably.Api.NuGetProtocol;

/// <summary>
/// Accumulates upstream-attempt outcomes across a multi-upstream fallback loop (NuGet
/// registration-index and flatcontainer version-list fetches walk the org's configured
/// upstreams in priority order, trying each in turn) so the caller can tell a genuine
/// "every configured upstream confirmed this does not exist" from "no upstream answered
/// cleanly" before deciding whether an empty result stays a 404 or becomes an
/// <see cref="UpstreamFetchFailedException"/>.
///
/// Applies the exact same credential-aware Refused/Transient classification
/// <c>UpstreamClient.ClassifyAndLogNonSuccess</c> uses for the artifact-fetch retry loop
/// (<c>refused = authorizationHeader is not null &amp;&amp; status is 401 or 403</c>), just
/// per-upstream rather than per-attempt: a confirmed-absent 404/410 from one upstream never
/// counts as a failure (that upstream gave a clean answer). A 401/403 from an upstream this
/// request authenticated to is a deterministic auth/policy refusal; the identical status from
/// an anonymous upstream (the default api.nuget.org configuration) is not a refusal — public
/// registry CDNs emit genuinely transient 403s (bot mitigation, edge throttling) with no
/// credential to be refused, so it is recorded as a non-refusal failure like a 429/5xx,
/// malformed response, timeout, or connection exception. When every recorded failure was an
/// authenticated 401/403 refusal, <see cref="ThrowIfFailed"/> reports the aggregate as
/// non-transient; any other failure mode (including an anonymous 403) marks it transient,
/// favouring a retryable 503 over a permanent 502 when the failure modes are mixed.
/// </summary>
internal sealed class UpstreamMetadataFailureTracker
{
    private bool _hadFailure;
    private bool _allFailuresRefused = true;
    private string _lastUrl = string.Empty;
    private int _lastStatusCode;

    /// <summary>
    /// Records the outcome of one upstream attempt that returned a non-success HTTP status.
    /// A confirmed-absent 404/410 is not recorded as a failure — it is a clean answer. A
    /// 401/403 is recorded as a refusal only when <paramref name="authorizationHeader"/> is
    /// non-null (this request authenticated to the upstream) — an anonymous 401/403, like every
    /// other non-refusal status (429, 5xx, other 4xx), is recorded as a non-refusal (transient)
    /// failure, mirroring <c>UpstreamClient.ClassifyAndLogNonSuccess</c>.
    /// </summary>
    public void RecordHttpStatus(string url, int statusCode, string? authorizationHeader)
    {
        if (statusCode is (int)System.Net.HttpStatusCode.NotFound or (int)System.Net.HttpStatusCode.Gone)
        {
            return;
        }

        bool refused = authorizationHeader is not null
            && statusCode is (int)System.Net.HttpStatusCode.Unauthorized or (int)System.Net.HttpStatusCode.Forbidden;
        Record(url, statusCode, refused);
    }

    /// <summary>
    /// Records an upstream attempt that never produced a usable status — a timeout, a
    /// connection-level exception, or a 2xx response whose body could not be parsed into the
    /// expected shape. Always a non-refusal failure.
    /// </summary>
    public void RecordFailure(string url) => Record(url, statusCode: 0, refused: false);

    private void Record(string url, int statusCode, bool refused)
    {
        _hadFailure = true;
        _lastUrl = url;
        _lastStatusCode = statusCode;
        _allFailuresRefused &= refused;
    }

    /// <summary>
    /// Throws <see cref="UpstreamFetchFailedException"/> when at least one configured upstream
    /// failed non-cleanly. A no-op when every upstream either succeeded or confirmed absence
    /// (404/410) — the caller is responsible for only calling this once every upstream is
    /// exhausted and there is no local fallback to serve instead.
    /// </summary>
    public void ThrowIfFailed()
    {
        if (!_hadFailure)
        {
            return;
        }

        throw new UpstreamFetchFailedException
        {
            Url = _lastUrl,
            StatusCode = _lastStatusCode,
            Transient = !_allFailuresRefused,
            Refused = _allFailuresRefused,
        };
    }
}
