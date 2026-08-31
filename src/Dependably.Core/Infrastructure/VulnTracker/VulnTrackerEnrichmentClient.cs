using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Dependably.Protocol;

namespace Dependably.Infrastructure.VulnTracker;

/// <summary>
/// HTTP client for the external vulnerability tracker's public batch lookup
/// (<c>POST /lookup/batch</c>), supplying the NVD-band and SSVC enrichment overlay.
///
/// <para>
/// The connection is resolved per call from <see cref="InstanceVulnTrackerConfig"/> rather than
/// baked into the named <see cref="HttpClient"/>, because it is instance state an operator edits
/// at runtime: base address and credential move without a restart, and an unconfigured deployment
/// never dials at all. The named client therefore carries only transport posture — timeout,
/// response-body cap, redirect refusal and the connect-time SSRF guard.
/// </para>
///
/// <para>
/// <b>Every no-answer path is unreached, never empty.</b> Transport failure, timeout, 401/403,
/// 429, 5xx, any other non-2xx and an unparseable 2xx all return
/// <see cref="VulnerabilityEnrichmentBatchResult.Reached"/> false with no local stamp. The reason
/// this is stricter than it looks: an enrichment stamp is what re-enables the gate arms that read
/// unknown while it is absent, so one false checked-and-clean answer converts a fail-closed
/// unknown into a pass for every tenant on the deployment at once.
/// </para>
/// </summary>
public sealed class VulnTrackerEnrichmentClient : IVulnerabilityEnrichmentSource
{
    /// <summary>Name of the transport-configured client in <see cref="IHttpClientFactory"/>.</summary>
    public const string HttpClientName = "vulntracker";

    /// <summary>Path of the producer's batch lookup, relative to the configured base URL.</summary>
    public const string LookupBatchPath = "lookup/batch";

    /// <summary>Path of the producer's client-identity handshake, relative to the configured base URL.</summary>
    public const string HandshakePath = "client/handshake";

    /// <summary>
    /// The identity this deployment announces at handshake. A fixed literal, not per-org: the
    /// producer's connection is instance-level (one token can back a whole multi-tenant install),
    /// so the thing identifying itself is this product, not any one tenant on it.
    /// </summary>
    private const string ClientName = "dependably-community";

    private static readonly string ClientVersion =
        typeof(VulnTrackerEnrichmentClient).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? typeof(VulnTrackerEnrichmentClient).Assembly.GetName().Version?.ToString()
        ?? "unknown";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        // The producer is an external wire format, not a frontend payload: snake_case, matching
        // the OSV and SIEM clients rather than the camelCase the Svelte frontend consumes.
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        NumberHandling = JsonNumberHandling.AllowReadingFromString,
    };

    private readonly IHttpClientFactory _httpFactory;
    private readonly InstanceVulnTrackerConfig _config;
    private readonly TimeProvider _time;
    private readonly ILogger<VulnTrackerEnrichmentClient> _logger;

    public VulnTrackerEnrichmentClient(
        IHttpClientFactory httpFactory,
        InstanceVulnTrackerConfig config,
        TimeProvider time,
        ILogger<VulnTrackerEnrichmentClient> logger)
    {
        _httpFactory = httpFactory;
        _config = config;
        _time = time;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<VulnerabilityEnrichmentBatchResult> TryLookupBatchAsync(
        IReadOnlyList<EnrichmentLookupTarget> targets, CancellationToken ct = default)
    {
        if (targets.Count == 0)
        {
            return VulnerabilityEnrichmentBatchResult.Unreached(0, EnrichmentUnreachedReason.EmptyRequest);
        }

        var resolved = await _config.ResolveAsync(ct);
        if (!resolved.IsActive
            || !VulnTrackerSettings.TryParseBaseUrl(resolved.Connection.BaseUrl, out var baseUri)
            || baseUri is null)
        {
            // No connection means the feature does not exist here: no request, no warning, no
            // scan regression. Deliberately not logged — an unconfigured deployment would emit
            // this on every batch of every pass, forever.
            return VulnerabilityEnrichmentBatchResult.Unreached(targets.Count, EnrichmentUnreachedReason.NotConfigured);
        }

        if (targets.Count > VulnTrackerSettings.MaxBatchSize)
        {
            // Refused whole, never trimmed to fit. A truncated tail comes back as "no enrichment"
            // for every purl dropped, which is the one answer this client must never manufacture.
            _logger.LogWarning(
                "Vulnerability tracker lookup refused locally: {PurlCount} purls exceeds the producer cap of {MaxBatchSize}",
                targets.Count, VulnTrackerSettings.MaxBatchSize);
            return VulnerabilityEnrichmentBatchResult.Unreached(targets.Count, EnrichmentUnreachedReason.BatchTooLarge);
        }

        HttpResponseMessage response;
        try
        {
            response = await SendAsync(baseUri, resolved.Connection.Token, targets, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // The caller's own cancellation (shutdown) is not a tracker failure — let it out.
            throw;
        }
        catch (OperationCanceledException ex)
        {
            // HttpClient surfaces its own timeout as a cancellation with an untriggered token.
            _logger.LogWarning(ex,
                "{ExceptionType}: vulnerability tracker lookup timed out for {PurlCount} purls",
                ex.GetType().Name, targets.Count);
            return VulnerabilityEnrichmentBatchResult.Unreached(targets.Count, EnrichmentUnreachedReason.Timeout);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning(ex,
                "{ExceptionType}: vulnerability tracker lookup failed to connect for {PurlCount} purls",
                ex.GetType().Name, targets.Count);
            return VulnerabilityEnrichmentBatchResult.Unreached(targets.Count, EnrichmentUnreachedReason.Transport);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                var reason = ClassifyStatus(response.StatusCode);
                _logger.LogWarning(
                    "Vulnerability tracker lookup returned {Status} for {PurlCount} purls; treated as {Reason}",
                    (int)response.StatusCode, targets.Count, reason);
                return VulnerabilityEnrichmentBatchResult.Unreached(targets.Count, reason);
            }

            string body;
            try
            {
                body = await response.Content.ReadAsStringAsync(ct);
            }
            catch (HttpRequestException ex)
            {
                // The response-body cap trips here: a body over the limit is a failed read, not a
                // short answer.
                _logger.LogWarning(ex,
                    "{ExceptionType}: vulnerability tracker response body could not be read",
                    ex.GetType().Name);
                return VulnerabilityEnrichmentBatchResult.Unreached(targets.Count, EnrichmentUnreachedReason.Transport);
            }

            return Parse(body, targets);
        }
    }

    private async Task<HttpResponseMessage> SendAsync(
        Uri baseUri, string? token, IReadOnlyList<EnrichmentLookupTarget> targets, CancellationToken ct)
    {
        var http = _httpFactory.CreateClient(HttpClientName);

        // Built absolutely from the resolved base URL: the named client has no BaseAddress,
        // because the address is instance state that changes without a restart. Preserving any
        // path prefix the operator configured is why this is a string concat rather than
        // new Uri(baseUri, path), which would discard it.
        // S1075: the "/" is a URL path separator joining a configured base to a relative
        // endpoint, not a hardcoded filesystem or absolute path. The alternative the rule
        // implies — new Uri(baseUri, LookupBatchPath) — is what the comment above rules out.
#pragma warning disable S1075
        var endpoint = new Uri(baseUri.AbsoluteUri.TrimEnd('/') + "/" + LookupBatchPath);
#pragma warning restore S1075

        string requestBody = JsonSerializer.Serialize(new LookupBatchRequest([.. targets.Select(t => new LookupBatchTarget(t.Purl, t.Cves))]), JsonOpts);

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new StringContent(requestBody, Encoding.UTF8, "application/json"),
        };

        if (!string.IsNullOrWhiteSpace(token))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        return await http.SendAsync(request, ct);
    }

    /// <summary>
    /// Identifies this deployment to the tracker via <c>POST /client/handshake</c> — distinct from
    /// <see cref="TryLookupBatchAsync"/>, which only ever proves a token is being used, not by
    /// what. A deliberate, low-frequency call fired from the operator-initiated connection test
    /// (<c>VulnTrackerProbe</c>), not on every scan pass.
    ///
    /// <para>
    /// Best-effort and never throws for a remote failure (mirroring every other method on this
    /// client): the tracker's own record of this deployment's identity is observability on the
    /// producer side only, and nothing here gates enrichment or the scan path, so a failure is
    /// logged and swallowed into <c>false</c> rather than surfaced as an exception the caller must
    /// handle.
    /// </para>
    /// </summary>
    public async Task<bool> TryHandshakeAsync(CancellationToken ct = default)
    {
        var resolved = await _config.ResolveAsync(ct);
        if (!resolved.IsActive
            || !VulnTrackerSettings.TryParseBaseUrl(resolved.Connection.BaseUrl, out var baseUri)
            || baseUri is null)
        {
            return false;
        }

        HttpResponseMessage response;
        try
        {
            response = await SendHandshakeAsync(baseUri, resolved.Connection.Token, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException ex)
        {
            _logger.LogWarning(ex,
                "{ExceptionType}: vulnerability tracker handshake timed out", ex.GetType().Name);
            return false;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning(ex,
                "{ExceptionType}: vulnerability tracker handshake failed to connect", ex.GetType().Name);
            return false;
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Vulnerability tracker handshake returned {Status}", response.StatusCode);
                return false;
            }
            return true;
        }
    }

    private async Task<HttpResponseMessage> SendHandshakeAsync(Uri baseUri, string? token, CancellationToken ct)
    {
        var http = _httpFactory.CreateClient(HttpClientName);

        // Same absolute-URL construction as SendAsync, for the same reason: preserving an
        // operator-configured path prefix.
#pragma warning disable S1075
        var endpoint = new Uri(baseUri.AbsoluteUri.TrimEnd('/') + "/" + HandshakePath);
#pragma warning restore S1075

        string requestBody = JsonSerializer.Serialize(new HandshakeRequest(ClientName, ClientVersion), JsonOpts);

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new StringContent(requestBody, Encoding.UTF8, "application/json"),
        };

        if (!string.IsNullOrWhiteSpace(token))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        return await http.SendAsync(request, ct);
    }

    private sealed record HandshakeRequest(string ClientName, string ClientVersion);

    /// <summary>
    /// Maps a non-2xx status onto its unreached reason. Every arm is unreached — the mapping only
    /// records which refusal it was, so an operator can tell a wrong credential from a quota wall
    /// from a producer outage without any of the three becoming a clean answer.
    /// </summary>
    private static EnrichmentUnreachedReason ClassifyStatus(HttpStatusCode status) => status switch
    {
        HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => EnrichmentUnreachedReason.Unauthorized,
        HttpStatusCode.TooManyRequests or HttpStatusCode.PaymentRequired => EnrichmentUnreachedReason.RateLimited,
        >= HttpStatusCode.InternalServerError => EnrichmentUnreachedReason.ServerError,
        _ => EnrichmentUnreachedReason.Refused,
    };

    private VulnerabilityEnrichmentBatchResult Parse(
        string body, IReadOnlyList<EnrichmentLookupTarget> targets)
    {
        LookupBatchResponse? parsed;
        try
        {
            parsed = JsonSerializer.Deserialize<LookupBatchResponse>(body, JsonOpts);
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex,
                "{ExceptionType}: vulnerability tracker returned an unparseable body",
                ex.GetType().Name);
            return VulnerabilityEnrichmentBatchResult.Unreached(targets.Count, EnrichmentUnreachedReason.MalformedResponse);
        }

        var rawResults = parsed?.Results;
        if (rawResults is null || rawResults.Count != targets.Count)
        {
            // Results are parallel to inputs by contract. A different length means this client
            // cannot say which purl each entry belongs to, and guessing would attribute one
            // package's enrichment to another — so the whole answer is discarded as unusable
            // rather than partially trusted.
            _logger.LogWarning(
                "Vulnerability tracker returned {ResultCount} results for {PurlCount} purls; discarding the response",
                rawResults?.Count ?? 0, targets.Count);
            return VulnerabilityEnrichmentBatchResult.Unreached(targets.Count, EnrichmentUnreachedReason.MalformedResponse);
        }

        var results = new List<IReadOnlyList<AdvisoryEnrichment>>(targets.Count);
        for (int i = 0; i < rawResults.Count; i++)
        {
            var entry = rawResults[i];

            // The producer echoes the purl it answered for. When it does and the echo does not
            // match, the arrays are misaligned however plausible each row looks on its own.
            if (!string.IsNullOrEmpty(entry?.Purl)
                && !string.Equals(entry.Purl, targets[i].Purl, StringComparison.Ordinal))
            {
                _logger.LogWarning(
                    "Vulnerability tracker result {Index} answered for a different purl than requested; discarding the response",
                    i);
                return VulnerabilityEnrichmentBatchResult.Unreached(targets.Count, EnrichmentUnreachedReason.MalformedResponse);
            }

            var advisories = new List<AdvisoryEnrichment>();
            foreach (var raw in entry?.Advisories ?? [])
            {
                var advisory = ToEnrichment(raw, targets[i].Purl);
                if (advisory is not null)
                {
                    advisories.Add(advisory);
                }
            }

            results.Add(advisories);
        }

        var freshness = (parsed?.Freshness ?? [])
            .Where(f => !string.IsNullOrWhiteSpace(f.Source))
            .Select(f => new EnrichmentSourceFreshness(f.Source!.Trim(), ParseInstant(f.LastIngest)))
            .ToList();

        return new VulnerabilityEnrichmentBatchResult(
            results,
            reached: true,
            checkedAt: _time.GetUtcNow(),
            freshness,
            EnrichmentUnreachedReason.None);
    }

    private AdvisoryEnrichment? ToEnrichment(AdvisoryRaw? raw, string purl)
    {
        if (raw is null || string.IsNullOrWhiteSpace(raw.VulnId))
        {
            return null;
        }

        var status = ParseStatus(raw.Status);
        if (status == EnrichmentAdvisoryStatus.Unrecognized)
        {
            _logger.LogWarning(
                "Vulnerability tracker advisory {AdvisoryId} carried an uninterpretable status; treated as no signal",
                raw.VulnId);
        }

        return new AdvisoryEnrichment(
            AdvisoryId: raw.VulnId.Trim(),
            Cve: string.IsNullOrWhiteSpace(raw.CanonicalCve) ? null : raw.CanonicalCve.Trim(),
            Status: status,
            Nvd: ToBand(raw.NistBand, raw.NistScore),
            Ssvc: ToSsvc(raw.SsvcExploitation, raw.SsvcAutomatable, raw.SsvcTechnicalImpact),
            Mal: ToMal(raw),
            ExploitCode: ToExploitCode(raw),
            Cvelist: ToCvelist(raw),
            MalStillLiveForRequestedVersion: IsStillLiveForRequestedVersion(raw, purl));
    }

    /// <summary>
    /// The raw OpenSSF malicious-packages pass-through, or null when the producer carried none of
    /// its five fields at all — the same "nothing to show" convention <see cref="ToBand"/> and
    /// <see cref="ToSsvc"/> use, rather than a record whose every member happens to be null.
    /// </summary>
    private static MalSignal? ToMal(AdvisoryRaw raw) =>
        raw.MalCompromisedVersions is null && raw.MalVersionCompromised is null
            && raw.MalStillLive is null && raw.MalLiveCheckedAt is null && raw.MalLiveVersions is null
            ? null
            : new MalSignal(
                CompromisedVersions: raw.MalCompromisedVersions,
                VersionCompromised: raw.MalVersionCompromised,
                StillLive: raw.MalStillLive,
                LiveCheckedAt: ParseInstant(raw.MalLiveCheckedAt),
                LiveVersions: raw.MalLiveVersions);

    private static ExploitCodeSignal ToExploitCode(AdvisoryRaw raw) =>
        new(raw.ExploitCodeExists, raw.ExploitCodeMaxWeight, raw.ExploitCodeSources);

    private static CvelistSignal? ToCvelist(AdvisoryRaw raw)
    {
        var cvss = ToBand(raw.CvelistCvssSeverity, raw.CvelistCvssScore);
        var ssvc = ToSsvc(raw.CvelistSsvcExploitation, raw.CvelistSsvcAutomatable, raw.CvelistSsvcTechnicalImpact);
        string? provenance = string.IsNullOrWhiteSpace(raw.CvelistCvssProvenance) ? null : raw.CvelistCvssProvenance.Trim();

        return cvss is null && ssvc is null && provenance is null && raw.CvelistCwes is null
            ? null
            : new CvelistSignal(cvss, provenance, raw.CvelistCwes, ssvc);
    }

    /// <summary>
    /// The one piece of real business logic in this client: whether the SPECIFIC version this
    /// lookup requested is still a live malicious threat right now.
    ///
    /// <para>
    /// <c>mal_still_live</c>/<c>mal_live_versions</c> describe the WHOLE flagged package (unioned
    /// across every advisory that flags it), not the one version a purl happened to ask about.
    /// <c>mal_version_compromised</c>, by contrast, IS already scoped to the exact requested
    /// version — true only when that purl's <c>@version</c> is itself in the compromised list. A
    /// package can have two compromised versions where one was cleaned up and one wasn't, so
    /// taking <c>mal_still_live</c> at face value would either let an already-removed version
    /// block installs forever, or — worse — fail to block a version that is genuinely still live.
    /// </para>
    /// </summary>
    private static bool IsStillLiveForRequestedVersion(AdvisoryRaw raw, string purl)
    {
        if (raw.MalVersionCompromised != true)
        {
            return false;
        }

        var parsed = PurlParser.TryParse(purl);
        return parsed is not null && !string.IsNullOrEmpty(parsed.Version)
            && (raw.MalLiveVersions ?? []).Contains(parsed.Version, StringComparer.Ordinal);
    }

    /// <summary>
    /// Maps the producer's status onto the closed set this client understands. An absent or
    /// unrecognized status is <see cref="EnrichmentAdvisoryStatus.Unrecognized"/>, which
    /// dispositions as no signal — a value this code cannot interpret must not clear stored
    /// enrichment, and must not be persisted as though it were live either.
    /// </summary>
    private static EnrichmentAdvisoryStatus ParseStatus(string? status) =>
        status?.Trim().ToLowerInvariant() switch
        {
            "active" => EnrichmentAdvisoryStatus.Active,
            "withdrawn" => EnrichmentAdvisoryStatus.Withdrawn,
            "rejected" => EnrichmentAdvisoryStatus.Rejected,
            "disputed" => EnrichmentAdvisoryStatus.Disputed,
            _ => EnrichmentAdvisoryStatus.Unrecognized,
        };

    private static NvdBand? ToBand(string? band, double? rawScore)
    {
        string? severity = band?.Trim().ToUpperInvariant() switch
        {
            "CRITICAL" => "CRITICAL",
            "HIGH" => "HIGH",
            "MEDIUM" => "MEDIUM",
            "LOW" => "LOW",
            "NONE" => "NONE",
            _ => null,
        };

        // Out-of-range scores are dropped rather than carried. The column takes any REAL, so a
        // nonsense value would persist and then be compared against an operator's tolerance.
        double? score = rawScore is { } s && s >= 0.0 && s <= 10.0 ? s : null;

        return severity is null && score is null ? null : new NvdBand(severity, score);
    }

    private static SsvcDecision? ToSsvc(string? rawExploitation, string? rawAutomatable, string? rawImpact)
    {
        // Each point is normalized against the exact token set its column admits; anything else
        // becomes null, so an unknown value reads as unknown instead of failing the write.
        string? exploitation = Token(rawExploitation, "none", "poc", "active");
        string? automatable = Token(rawAutomatable, "yes", "no");
        string? technicalImpact = Token(rawImpact, "partial", "total");

        return exploitation is null && automatable is null && technicalImpact is null
            ? null
            : new SsvcDecision(exploitation, automatable, technicalImpact);
    }

    private static string? Token(string? value, params string[] allowed)
    {
        string? normalized = value?.Trim().ToLowerInvariant();
        return normalized is not null && Array.IndexOf(allowed, normalized) >= 0 ? normalized : null;
    }

    /// <summary>
    /// Parses a producer-asserted as-of. An unusable value yields null rather than throwing: the
    /// rest of the response is still usable, and a null asserted-at correctly leaves the caller
    /// with no upper bound on that source's staleness.
    /// </summary>
    private static DateTimeOffset? ParseInstant(string? value) =>
        DateTimeOffset.TryParse(
            value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed)
            ? parsed.ToUniversalTime()
            : null;

    // ── Producer wire shapes ──────────────────────────────────────────────────
    // Reconciled against the producer's shipped POST /lookup/batch. The advisory fields are
    // FLAT and carry the producer's own column names (vuln_id, canonical_cve, nist_band, …)
    // rather than the nested nvd/ssvc objects this client was first written against: the
    // producer returns one advisory shape across both /lookup and /lookup/batch, so a consumer
    // of both sees a single shape. Unknown members are ignored, so it may add fields freely.

    /// <summary>
    /// One requested purl, optionally naming the CVEs this deployment has ALREADY resolved for
    /// it. The hints exist because the producer resolves purl → advisory through its own OSV
    /// corpus, which covers four ecosystems, while its NVD mirror and Vulnrichment are
    /// ecosystem-agnostic — so without them a Cargo, Go or Alpine purl comes back empty even
    /// though the enrichment is held. Naming what the local scan already found is free here and
    /// is what gives those ecosystems the overlay at all.
    /// </summary>
    private sealed record LookupBatchTarget(string Purl, IReadOnlyList<string> Cves);

    private sealed record LookupBatchRequest(IReadOnlyList<LookupBatchTarget> Purls);

    private sealed record LookupBatchResponse(
        List<PurlResultRaw?>? Results,
        List<FreshnessRaw>? Freshness);

    private sealed record PurlResultRaw(string? Purl, List<AdvisoryRaw?>? Advisories);

    private sealed record AdvisoryRaw(
        string? VulnId,
        string? CanonicalCve,
        string? Status,
        string? NistBand,
        double? NistScore,
        string? SsvcExploitation,
        string? SsvcAutomatable,
        string? SsvcTechnicalImpact,
        List<string>? MalCompromisedVersions,
        bool? MalVersionCompromised,
        bool? MalStillLive,
        string? MalLiveCheckedAt,
        List<string>? MalLiveVersions,
        bool ExploitCodeExists,
        int? ExploitCodeMaxWeight,
        List<string>? ExploitCodeSources,
        double? CvelistCvssScore,
        string? CvelistCvssSeverity,
        string? CvelistCvssProvenance,
        List<string>? CvelistCwes,
        string? CvelistSsvcExploitation,
        string? CvelistSsvcAutomatable,
        string? CvelistSsvcTechnicalImpact);

    private sealed record FreshnessRaw(string? Source, string? LastIngest);
}
