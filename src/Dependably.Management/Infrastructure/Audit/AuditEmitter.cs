using System.Text.Json;
using Dependably.Infrastructure.Audit.Events;
using Dependably.Infrastructure.Observability;
using Dependably.Infrastructure.Siem;
using Dependably.Infrastructure.Webhooks;
using Dependably.Security;

namespace Dependably.Infrastructure.Audit;

/// <summary>
/// Default <see cref="IAuditEmitter"/>. Reads envelope fields from <see cref="HttpContext"/>
/// via <see cref="IHttpContextAccessor"/>: tenant resolver name from configuration,
/// request id from <c>TraceIdentifier</c>, source ip from <c>Connection.RemoteIpAddress</c>,
/// user agent from request header. Persists via <see cref="AuditEventRepository"/>.
///
/// If the persist fails, logs at error level and increments
/// <c>dependably.audit.emit_failures</c> (Prom: <c>dependably_audit_emit_failures_total</c>).
/// Ops alerts on a non-zero rate — audit gaps are a security concern but they must
/// never break the originating request.
///
/// For the package-event family (publish, replace, import) the audit record is also
/// dispatched to the <see cref="IPackageEventSink"/> for outbound webhook delivery, if
/// any webhook subscriptions match the event type and org.
/// </summary>
public sealed class AuditEmitter : IAuditEmitter
{
    private readonly AuditEventRepository _repo;
    private readonly IHttpContextAccessor _http;
    private readonly ILogger<AuditEmitter> _logger;
    private readonly string _resolverMode;
    // SIEM forwarder is opt-in. Resolved at construction so the call path stays a
    // single null check; null when no forwarder is configured.
    private readonly SiemForwarderQueue? _siemQueue;
    private readonly IPackageEventSink? _webhookSink;
    private readonly OrgRepository _orgs;
    private readonly TimeProvider _time;

    /// <summary>
    /// When true, <c>source_ip</c> records the network rather than the host: <c>/24</c> for IPv4,
    /// <c>/48</c> for IPv6. Off by default — attribution is what the trail is for, and the
    /// trade-off against retention is the operator's to make. <c>AUDIT_TRUNCATE_IP</c>.
    ///
    /// Deliberately scoped to the audit write path only. Rate-limit partition keys aggregate for
    /// an unrelated reason (bounding one subscriber's budget) at an unrelated prefix, and abuse
    /// triage may still want full precision there — see
    /// <see cref="Dependably.Security.IpAddressExtensions.NormalizeForRateLimit"/>.
    /// </summary>
    private readonly bool _truncateSourceIp;

    /// <summary>
    /// When false, no <c>user_agent</c> is recorded at all. A UA string is a browser/device
    /// fingerprint with little forensic value beyond "which client", so a deployment that does not
    /// want to hold one can stop holding it. On by default. <c>AUDIT_DISABLE_USER_AGENT</c>.
    /// </summary>
    private readonly bool _captureUserAgent;

    public AuditEmitter(
        AuditEventRepository repo,
        IHttpContextAccessor http,
        ILogger<AuditEmitter> logger,
        IConfiguration config,
        IServiceProvider sp,
        OrgRepository orgs,
        TimeProvider time)
    {
        _repo = repo;
        _http = http;
        _logger = logger;
        _resolverMode = (config["DEPLOYMENT_MODE"] ?? "single").Trim().ToLowerInvariant();
        // Data-minimization knobs for the audit WRITE path. Both default to the attributing
        // behaviour: an audit trail exists to answer "who, from where", and silently degrading
        // that for every deployment would trade one compliance posture for another without the
        // operator choosing. Turning either on is that choice — see the field docs.
        _truncateSourceIp = ParseBool(config["AUDIT_TRUNCATE_IP"]);
        _captureUserAgent = !ParseBool(config["AUDIT_DISABLE_USER_AGENT"]);
        _siemQueue = sp.GetService<SiemForwarderQueue>();
        _webhookSink = sp.GetService<IPackageEventSink>();
        _orgs = orgs;
        _time = time;
    }

    public async Task EmitAsync(
        string eventType,
        string? orgId,
        string actorType,
        string? actorId,
        string outcome,
        string payloadJson,
        CancellationToken ct = default)
    {
        var ctx = _http.HttpContext;
        var ev = new AuditEvent
        {
            EventId = Guid.NewGuid().ToString("D"),  // UUIDv7 once .NET native helper lands; Guid.NewGuid for now
            SchemaVersion = 1,
            EventType = eventType,
            OrgId = orgId,
            TenantResolver = _resolverMode,
            ActorType = actorType,
            ActorId = actorId,
            RequestId = ctx?.TraceIdentifier,
            SourceIp = ResolveSourceIp(ctx),
            UserAgent = _captureUserAgent
                ? Truncate(ctx?.Request?.Headers.UserAgent.FirstOrDefault(), 512)
                : null,
            Outcome = outcome,
            Payload = payloadJson,
            OccurredAt = _time.GetUtcNow()
        };

        try
        {
            await _repo.InsertAsync(ev, ct);

            // Outbound SIEM. Fire-and-forget: TryEnqueue is non-blocking and
            // drops on overflow with its own metric. Queue is null when SIEM_WEBHOOK_URL /
            // SIEM_SYSLOG_HOST aren't configured — most deployments. Map to the lightweight
            // SiemEvent shape; the typed payload travels in Detail, the forwarder formats
            // it (NDJSON / CEF / RFC5424).
            _siemQueue?.TryEnqueue(new SiemEvent(
                Id: ev.EventId,
                Action: ev.EventType,
                Scope: ev.OrgId is null ? "system" : "tenant",
                OrgId: ev.OrgId,
                ActorId: ev.ActorId,
                Ecosystem: null,
                Purl: null,
                Detail: ev.Payload,
                CreatedAt: ev.OccurredAt));

            // Outbound webhook dispatch for the package-event family. Non-blocking: Dispatch
            // returns immediately; the queue handles delivery asynchronously.
            if (_webhookSink is not null && orgId is not null && IsPackageEventType(eventType))
            {
                await DispatchPackageEventAsync(ev, orgId, actorId, payloadJson, ct);
            }
        }
        catch (Exception ex)
        {
            // Audit gap: log + count + continue. Don't propagate — the originating operation
            // already succeeded and the caller is past the rollback point. Ops alerts on
            // dependably_audit_emit_failures_total going non-zero.
            DependablyMeter.AuditEmitFailures.Add(1, new KeyValuePair<string, object?>("event_type", eventType));
            _logger.LogError(ex,
                "Audit emit failed for {EventType} (org {OrgId}, actor {ActorId})",
                eventType, orgId, actorId);
        }
    }

    // Builds a PackageEventEnvelope from a publish/replace/import audit payload JSON and
    // dispatches it to the webhook sink. Parses the JSON payload to recover the structured
    // fields — the payload already carries everything needed for the envelope. Failure is
    // swallowed: webhook dispatch is best-effort and must not break the publish path.
    private async Task DispatchPackageEventAsync(
        AuditEvent ev, string orgId, string? actorId, string payloadJson, CancellationToken ct)
    {
        try
        {
            using var doc = JsonDocument.Parse(payloadJson);
            var root = doc.RootElement;

            string ecosystem = GetString(root, "ecosystem") ?? "";
            string name = GetString(root, "name") ?? "";
            string version = GetString(root, "version") ?? "";
            string? artifactHash = GetString(root, "artifact_hash");
            string purl = GetString(root, "purl") ?? $"pkg:{ecosystem}/{name}@{version}";

            var org = await _orgs.GetByIdAsync(orgId, ct);
            string orgSlug = org?.Slug ?? orgId;

            _webhookSink!.Dispatch(new PackageEventEnvelope(
                EventType: ev.EventType,
                OrgId: orgId,
                OrgSlug: orgSlug,
                Ecosystem: ecosystem,
                Name: name,
                Version: version,
                Purl: purl,
                ArtifactHash: artifactHash,
                Actor: actorId,
                OccurredAt: ev.OccurredAt,
                DataJson: payloadJson));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to dispatch webhook for {EventType} (org {OrgId}); delivery skipped.",
                ev.EventType, orgId);
        }
    }

    private static bool IsPackageEventType(string eventType) =>
        eventType is PackageEvents.TypePublish
            or PackageEvents.TypeReplace
            or PackageEvents.TypeImport;

    private static string? GetString(JsonElement root, string propertyName) =>
        root.TryGetProperty(propertyName, out var el) && el.ValueKind == JsonValueKind.String
            ? el.GetString() : null;

    // Resolves the recorded source IP under the configured minimization posture.
    private string? ResolveSourceIp(HttpContext? ctx) =>
        _truncateSourceIp
            ? IpAddressExtensions.NormalizeForAuditMinimization(ctx?.Connection?.RemoteIpAddress)
            : ctx.GetNormalizedRemoteIp();

    // Accepts the spellings an operator plausibly writes in a compose file.
    private static bool ParseBool(string? value) =>
        value is not null
        && (value.Trim().Equals("true", StringComparison.OrdinalIgnoreCase)
            || value.Trim() == "1"
            || value.Trim().Equals("yes", StringComparison.OrdinalIgnoreCase));

    // Char-index (UTF-16 code unit) truncation, but never on an unpaired surrogate: the
    // User-Agent header is fully client-controlled, so an astral-plane character (e.g. an
    // emoji) can be engineered to straddle the cut point. Cutting at `max` in that case would
    // keep a lone high surrogate at the end of the persisted string — invalid UTF-16 that does
    // not round-trip through UTF-8 storage or SIEM/webhook JSON export.
    private static string? Truncate(string? s, int max)
    {
        if (s is null || s.Length <= max)
        {
            return s;
        }

        int cut = max;
        if (cut > 0 && char.IsHighSurrogate(s[cut - 1]))
        {
            cut--;
        }
        return s[..cut];
    }
}
