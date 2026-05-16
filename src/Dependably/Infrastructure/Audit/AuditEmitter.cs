using Dependably.Infrastructure.Siem;
using Dependably.Security;
using Prometheus;

namespace Dependably.Infrastructure.Audit;

/// <summary>
/// Default <see cref="IAuditEmitter"/>. Reads envelope fields from <see cref="HttpContext"/>
/// via <see cref="IHttpContextAccessor"/>: tenant resolver name from configuration,
/// request id from <c>TraceIdentifier</c>, source ip from <c>Connection.RemoteIpAddress</c>,
/// user agent from request header. Persists via <see cref="AuditEventRepository"/>.
///
/// If the persist fails, logs at error level and increments
/// <c>dependably_audit_emit_failures_total</c>. Ops alerts on a non-zero rate — audit gaps
/// are a security concern but they must never break the originating request.
/// </summary>
public sealed class AuditEmitter : IAuditEmitter
{
    /// <summary>
    /// #52 acceptance: "Failure to emit an audit event for a successful operation logs an
    /// error and triggers an alert." The trigger is this counter — wire alerts on
    /// <c>rate(dependably_audit_emit_failures_total[5m]) &gt; 0</c>.
    /// </summary>
    private static readonly Counter EmitFailures = Metrics.CreateCounter(
        "dependably_audit_emit_failures_total",
        "Audit event emit failures (swallowed exceptions in AuditEmitter)",
        new CounterConfiguration { LabelNames = ["event_type"] });

    private readonly AuditEventRepository _repo;
    private readonly IHttpContextAccessor _http;
    private readonly ILogger<AuditEmitter> _logger;
    private readonly string _resolverMode;
    // SIEM forwarder is opt-in (#40). Resolved at construction so the call path stays a
    // single null check; null when no forwarder is configured.
    private readonly SiemForwarderQueue? _siemQueue;

    public AuditEmitter(
        AuditEventRepository repo,
        IHttpContextAccessor http,
        ILogger<AuditEmitter> logger,
        IConfiguration config,
        IServiceProvider sp)
    {
        _repo = repo;
        _http = http;
        _logger = logger;
        _resolverMode = (config["DEPLOYMENT_MODE"] ?? "single").Trim().ToLowerInvariant();
        _siemQueue = sp.GetService<SiemForwarderQueue>();
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
            SourceIp = ctx.GetNormalizedRemoteIp(),
            UserAgent = Truncate(ctx?.Request?.Headers.UserAgent.FirstOrDefault(), 512),
            Outcome = outcome,
            Payload = payloadJson,
            OccurredAt = DateTimeOffset.UtcNow
        };

        try
        {
            await _repo.InsertAsync(ev, ct);

            // Outbound SIEM (#40 + #52). Fire-and-forget: TryEnqueue is non-blocking and
            // drops on overflow with its own metric. Queue is null when SIEM_WEBHOOK_URL /
            // SIEM_SYSLOG_HOST aren't configured — most deployments. Map to the lightweight
            // SiemEvent shape; the typed payload travels in Detail, the forwarder formats
            // it (NDJSON / CEF / RFC5424).
            _siemQueue?.TryEnqueue(new SiemEvent(
                Id:        ev.EventId,
                Action:    ev.EventType,
                Scope:     ev.OrgId is null ? "system" : "tenant",
                OrgId:     ev.OrgId,
                ActorId:   ev.ActorId,
                Ecosystem: null,
                Purl:      null,
                Detail:    ev.Payload,
                CreatedAt: ev.OccurredAt));
        }
        catch (Exception ex)
        {
            // Audit gap: log + count + continue. Don't propagate — the originating operation
            // already succeeded and the caller is past the rollback point. Ops alerts on
            // dependably_audit_emit_failures_total going non-zero (#52 acceptance).
            EmitFailures.WithLabels(eventType).Inc();
            _logger.LogError(ex,
                "Audit emit failed for {EventType} (org {OrgId}, actor {ActorId})",
                eventType, orgId, actorId);
        }
    }

    private static string? Truncate(string? s, int max)
    {
        if (s is null) return null;
        return s.Length <= max ? s : s[..max];
    }
}
