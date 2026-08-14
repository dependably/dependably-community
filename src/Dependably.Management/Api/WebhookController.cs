using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit.Events;
using Dependably.Infrastructure.Identity;
using Dependably.Infrastructure.Webhooks;
using Dependably.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Api;

/// <summary>
/// Per-org outbound webhook subscriptions, surfaced under Settings → Webhooks.
/// Manages CRUD for <c>webhook_subscription</c> rows plus a test-ping action and
/// secret rotation. Routes to /api/v1/webhooks, which lands in the management
/// OpenAPI document automatically (route-prefix-driven).
///
/// HMAC signing secrets are write-only: GET responses never return the secret value;
/// callers see a computed <c>hasSecret</c> boolean. Storing a secret requires
/// <c>DEPENDABLY_MASTER_KEY</c> to be configured (fail-closed).
///
/// Management API responses are camelCase (JsonSerializerDefaults.Web); the outbound
/// webhook body is snake_case (EventJsonOptions.Snake) — these two serialization
/// contexts are explicitly kept separate.
/// </summary>
[ApiController]
[Authorize]
public sealed class WebhookController : OrgScopedControllerBase
{
    // Audit-detail-only options for this controller (subscription id/url pairs): the shared
    // camelCase Web contract with the relaxed encoder added so a webhook URL's query string
    // doesn't render with literal \uXXXX escapes for '&'/'+' in the audit UI.
    private static readonly JsonSerializerOptions WebJson = new(JsonContracts.Web)
    {
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>
    /// Upper bound on webhook subscriptions per org. Deliberately generous — it is a blast-radius
    /// bound, not a product limit: one event fans out to every matching subscription, and the
    /// dispatch queue gives each org's envelope a bounded time budget, so an unbounded list would
    /// let an org queue more delivery work per event than any single envelope can attempt.
    /// </summary>
    internal const int MaxSubscriptionsPerOrg = 50;

    private static readonly HashSet<string> ValidEventTypes = new(StringComparer.Ordinal)
    {
        PackageEvents.TypePublish,
        PackageEvents.TypeReplace,
        PackageEvents.TypeImport,
        PackageEvents.TypeUnlist,
        PackageEvents.TypeYank,
        PackageEvents.TypeVuln,
    };

    private readonly WebhookSubscriptionRepository _webhooks;
    private readonly OrgAccessGuard _guard;
    private readonly AuditRepository _audit;
    private readonly ProblemResults _problems;
    private readonly IPackageEventSink _sink;
    private readonly EnvelopeProtector _envelope;
    private readonly IConfiguration _config;
    private readonly TimeProvider _time;

    // Each parameter is a distinct DI-registered service the controller depends on directly;
    // grouping them into a wrapper type would just move the coupling without reducing it.
#pragma warning disable S107 // constructor injection of independently-registered DI services
    public WebhookController(
        WebhookSubscriptionRepository webhooks,
        OrgAccessGuard guard,
        AuditRepository audit,
        ProblemResults problems,
        IPackageEventSink sink,
        EnvelopeProtector envelope,
        IConfiguration config,
        TimeProvider time)
#pragma warning restore S107
    {
        _webhooks = webhooks;
        _guard = guard;
        _audit = audit;
        _problems = problems;
        _sink = sink;
        _envelope = envelope;
        _config = config;
        _time = time;
    }

    /// <summary>GET /api/v1/webhooks</summary>
    [HttpGet("api/v1/webhooks")]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        var items = await _webhooks.ListAsync(CurrentTenantId(), ct);
        return Ok(items);
    }

    /// <summary>GET /api/v1/webhooks/{id}</summary>
    [HttpGet("api/v1/webhooks/{id}")]
    public async Task<IActionResult> Get(string id, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.ReadTenant, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        var sub = await _webhooks.GetAsync(CurrentTenantId(), id, ct);
        return sub is null ? NotFound() : Ok(sub);
    }

    /// <summary>POST /api/v1/webhooks</summary>
    [HttpPost("api/v1/webhooks")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    public async Task<IActionResult> Add([FromBody] WebhookRequest req, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        var problem = ValidateRequest(req);
        if (problem is not null)
        {
            return problem;
        }

        if (!string.IsNullOrEmpty(req.Secret) && !_envelope.IsConfigured)
        {
            return _problems.ValidationErrorActionKey("secret", "error.webhook.masterKeyRequired");
        }

        bool allowPrivate = string.Equals(
            _config["WEBHOOK_ALLOW_PRIVATE"], "true", StringComparison.OrdinalIgnoreCase);
        string? urlError = WebhookDeliveryClient.ValidateWebhookUrl(req.Url!, allowPrivate);
        if (urlError is not null)
        {
            return _problems.ValidationErrorAction("url", urlError);
        }

        string orgId = CurrentTenantId();

        // Every subscription multiplies the delivery work one event creates, and the delivery
        // queue serves each org one envelope at a time — so an unbounded subscription list is an
        // org's own delivery latency, not an instance-wide one, but it is still unbounded. The cap
        // keeps a single event's fan-out to a size the per-envelope budget can actually attempt.
        // Counting and then inserting is not atomic: N creates that read the count before any of
        // them inserts all pass, so the stored total can exceed the cap by up to N-1 and those
        // extra rows stay until someone deletes them — every later create is refused, which stops
        // the overshoot growing but does not undo it. That is an accepted bound for a
        // blast-radius limit, whose job is to keep the fan-out the same order of magnitude as the
        // budget, not to hold an exact number.
        if (await _webhooks.CountAsync(orgId, ct) >= MaxSubscriptionsPerOrg)
        {
            return _problems.ValidationErrorActionKey(
                "url", "error.webhook.maxPerOrg", MaxSubscriptionsPerOrg);
        }

        var sub = await _webhooks.AddAsync(orgId, new NewWebhookSubscription(
            req.Url!, req.EventTypes!, req.Secret, req.Description), ct);

        await _audit.LogAsync("webhook_subscription_added", orgId, GetUserId(),
            actorKind: ActorKinds.User,
            detail: JsonSerializer.Serialize(new { id = sub.Id, url = sub.Url }, WebJson),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return CreatedAtAction(nameof(Get), new { id = sub.Id }, sub);
    }

    /// <summary>PUT /api/v1/webhooks/{id}</summary>
    [HttpPut("api/v1/webhooks/{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Update(string id, [FromBody] WebhookRequest req, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        var problem = ValidateRequest(req);
        if (problem is not null)
        {
            return problem;
        }

        if (!string.IsNullOrEmpty(req.Secret) && !_envelope.IsConfigured)
        {
            return _problems.ValidationErrorActionKey("secret", "error.webhook.masterKeyRequired");
        }

        bool allowPrivate = string.Equals(
            _config["WEBHOOK_ALLOW_PRIVATE"], "true", StringComparison.OrdinalIgnoreCase);
        string? urlError = WebhookDeliveryClient.ValidateWebhookUrl(req.Url!, allowPrivate);
        if (urlError is not null)
        {
            return _problems.ValidationErrorAction("url", urlError);
        }

        string orgId = CurrentTenantId();
        var updated = await _webhooks.UpdateAsync(orgId, id, new UpdateWebhookSubscription(
            req.Url!, req.EventTypes!, req.Enabled ?? true, req.Secret, req.Description), ct);

        if (updated is null)
        {
            return NotFound();
        }

        await _audit.LogAsync("webhook_subscription_updated", orgId, GetUserId(),
            actorKind: ActorKinds.User,
            detail: JsonSerializer.Serialize(new { id, url = req.Url }, WebJson),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return Ok(updated);
    }

    /// <summary>DELETE /api/v1/webhooks/{id}</summary>
    [HttpDelete("api/v1/webhooks/{id}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Delete(string id, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = CurrentTenantId();
        await _webhooks.DeleteAsync(orgId, id, ct);

        await _audit.LogAsync("webhook_subscription_deleted", orgId, GetUserId(),
            actorKind: ActorKinds.User,
            detail: JsonSerializer.Serialize(new { id }, WebJson),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return NoContent();
    }

    /// <summary>POST /api/v1/webhooks/{id}/test — sends a signed webhook.ping to the endpoint.</summary>
    [HttpPost("api/v1/webhooks/{id}/test")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    public async Task<IActionResult> Test(string id, CancellationToken ct)
    {
        var authResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
        if (authResult is not null)
        {
            return authResult;
        }

        string orgId = CurrentTenantId();
        var sub = await _webhooks.GetAsync(orgId, id, ct);
        if (sub is null)
        {
            return NotFound();
        }

        // Dispatch a synthetic webhook.ping event so the user can verify their endpoint is reachable.
        var orgs = HttpContext.RequestServices.GetRequiredService<OrgRepository>();
        var org = await orgs.GetByIdAsync(orgId, ct);
        string orgSlug = org?.Slug ?? orgId;

        _sink.Dispatch(new PackageEventEnvelope(
            EventType: "webhook.ping",
            OrgId: orgId,
            OrgSlug: orgSlug,
            Ecosystem: "system",
            Name: "",
            Version: "",
            Purl: "",
            ArtifactHash: null,
            Actor: GetUserId(),
            OccurredAt: _time.GetUtcNow(),
            DataJson: """{"triggered_by":"test"}"""));

        await _audit.LogAsync("webhook_test_sent", orgId, GetUserId(),
            actorKind: ActorKinds.User,
            detail: JsonSerializer.Serialize(new { id, url = sub.Url }, WebJson),
            sourceIp: HttpContext.GetNormalizedRemoteIp(), ct: ct);

        return NoContent();
    }

    // Validates common request fields: url required, event types non-empty and from the
    // closed vocab. Returns a problem result on the first failure, or null when valid.
    private IActionResult? ValidateRequest(WebhookRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Url))
        {
            return _problems.ValidationErrorActionKey("url", "error.webhook.urlRequired");
        }

        if (req.EventTypes is null || req.EventTypes.Count == 0)
        {
            return _problems.ValidationErrorActionKey("eventTypes", "error.webhook.eventTypeRequired");
        }

        var unknown = req.EventTypes.Where(t => !ValidEventTypes.Contains(t)).ToList();
        return unknown.Count > 0
            ? _problems.ValidationErrorActionKey(
                "eventTypes", "error.webhook.unknownEventTypes",
                string.Join(", ", unknown), string.Join(", ", ValidEventTypes))
            : null;
    }
}

/// <summary>Request body for create and update.</summary>
public sealed class WebhookRequest
{
    public string? Url { get; set; }
    public List<string>? EventTypes { get; set; }
    public bool? Enabled { get; set; }
    /// <summary>
    /// HMAC signing secret. Write-only — never returned in responses. Null = no change on update.
    /// </summary>
    public string? Secret { get; set; }
    public string? Description { get; set; }
}
