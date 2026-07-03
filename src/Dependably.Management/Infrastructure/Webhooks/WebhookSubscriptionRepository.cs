using System.Text.Json;
using Dapper;
using Dependably.Infrastructure.Identity;

namespace Dependably.Infrastructure.Webhooks;

/// <summary>
/// Dapper-backed store for <c>webhook_subscription</c> rows. Every query filters
/// on <c>org_id</c> to enforce tenant isolation. The HMAC signing secret is
/// envelope-encrypted at rest via <see cref="EnvelopeProtector"/> when
/// <c>DEPENDABLY_MASTER_KEY</c> is configured; the API layer enforces that a secret
/// can only be stored when the key is present.
/// </summary>
public sealed class WebhookSubscriptionRepository
{
    private readonly IMetadataStore _db;
    private readonly EnvelopeProtector _envelope;
    private readonly TimeProvider _time;

    public WebhookSubscriptionRepository(IMetadataStore db, EnvelopeProtector envelope, TimeProvider time)
    {
        _db = db;
        _envelope = envelope;
        _time = time;
    }

    /// <summary>All subscriptions for an org, ordered by creation date.</summary>
    public async Task<IReadOnlyList<WebhookSubscription>> ListAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<RawRow>(
            """
            SELECT id AS Id, org_id AS OrgId, url AS Url, event_types AS EventTypesJson,
                   enabled AS Enabled, secret AS SecretStored,
                   description AS Description, last_delivery_at AS LastDeliveryAt,
                   last_status AS LastStatus, consecutive_failures AS ConsecutiveFailures,
                   failing_since AS FailingSince, last_error AS LastError,
                   created_at AS CreatedAt, updated_at AS UpdatedAt
            FROM webhook_subscription
            WHERE org_id = @orgId
            ORDER BY created_at
            """,
            new { orgId });
        return rows.Select(MapRow).ToList();
    }

    /// <summary>Single subscription by id, scoped to org.</summary>
    public async Task<WebhookSubscription?> GetAsync(string orgId, string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var row = await conn.QuerySingleOrDefaultAsync<RawRow>(
            """
            SELECT id AS Id, org_id AS OrgId, url AS Url, event_types AS EventTypesJson,
                   enabled AS Enabled, secret AS SecretStored,
                   description AS Description, last_delivery_at AS LastDeliveryAt,
                   last_status AS LastStatus, consecutive_failures AS ConsecutiveFailures,
                   failing_since AS FailingSince, last_error AS LastError,
                   created_at AS CreatedAt, updated_at AS UpdatedAt
            FROM webhook_subscription
            WHERE org_id = @orgId AND id = @id
            """,
            new { orgId, id });
        return row is null ? null : MapRow(row);
    }

    /// <summary>
    /// All enabled subscriptions for an org that include the given event type.
    /// Used by the delivery fan-out path; returns the decrypted secret for signing.
    /// </summary>
    internal async Task<IReadOnlyList<WebhookSubscriptionDelivery>> ListEnabledForEventAsync(
        string orgId, string eventType, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        var rows = await conn.QueryAsync<RawDeliveryRow>(
            """
            SELECT id AS Id, org_id AS OrgId, url AS Url, secret AS SecretStored,
                   event_types AS EventTypesJson, consecutive_failures AS ConsecutiveFailures,
                   failing_since AS FailingSince
            FROM webhook_subscription
            WHERE org_id = @orgId AND enabled = 1
            """,
            new { orgId });

        // Filter event types in application layer so we can parse JSON without raw SQL
        // and avoid injecting user-supplied event type strings into a SQL query.
        return rows
            .Where(r => ParseEventTypes(r.EventTypesJson).Contains(eventType, StringComparer.Ordinal))
            .Select(r => new WebhookSubscriptionDelivery(
                r.Id,
                r.OrgId,
                r.Url,
                r.SecretStored is null ? null : _envelope.Unprotect(r.SecretStored),
                ParseEventTypes(r.EventTypesJson),
                (int)r.ConsecutiveFailures,
                r.FailingSince))
            .ToList();
    }

    /// <summary>Creates a new subscription. Secret must already be protected by the caller.</summary>
    public async Task<WebhookSubscription> AddAsync(
        string orgId, NewWebhookSubscription req, CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        string eventTypesJson = JsonSerializer.Serialize(req.EventTypes);
        // An empty (or absent) secret means unsigned delivery — never protect it. Only a
        // non-empty secret is envelope-encrypted, which requires a configured master key.
        string? encryptedSecret = string.IsNullOrEmpty(req.Secret) ? null : _envelope.Protect(req.Secret);

        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            """
            INSERT INTO webhook_subscription
                (id, org_id, url, secret, event_types, enabled, description, created_at, updated_at)
            VALUES
                (@id, @orgId, @url, @secret, @eventTypesJson, 1, @description, @now, @now)
            """,
            new
            {
                id,
                orgId,
                url = req.Url,
                secret = encryptedSecret,
                eventTypesJson,
                description = req.Description,
                now
            });

        return (await GetAsync(orgId, id, ct))!;
    }

    /// <summary>Updates url, event_types, enabled, description, and optionally rotates the secret.</summary>
    public async Task<WebhookSubscription?> UpdateAsync(
        string orgId, string id, UpdateWebhookSubscription req, CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        string eventTypesJson = JsonSerializer.Serialize(req.EventTypes);
        // A non-empty secret rotates the stored secret; null or empty leaves it unchanged.
        bool rotateSecret = !string.IsNullOrEmpty(req.Secret);
        string? encryptedSecret = rotateSecret ? _envelope.Protect(req.Secret!) : null;

        await using var conn = await _db.OpenAsync(ct);
        int rows;
        if (rotateSecret)
        {
            rows = await conn.ExecuteAsync(
                """
                UPDATE webhook_subscription
                SET url = @url, event_types = @eventTypesJson, enabled = @enabled,
                    description = @description, secret = @secret,
                    consecutive_failures = 0, failing_since = NULL, last_error = NULL,
                    updated_at = @now
                WHERE org_id = @orgId AND id = @id
                """,
                new
                {
                    orgId,
                    id,
                    url = req.Url,
                    eventTypesJson,
                    enabled = req.Enabled ? 1 : 0,
                    description = req.Description,
                    secret = encryptedSecret,
                    now
                });
        }
        else
        {
            rows = await conn.ExecuteAsync(
                """
                UPDATE webhook_subscription
                SET url = @url, event_types = @eventTypesJson, enabled = @enabled,
                    description = @description, updated_at = @now
                WHERE org_id = @orgId AND id = @id
                """,
                new
                {
                    orgId,
                    id,
                    url = req.Url,
                    eventTypesJson,
                    enabled = req.Enabled ? 1 : 0,
                    description = req.Description,
                    now
                });
        }

        return rows == 0 ? null : await GetAsync(orgId, id, ct);
    }

    /// <summary>Deletes a subscription. No-op if not found or wrong org.</summary>
    public async Task DeleteAsync(string orgId, string id, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await conn.ExecuteAsync(
            "DELETE FROM webhook_subscription WHERE org_id = @orgId AND id = @id",
            new { orgId, id });
    }

    /// <summary>
    /// Records a successful delivery: resets failure counters, updates last_delivery_at and
    /// last_status. Called by the dispatch queue after a confirmed 2xx response.
    /// </summary>
    public async Task RecordSuccessAsync(string orgId, string id, CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);
        // xtenant: id is already org-scoped by the FK; explicit org_id filter is defense-in-depth
        await conn.ExecuteAsync(
            """
            UPDATE webhook_subscription
            SET last_delivery_at = @now, last_status = 'ok',
                consecutive_failures = 0, failing_since = NULL, last_error = NULL,
                updated_at = @now
            WHERE org_id = @orgId AND id = @id
            """,
            new { orgId, id, now });
    }

    /// <summary>
    /// Records a terminal delivery failure and conditionally auto-disables the subscription
    /// when consecutive_failures reaches the threshold OR the failing_since window has elapsed.
    /// Returns true when the subscription was auto-disabled so the caller can log/notify.
    /// </summary>
    public async Task<bool> RecordFailureAsync(
        string orgId, string id, string error,
        int autoDisableAfterFailures, TimeSpan autoDisableAfterDuration,
        CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToString("yyyy-MM-ddTHH:mm:ssZ");
        await using var conn = await _db.OpenAsync(ct);

        // Read current counters to decide whether to auto-disable.
        // xtenant: id is already org-scoped by the FK; explicit org_id filter is defense-in-depth
        var (currentFailures, currentFailingSince) = await conn.QuerySingleOrDefaultAsync<(long Failures, string? FailingSince)>(
            """
            SELECT consecutive_failures AS Failures, failing_since AS FailingSince
            FROM webhook_subscription
            WHERE org_id = @orgId AND id = @id
            """,
            new { orgId, id });

        int newFailures = (int)currentFailures + 1;
        string? failingSince = currentFailingSince ?? now;

        // Auto-disable when count threshold OR duration window is exceeded.
        bool autoDisable = newFailures >= autoDisableAfterFailures
            || (DateTimeOffset.TryParse(failingSince, out var since)
                && _time.GetUtcNow() - since >= autoDisableAfterDuration);

        // Truncate error message to avoid unbounded DB column growth.
        string truncatedError = error.Length > 500 ? error[..500] : error;

        await conn.ExecuteAsync(
            """
            UPDATE webhook_subscription
            SET last_delivery_at = @now, last_status = 'failed',
                consecutive_failures = @newFailures, failing_since = @failingSince,
                last_error = @truncatedError,
                enabled = CASE WHEN @autoDisable = 1 THEN 0 ELSE enabled END,
                updated_at = @now
            WHERE org_id = @orgId AND id = @id
            """,
            new
            {
                orgId,
                id,
                now,
                newFailures,
                failingSince,
                truncatedError,
                autoDisable = autoDisable ? 1 : 0
            });

        return autoDisable;
    }

    // Raw Dapper projection for the API-facing read path (no secret column).
    // SQLite returns all INTEGER columns as Int64; use long for every integer field to avoid
    // Dapper constructor-matching errors, then convert in MapRow.
    // HasSecret is derived in C# from the raw secret column rather than a SQL CASE:
    // Microsoft.Data.Sqlite reports computed/expression columns as byte[] (no declared
    // type affinity), which fails RawRow materialization on the buffered QueryAsync path.
    private sealed record RawRow(
        string Id, string OrgId, string Url, string EventTypesJson, long Enabled,
        string? SecretStored, string? Description, string? LastDeliveryAt, string? LastStatus,
        long ConsecutiveFailures, string? FailingSince, string? LastError,
        string CreatedAt, string UpdatedAt);

    // Raw Dapper projection for the delivery fan-out path (includes encrypted secret).
    private sealed record RawDeliveryRow(
        string Id, string OrgId, string Url, string? SecretStored,
        string EventTypesJson, long ConsecutiveFailures, string? FailingSince);

    private static WebhookSubscription MapRow(RawRow r) => new(
        r.Id, r.OrgId, r.Url,
        ParseEventTypes(r.EventTypesJson),
        r.Enabled != 0, r.SecretStored is not null, r.Description,
        r.LastDeliveryAt, r.LastStatus,
        (int)r.ConsecutiveFailures, r.FailingSince, r.LastError,
        r.CreatedAt, r.UpdatedAt);

    private static List<string> ParseEventTypes(string? json)
    {
        if (string.IsNullOrEmpty(json))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<List<string>>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }
}

/// <summary>Fields required to create a webhook subscription.</summary>
public sealed record NewWebhookSubscription(
    string Url,
    IReadOnlyList<string> EventTypes,
    string? Secret,
    string? Description);

/// <summary>Fields accepted when updating a webhook subscription.</summary>
public sealed record UpdateWebhookSubscription(
    string Url,
    IReadOnlyList<string> EventTypes,
    bool Enabled,
    string? Secret,
    string? Description);
