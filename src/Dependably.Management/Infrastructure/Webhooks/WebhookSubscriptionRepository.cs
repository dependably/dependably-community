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

    /// <summary>
    /// How many subscriptions an org holds, enabled or not. Backs the per-org cap
    /// (<see cref="Dependably.Api.WebhookController.MaxSubscriptionsPerOrg"/>): every
    /// subscription costs a delivery attempt on every matching event, so the count is what bounds
    /// how much work one org's own event can create.
    /// </summary>
    public async Task<int> CountAsync(string orgId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        return await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM webhook_subscription WHERE org_id = @orgId",
            new { orgId });
    }

    /// <summary>Creates a new subscription. Secret must already be protected by the caller.</summary>
    public async Task<WebhookSubscription> AddAsync(
        string orgId, NewWebhookSubscription req, CancellationToken ct = default)
    {
        string id = Guid.NewGuid().ToString("N");
        string now = _time.GetUtcNow().ToUtcIso();
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
        string now = _time.GetUtcNow().ToUtcIso();
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
        string now = _time.GetUtcNow().ToUtcIso();
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
    ///
    /// The count is incremented by the database and read back from the same statement, never
    /// computed in application code from a separately-read snapshot: deliveries for one
    /// subscription run concurrently (a fan-out worker per org, and one dispatch queue per replica
    /// on a Postgres deployment), so two failures that read the same value would both write the
    /// same +1 and the counter would advance by one for two failures — pushing out the very
    /// auto-disable threshold it exists to reach.
    /// </summary>
    public async Task<bool> RecordFailureAsync(
        string orgId, string id, string error,
        int autoDisableAfterFailures, TimeSpan autoDisableAfterDuration,
        CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);

        // Truncate error message to avoid unbounded DB column growth.
        string truncatedError = error.Length > 500 ? error[..500] : error;

        // RETURNING yields the post-update row on both providers, so Failures is the authoritative
        // count this failure produced and FailingSince the first failure of the current streak.
        // xtenant: id is already org-scoped by the FK; explicit org_id filter is defense-in-depth
        var (newFailures, failingSince) = await conn.QuerySingleOrDefaultAsync<(long Failures, string? FailingSince)>(
            """
            UPDATE webhook_subscription
            SET last_delivery_at = @now, last_status = 'failed',
                consecutive_failures = consecutive_failures + 1,
                failing_since = COALESCE(failing_since, @now),
                last_error = @truncatedError,
                updated_at = @now
            WHERE org_id = @orgId AND id = @id
            RETURNING consecutive_failures AS Failures, failing_since AS FailingSince
            """,
            new { orgId, id, now, truncatedError });

        // Auto-disable when count threshold OR duration window is exceeded. A row that no longer
        // exists returns zero failures and a null streak start, which disables nothing.
        bool autoDisable = newFailures > 0
            && (newFailures >= autoDisableAfterFailures
                || (DateTimeOffset.TryParse(failingSince, out var since)
                    && _time.GetUtcNow() - since >= autoDisableAfterDuration));

        if (autoDisable)
        {
            // Separate statement rather than a CASE on the update above so the disable condition
            // is expressed once, in C#, over the values the increment actually produced. It is
            // idempotent, so two concurrent failures crossing the threshold together are harmless.
            // xtenant: id is already org-scoped by the FK; explicit org_id filter is defense-in-depth
            await conn.ExecuteAsync(
                """
                UPDATE webhook_subscription
                SET enabled = 0, updated_at = @now
                WHERE org_id = @orgId AND id = @id
                """,
                new { orgId, id, now });
        }

        return autoDisable;
    }

    // Raw Dapper projection for the API-facing read path (no secret column).
    // Integer columns bind as long, and [ExplicitConstructor] is what lets one signature serve
    // both providers — SQLite reports INTEGER as Int64, Postgres as Int32, and Dapper's default
    // positional-record binding demands an exact CLR match. See
    // DapperPositionalRecordComplianceTests. Converted to bool/int in MapRow.
    // HasSecret is derived in C# from the raw secret column rather than a SQL CASE:
    // Microsoft.Data.Sqlite reports computed/expression columns as byte[] (no declared
    // type affinity), which fails RawRow materialization on the buffered QueryAsync path.
    [method: ExplicitConstructor]
    private sealed record RawRow(
        string Id, string OrgId, string Url, string EventTypesJson, long Enabled,
        string? SecretStored, string? Description, string? LastDeliveryAt, string? LastStatus,
        long ConsecutiveFailures, string? FailingSince, string? LastError,
        string CreatedAt, string UpdatedAt);

    // Raw Dapper projection for the delivery fan-out path (includes encrypted secret).
    [method: ExplicitConstructor]
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
