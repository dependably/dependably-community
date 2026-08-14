using System.Data.Common;
using Dapper;
using Dependably.Storage;

namespace Dependably.Infrastructure.Mail;

/// <summary>The <c>email_outbox.state</c> vocabulary. Only the first two are non-terminal.</summary>
public static class EmailOutboxStates
{
    /// <summary>Persisted, waiting for its next attempt window. Non-terminal.</summary>
    public const string Pending = "pending";

    /// <summary>Claimed by a delivery worker under a lease. Non-terminal.</summary>
    public const string Sending = "sending";

    /// <summary>Handed to the relay successfully. Terminal.</summary>
    public const string Delivered = "delivered";

    /// <summary>Permanently undeliverable as sent — the message or the configuration is wrong. Terminal.</summary>
    public const string DeadLetter = "dead_letter";

    /// <summary>Ran out of attempts, retry duration, or retention. Terminal.</summary>
    public const string Expired = "expired";
}

/// <summary>A message being handed to the outbox for durable delivery.</summary>
/// <param name="OrgId">Owning tenant, or null for operator-scope mail.</param>
/// <param name="MessageKind">Selects the terminal bookkeeping — see <c>email_outbox.message_kind</c>.</param>
/// <param name="CoalesceKey">
/// Burst-dedup key (alert kind plus package coordinate). Recorded from the first release even
/// though nothing groups on it yet, so adding coalescing later is not a migration of every row.
/// </param>
/// <param name="CorrelationId">The domain row this message reports on — <c>alert.id</c> for alert mail.</param>
public sealed record NewEmailOutboxMessage(
    string? OrgId,
    string MessageKind,
    string CoalesceKey,
    string? CorrelationId,
    IReadOnlyList<string> Recipients,
    string Subject,
    string Body);

/// <summary>
/// A claimed outbox row, ready for one delivery attempt. Timestamps stay in their canonical
/// ISO-8601 UTC string form: they are only ever compared, and comparing the stored text ordinally
/// is exactly what the database does, so there is no parse/format round trip to get wrong.
/// </summary>
public sealed record ClaimedEmailOutboxMessage(
    string Id,
    string? OrgId,
    string MessageKind,
    string? CorrelationId,
    IReadOnlyList<string> Recipients,
    string Subject,
    string Body,
    int Attempts,
    string RetryDeadlineAt,
    string ExpiresAt);

/// <summary>Backlog shape the delivery worker logs when it crosses the warn threshold.</summary>
public sealed record EmailOutboxBacklog(int Depth, string? OldestCreatedAt, int DeadLettered, int Expired);

/// <summary>
/// A pending row eligible to absorb a fresh occurrence via burst coalescing — the same (org,
/// coalesce_key) pair, not yet claimed for delivery. <c>OccurrenceCount</c> is <c>long</c>, not
/// <c>int</c>, and the constructor is explicit: SQLite materialises INTEGER as Int64 while
/// Postgres materialises it as Int32, and Dapper's default positional-record constructor match
/// is exact. See <c>DapperPositionalRecordComplianceTests</c>.
/// </summary>
[method: ExplicitConstructor]
public sealed record EmailOutboxCoalesceTarget(string Id, long OccurrenceCount);

/// <summary>
/// Dapper-backed store for <c>email_outbox</c> — the durable queue behind alert email. Every
/// statement here is parameterized, and every one but the insert is deliberately cross-tenant: the
/// drain, the ceiling sweep, and the backlog gauge are one worker draining one shared SMTP
/// transport, not a tenant reading its own rows.
///
/// <para>
/// Claiming is a two-step guarded update rather than a single <c>UPDATE … RETURNING</c> so it works
/// identically on SQLite and Postgres: candidate ids are read, then each is claimed with the
/// pending-or-lapsed-lease predicate re-asserted in the <c>UPDATE</c> itself. A row another replica
/// claimed in between updates zero rows and is skipped, so two workers never attempt the same
/// message concurrently.
/// </para>
/// </summary>
public sealed class EmailOutboxRepository
{
    private readonly IMetadataStore _db;
    private readonly TimeProvider _time;

    public EmailOutboxRepository(IMetadataStore db, TimeProvider time)
    {
        _db = db;
        _time = time;
    }

    /// <summary>
    /// Persists <paramref name="message"/> as <c>pending</c>, due immediately, and returns true.
    /// Returns false when the non-terminal backlog is already at <paramref name="maxDepth"/> — the
    /// shed policy is refuse-the-newest, and the caller is responsible for recording the refusal
    /// where an operator will see it (see <see cref="EmailOutboxPolicy.MaxDepth"/>).
    ///
    /// <para>
    /// The depth check is a soft cap: two concurrent enqueues can both observe depth just under the
    /// bound and both insert. Holding a lock or a serializable transaction to make it exact would
    /// put the alert-raising path behind the outbox writer's contention for a bound whose purpose is
    /// bounding memory and disk, not exactness — overshooting it by the number of concurrent raisers
    /// changes nothing an operator would act on.
    /// </para>
    /// </summary>
    public async Task<bool> TryEnqueueAsync(
        NewEmailOutboxMessage message,
        EmailOutboxPolicy policy,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(policy);

        var now = _time.GetUtcNow();
        await using var conn = await _db.OpenAsync(ct);

        if (await CountNonTerminalAsync(conn, ct) >= policy.MaxDepth)
        {
            return false;
        }

        await conn.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO email_outbox
                (id, org_id, message_kind, coalesce_key, correlation_id, recipients, subject, body,
                 state, attempts, next_attempt_at, retry_deadline_at, expires_at, created_at)
            VALUES
                (@id, @orgId, @messageKind, @coalesceKey, @correlationId, @recipients, @subject, @body,
                 @state, 0, @now, @retryDeadlineAt, @expiresAt, @now)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId = message.OrgId,
                messageKind = message.MessageKind,
                coalesceKey = message.CoalesceKey,
                correlationId = message.CorrelationId,
                recipients = string.Join(",", message.Recipients),
                subject = message.Subject,
                body = message.Body,
                state = EmailOutboxStates.Pending,
                now = now.ToUtcIso(),
                retryDeadlineAt = now.Add(policy.MaxRetryDuration).ToUtcIso(),
                expiresAt = now.Add(policy.MaxRetention).ToUtcIso(),
            },
            cancellationToken: ct));

        return true;
    }

    /// <summary>
    /// Retires every non-terminal row that has passed a ceiling — its retry deadline
    /// (<see cref="EmailOutboxPolicy.MaxRetryDuration"/>) or its retention deadline
    /// (<see cref="EmailOutboxPolicy.MaxRetention"/>) — to <c>expired</c>, and returns how many.
    /// Runs before each claim so a row whose next attempt falls beyond a ceiling is never attempted,
    /// and so a row nothing ever tried (the relay was never configured) still retires.
    /// </summary>
    public async Task<int> ExpireOverdueAsync(CancellationToken ct = default)
    {
        string now = _time.GetUtcNow().ToUtcIso();
        await using var conn = await _db.OpenAsync(ct);

        // xtenant: one worker retires every tenant's overdue rows in one age sweep over the shared
        // outbox; the ceilings are instance policy, not per-tenant configuration.
        return await conn.ExecuteAsync(new CommandDefinition(
            """
            UPDATE email_outbox
            SET state = @expired, completed_at = @now,
                last_error = COALESCE(last_error, @reason)
            WHERE state IN (@pending, @sending)
              AND (retry_deadline_at <= @now OR expires_at <= @now)
            """,
            new
            {
                expired = EmailOutboxStates.Expired,
                pending = EmailOutboxStates.Pending,
                sending = EmailOutboxStates.Sending,
                now,
                reason = "Retry or retention ceiling reached before delivery succeeded.",
            },
            cancellationToken: ct));
    }

    /// <summary>
    /// Claims up to <paramref name="batchSize"/> due rows for delivery, moving each to
    /// <c>sending</c> under a <see cref="EmailOutboxPolicy.LeaseDuration"/> lease and consuming one
    /// attempt. A row is due when it is <c>pending</c> with its backoff elapsed, or <c>sending</c>
    /// with a lapsed lease — the second case is how a message survives the replica that was mid-
    /// attempt when the process died.
    /// </summary>
    public async Task<IReadOnlyList<ClaimedEmailOutboxMessage>> ClaimDueAsync(
        int batchSize, CancellationToken ct = default)
    {
        var now = _time.GetUtcNow();
        string nowIso = now.ToUtcIso();
        string leaseIso = now.Add(EmailOutboxPolicy.LeaseDuration).ToUtcIso();

        await using var conn = await _db.OpenAsync(ct);

        // xtenant: the drain is instance-wide by design — one shared SMTP transport carries every
        // tenant's alert mail, so the worker orders the whole backlog by due time, not by tenant.
        var candidates = (await conn.QueryAsync<RawRow>(new CommandDefinition(
            """
            SELECT id AS Id, org_id AS OrgId, message_kind AS MessageKind,
                   correlation_id AS CorrelationId, recipients AS Recipients,
                   subject AS Subject, body AS Body, attempts AS Attempts,
                   retry_deadline_at AS RetryDeadlineAt, expires_at AS ExpiresAt
            FROM email_outbox
            WHERE (state = @pending AND next_attempt_at <= @now)
               OR (state = @sending AND (lease_expires_at IS NULL OR lease_expires_at <= @now))
            ORDER BY next_attempt_at, created_at
            LIMIT @batchSize
            """,
            new
            {
                pending = EmailOutboxStates.Pending,
                sending = EmailOutboxStates.Sending,
                now = nowIso,
                batchSize,
            },
            cancellationToken: ct))).ToList();

        var claimed = new List<ClaimedEmailOutboxMessage>(candidates.Count);
        foreach (var row in candidates)
        {
            // xtenant: keyed by the outbox row's own primary key, which already carries whatever
            // tenant the row belongs to (or none, for operator-scope mail).
            int affected = await conn.ExecuteAsync(new CommandDefinition(
                """
                UPDATE email_outbox
                SET state = @sending, attempts = attempts + 1, lease_expires_at = @lease
                WHERE id = @id
                  AND (state = @pending
                       OR (state = @sending AND (lease_expires_at IS NULL OR lease_expires_at <= @now)))
                """,
                new
                {
                    sending = EmailOutboxStates.Sending,
                    pending = EmailOutboxStates.Pending,
                    lease = leaseIso,
                    now = nowIso,
                    id = row.Id,
                },
                cancellationToken: ct));

            if (affected == 1)
            {
                claimed.Add(new ClaimedEmailOutboxMessage(
                    row.Id,
                    row.OrgId,
                    row.MessageKind,
                    row.CorrelationId,
                    EmailRecipients.Split(row.Recipients),
                    row.Subject,
                    row.Body,
                    (int)row.Attempts + 1,
                    row.RetryDeadlineAt,
                    row.ExpiresAt));
            }
        }

        return claimed;
    }

    /// <summary>Terminal: the relay accepted the message.</summary>
    public Task MarkDeliveredAsync(string id, CancellationToken ct = default) =>
        SetTerminalAsync(id, EmailOutboxStates.Delivered, failureClass: null, error: null, ct);

    /// <summary>
    /// Terminal: permanently undeliverable as sent. Kept in the table for inspection — nothing in
    /// the delivery path deletes a dead letter.
    /// </summary>
    public Task MarkDeadLetterAsync(string id, string failureClass, string error, CancellationToken ct = default) =>
        SetTerminalAsync(id, EmailOutboxStates.DeadLetter, failureClass, error, ct);

    /// <summary>Terminal: the retry ceiling was reached without a permanent verdict.</summary>
    public Task MarkExpiredAsync(string id, string failureClass, string error, CancellationToken ct = default) =>
        SetTerminalAsync(id, EmailOutboxStates.Expired, failureClass, error, ct);

    /// <summary>
    /// Returns the row to <c>pending</c>, due at <paramref name="nextAttemptAt"/>, releasing the
    /// lease. The attempt count is not rewound — it was consumed at claim time, which is what makes
    /// the retry ceiling hold across a crash mid-attempt.
    /// </summary>
    public async Task ScheduleRetryAsync(
        string id, DateTimeOffset nextAttemptAt, string failureClass, string error,
        CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // xtenant: keyed by the outbox row's own primary key.
        await conn.ExecuteAsync(new CommandDefinition(
            """
            UPDATE email_outbox
            SET state = @pending, next_attempt_at = @next, lease_expires_at = NULL,
                failure_class = @failureClass, last_error = @error
            WHERE id = @id
            """,
            new
            {
                pending = EmailOutboxStates.Pending,
                next = nextAttemptAt.ToUtcIso(),
                failureClass,
                error = Truncate(error),
                id,
            },
            cancellationToken: ct));
    }

    /// <summary>Current backlog shape: non-terminal depth, oldest queued row, and terminal counts.</summary>
    public async Task<EmailOutboxBacklog> GetBacklogAsync(CancellationToken ct = default)
    {
        var nonTerminal = new { pending = EmailOutboxStates.Pending, sending = EmailOutboxStates.Sending };
        await using var conn = await _db.OpenAsync(ct);

        // Four plain aggregates rather than one CASE-projecting statement: under SQLite a bare
        // `CASE … THEN <text column> END` projection loses its declared type and comes back as a
        // byte[], which then fails to map onto a string property.
        //
        // xtenant: an instance-wide gauge over one shared transport's queue.
        int depth = await conn.ExecuteScalarAsync<int>(new CommandDefinition(
            "SELECT COUNT(*) FROM email_outbox WHERE state IN (@pending, @sending)",
            nonTerminal, cancellationToken: ct));

        // xtenant: same instance-wide gauge.
        string? oldest = await conn.ExecuteScalarAsync<string?>(new CommandDefinition(
            "SELECT MIN(created_at) FROM email_outbox WHERE state IN (@pending, @sending)",
            nonTerminal, cancellationToken: ct));

        // xtenant: same instance-wide gauge.
        int deadLettered = await conn.ExecuteScalarAsync<int>(new CommandDefinition(
            "SELECT COUNT(*) FROM email_outbox WHERE state = @state",
            new { state = EmailOutboxStates.DeadLetter }, cancellationToken: ct));

        // xtenant: same instance-wide gauge.
        int expired = await conn.ExecuteScalarAsync<int>(new CommandDefinition(
            "SELECT COUNT(*) FROM email_outbox WHERE state = @state",
            new { state = EmailOutboxStates.Expired }, cancellationToken: ct));

        return new EmailOutboxBacklog(depth, oldest, deadLettered, expired);
    }

    /// <summary>
    /// Looks for a <c>pending</c> row already carrying <paramref name="coalesceKey"/> for
    /// <paramref name="orgId"/>, so the caller can fold a fresh occurrence into it instead of
    /// enqueueing a second message for the same burst. <c>org_id</c> is nullable for operator-scope
    /// mail, so the match is written <c>IS NOT DISTINCT FROM</c> rather than <c>=</c> — a plain
    /// equality predicate never matches two NULLs (SQL's three-valued logic), which would silently
    /// fail to coalesce two NULL-org rows into each other and quietly defeat deduplication for
    /// exactly the mail this comparison exists to cover.
    /// </summary>
    public async Task<EmailOutboxCoalesceTarget?> FindCoalesceTargetAsync(
        string? orgId, string coalesceKey, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // xtenant: org_id is part of the match predicate via IS NOT DISTINCT FROM — this is an
        // org-scoped read written NULL-safely, not a cross-tenant one.
        return await conn.QuerySingleOrDefaultAsync<EmailOutboxCoalesceTarget>(new CommandDefinition(
            """
            SELECT id AS Id, occurrence_count AS OccurrenceCount
            FROM email_outbox
            WHERE state = @pending
              AND coalesce_key = @coalesceKey
              AND org_id IS NOT DISTINCT FROM @orgId
            ORDER BY created_at DESC
            LIMIT 1
            """,
            new { pending = EmailOutboxStates.Pending, coalesceKey, orgId },
            cancellationToken: ct));
    }

    /// <summary>
    /// Folds a fresh occurrence into the still-<c>pending</c> row <paramref name="id"/>: bumps
    /// <c>occurrence_count</c> and replaces the subject/body with the digest text the caller already
    /// rendered. Returns false — without changing anything — when the row is no longer <c>pending</c>,
    /// which happens when the delivery worker claimed it in the window between
    /// <see cref="FindCoalesceTargetAsync"/> and this call; the caller's fallback is to enqueue a
    /// fresh row rather than lose the occurrence.
    /// </summary>
    public async Task<bool> TryCoalesceAsync(
        string id, int occurrenceCount, string subject, string body, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // xtenant: keyed by the outbox row's own primary key, which already carries whatever
        // tenant the row belongs to (or none, for operator-scope mail).
        int rows = await conn.ExecuteAsync(new CommandDefinition(
            """
            UPDATE email_outbox
            SET occurrence_count = @occurrenceCount, subject = @subject, body = @body
            WHERE id = @id AND state = @pending
            """,
            new
            {
                id,
                occurrenceCount,
                subject,
                body,
                pending = EmailOutboxStates.Pending,
            },
            cancellationToken: ct));

        return rows == 1;
    }

    /// <summary>
    /// Deletes terminal rows completed before <paramref name="cutoff"/>. The only delete path on
    /// this table; called by the retention sweep, which logs the count so a removal is never silent.
    /// </summary>
    public async Task<int> PruneTerminalAsync(DateTimeOffset cutoff, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);

        // xtenant: instance-wide storage-limitation sweep by age, the same posture as the
        // audit_log and account_send_throttle reapers in RetentionService.
        return await conn.ExecuteAsync(new CommandDefinition(
            """
            DELETE FROM email_outbox
            WHERE state IN (@delivered, @deadLetter, @expired)
              AND completed_at IS NOT NULL AND completed_at < @cutoff
            """,
            new
            {
                delivered = EmailOutboxStates.Delivered,
                deadLetter = EmailOutboxStates.DeadLetter,
                expired = EmailOutboxStates.Expired,
                cutoff = cutoff.ToUtcIso(),
            },
            cancellationToken: ct));
    }

    private async Task SetTerminalAsync(
        string id, string state, string? failureClass, string? error, CancellationToken ct)
    {
        await using var conn = await _db.OpenAsync(ct);

        // xtenant: keyed by the outbox row's own primary key.
        await conn.ExecuteAsync(new CommandDefinition(
            """
            UPDATE email_outbox
            SET state = @state, completed_at = @now, lease_expires_at = NULL,
                failure_class = COALESCE(@failureClass, failure_class),
                last_error = COALESCE(@error, last_error)
            WHERE id = @id
            """,
            new
            {
                state,
                now = _time.GetUtcNow().ToUtcIso(),
                failureClass,
                error = error is null ? null : Truncate(error),
                id,
            },
            cancellationToken: ct));
    }

    private static async Task<int> CountNonTerminalAsync(DbConnection conn, CancellationToken ct) =>
        // xtenant: the depth bound is an instance-wide memory/disk bound over one shared queue,
        // not a per-tenant quota.
        await conn.ExecuteScalarAsync<int>(new CommandDefinition(
            "SELECT COUNT(*) FROM email_outbox WHERE state IN (@pending, @sending)",
            new { pending = EmailOutboxStates.Pending, sending = EmailOutboxStates.Sending },
            cancellationToken: ct));

    // Relay error text is unbounded (a verbose 5xx can carry the whole rejected header set). Bound
    // it so one hostile or chatty upstream cannot grow the row without limit.
    private const int MaxErrorLength = 500;

    private static string Truncate(string error) =>
        error.Length <= MaxErrorLength ? error : error[..MaxErrorLength];

    // Integer columns bind as long, and [ExplicitConstructor] is what lets one signature serve
    // both providers — SQLite reports INTEGER as Int64, Postgres as Int32, and Dapper's default
    // positional-record binding demands an exact CLR match. See
    // DapperPositionalRecordComplianceTests.
    [method: ExplicitConstructor]
    private sealed record RawRow(
        string Id, string? OrgId, string MessageKind, string? CorrelationId, string? Recipients,
        string Subject, string Body, long Attempts, string RetryDeadlineAt, string ExpiresAt);
}
