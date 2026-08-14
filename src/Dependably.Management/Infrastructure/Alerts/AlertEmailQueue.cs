using System.Globalization;
using Dependably.Infrastructure.Mail;
using Microsoft.Extensions.Localization;

namespace Dependably.Infrastructure.Alerts;

/// <summary>
/// Per-org email delivery for freshly-raised alerts, over the durable outbox.
/// <see cref="NotifyAsync"/> resolves the org's channel, renders the message, and persists it to
/// <c>email_outbox</c> before returning — so the mail exists on disk from the moment the alert is
/// raised, and an SMTP outage longer than one process lifetime no longer loses it.
/// <see cref="EmailOutboxDeliveryService"/> owns every attempt, the backoff, and the terminal
/// bookkeeping from there.
///
/// <para>
/// The split of responsibilities is deliberate, and it is why this class reads the org's channel
/// directly rather than through <see cref="EffectiveEmailConfigResolver"/>. The <b>channel</b> — is
/// this org's alert email on, and to whom — is resolved here, at raise time, and snapshotted onto
/// the row: it is the tenant's intent at the moment the alert fired, and an org that had email off
/// then did not want this message. The <b>transport</b> is resolved by the delivery worker, fresh on
/// every attempt. Folding the two together (which is what the resolver does, correctly, for the
/// synchronous test-send endpoint) would make an unconfigured relay resolve to "nothing to send" and
/// persist nothing — reinstating the exact silent drop the outbox exists to remove.
/// </para>
///
/// <para>
/// Security-token mail (password-reset links, email-change verification) deliberately does not come
/// through here. It stays on the in-memory <see cref="EmailDeliveryQueue"/> with its fail-silent
/// semantics, because its bodies carry live credentials that an outbox would put at rest in the
/// database, and because a user can re-request one. Alert mail is the opposite: it carries no
/// credential and cannot be re-requested by anyone.
/// </para>
/// </summary>
public sealed class AlertEmailQueue : IAlertNotifier
{
    private readonly EmailOutboxRepository _outbox;
    private readonly EmailOutboxPolicy _policy;
    private readonly EmailOutboxDeliveryService _worker;
    private readonly AlertSettingsRepository _settings;
    private readonly AlertRepository _alerts;
    private readonly IStringLocalizer<SharedResource> _localizer;
    private readonly ILogger<AlertEmailQueue> _logger;

    public AlertEmailQueue(
        EmailOutboxRepository outbox,
        EmailOutboxPolicy policy,
        EmailOutboxDeliveryService worker,
        AlertSettingsRepository settings,
        AlertRepository alerts,
        IStringLocalizer<SharedResource> localizer,
        ILogger<AlertEmailQueue> logger)
    {
        _outbox = outbox;
        _policy = policy;
        _worker = worker;
        _settings = settings;
        _alerts = alerts;
        _localizer = localizer;
        _logger = logger;
    }

    /// <summary>
    /// Persists the alert's email to the outbox, then nudges the delivery worker. A disabled channel
    /// or an empty recipient list resolves to nothing and is a silent no-op — nothing queued, nothing
    /// recorded — exactly as before: there was never anything to send.
    ///
    /// <para>
    /// Before enqueueing a fresh row, this first tries to fold the alert into an already-pending row
    /// sharing its (org, coalesce key) — a burst of the same alert collapsing into one digest rather
    /// than one row per occurrence. A coalesced occurrence is not silently dropped: it is recorded as
    /// its own <c>"coalesced"</c> outcome on its own alert row (the digest row's own delivery outcome
    /// lands on whichever alert opened it), and the digest's <c>occurrence_count</c> is exactly the
    /// number of alerts folded into it. Coalescing only ever targets a <c>pending</c> row, never one
    /// already claimed for delivery — a race with the delivery worker resolves toward not losing the
    /// alert, by falling through to a fresh enqueue.
    /// </para>
    /// </summary>
    public async Task NotifyAsync(AlertRecord alert, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(alert);

        string[]? resolved = await ResolveChannelAsync(alert, ct);
        if (resolved is null)
        {
            return;
        }

        string coalesceKey = EmailOutboxCoalescing.ForAlert(alert.Type, alert.Purl, alert.SourceRef);

        if (await TryCoalesceAsync(alert, coalesceKey, ct))
        {
            _worker.Wake();
            return;
        }

        (string subject, string body) = BuildMessage(_localizer, alert);

        bool queued = await _outbox.TryEnqueueAsync(
            new NewEmailOutboxMessage(
                OrgId: alert.OrgId,
                MessageKind: EmailOutboxMessageKinds.Alert,
                CoalesceKey: coalesceKey,
                CorrelationId: alert.Id,
                Recipients: resolved,
                Subject: subject,
                Body: body),
            _policy,
            ct);

        if (!queued)
        {
            await RecordShedAsync(alert, ct);
            return;
        }

        _worker.Wake();
    }

    /// <summary>
    /// Attempts to fold <paramref name="alert"/> into an existing pending outbox row sharing its
    /// (org, coalesce key). Returns true when the fold succeeded, in which case the caller has
    /// nothing left to enqueue — the burst is already represented by the surviving row's
    /// <c>occurrence_count</c>.
    /// </summary>
    private async Task<bool> TryCoalesceAsync(AlertRecord alert, string coalesceKey, CancellationToken ct)
    {
        var target = await _outbox.FindCoalesceTargetAsync(alert.OrgId, coalesceKey, ct);
        if (target is null)
        {
            return false;
        }

        int occurrenceCount = (int)target.OccurrenceCount + 1;
        (string subject, string body) = BuildDigestMessage(_localizer, alert, occurrenceCount);

        bool coalesced = await _outbox.TryCoalesceAsync(target.Id, occurrenceCount, subject, body, ct);
        if (!coalesced)
        {
            // The delivery worker claimed the target row in the window between the read above and
            // this write — the burst window closed. Let the caller enqueue a fresh row rather than
            // lose the occurrence.
            return false;
        }

        await RecordCoalescedAsync(alert, occurrenceCount, ct);
        return true;
    }

    /// <summary>
    /// Records that this alert's own email was folded into a pending digest rather than sent on its
    /// own — so the alert list never shows a coalesced occurrence as silently un-mailed. The digest
    /// row's own terminal outcome (delivered / dead-lettered / expired) lands on whichever alert
    /// opened it, via that row's <c>correlation_id</c>.
    /// </summary>
    private async Task RecordCoalescedAsync(AlertRecord alert, int occurrenceCount, CancellationToken ct)
    {
        try
        {
            await _alerts.RecordEmailOutcomeAsync(
                alert.OrgId, alert.Id, "coalesced",
                $"Folded into a pending digest ({occurrenceCount} occurrence(s)); the digest's own "
                + "delivery outcome lands on the alert that opened it.",
                ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "{ExceptionType} recording the coalesced outcome of alert {AlertId} (org {OrgId}); "
                + "the digest row is correct but this alert's own status was not updated.",
                ex.GetType().Name, alert.Id, alert.OrgId);
        }
    }

    /// <summary>
    /// The org's alert-email channel: enabled, with at least one recipient. Deliberately reads only
    /// the tenant's own columns — the state of the operator's relay is not part of this decision.
    /// </summary>
    private async Task<string[]?> ResolveChannelAsync(AlertRecord alert, CancellationToken ct)
    {
        try
        {
            var delivery = await _settings.GetDecryptedEmailDeliveryConfigAsync(alert.OrgId, ct);
            return delivery?.Recipients;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "{ExceptionType} loading email settings for org {OrgId}; skipping delivery for alert {AlertId}.",
                ex.GetType().Name, alert.OrgId, alert.Id);
            return null;
        }
    }

    /// <summary>
    /// Records a message shed because the outbox was at its depth cap. The refusal is written where
    /// an operator and the tenant will actually see it — the alert row's <c>email_status</c> and the
    /// org's delivery-health columns — rather than only in a log line, because a silently discarded
    /// alert is the failure mode the outbox exists to remove. The channel itself is left enabled:
    /// a full shared queue is an operator condition, not the tenant's configuration being wrong.
    /// </summary>
    private async Task RecordShedAsync(AlertRecord alert, CancellationToken ct)
    {
        const string reason = "Email outbox is at its depth cap; the message was refused, not queued.";

        _logger.LogWarning(
            "Email outbox at its {MaxDepth}-message cap; refused alert {AlertId} (org {OrgId}) without queueing it.",
            _policy.MaxDepth, alert.Id, alert.OrgId);

        try
        {
            await _alerts.RecordEmailOutcomeAsync(alert.OrgId, alert.Id, "failed", reason, ct);
            await _settings.RecordEmailFailureAsync(alert.OrgId, reason, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex,
                "{ExceptionType} recording the outbox-full refusal of alert {AlertId} (org {OrgId}); "
                + "the message was dropped and the drop was not durably recorded.",
                ex.GetType().Name, alert.Id, alert.OrgId);
        }
    }

    /// <summary>Renders the single-occurrence alert subject/body from the resx <c>email.alert.*</c>
    /// keys — see <see cref="WithPinnedCulture"/> for the culture handling and <see cref="StripCrLf"/>
    /// for why the title is sanitised before formatting.</summary>
    internal static (string Subject, string Body) BuildMessage(
        IStringLocalizer<SharedResource> localizer, AlertRecord alert) =>
        WithPinnedCulture(() =>
        {
            string safeTitle = StripCrLf(alert.Title);
            string subject = StripCrLf(localizer["email.alert.subject", safeTitle]);
            string body = localizer["email.alert.body", safeTitle, alert.Detail ?? string.Empty];
            return (subject, body);
        });

    /// <summary>
    /// Renders the digest form of the same alert kind/coordinate — <paramref name="occurrenceCount"/>
    /// raw alerts folded into this one email. The digest states the count explicitly and carries the
    /// most recent occurrence's detail, so a burst never arrives as N indistinguishable copies but
    /// also never arrives looking like exactly one thing happened.
    /// </summary>
    internal static (string Subject, string Body) BuildDigestMessage(
        IStringLocalizer<SharedResource> localizer, AlertRecord alert, int occurrenceCount) =>
        WithPinnedCulture(() =>
        {
            string safeTitle = StripCrLf(alert.Title);
            string subject = StripCrLf(localizer["email.alert.digest.subject", safeTitle, occurrenceCount]);
            string body = localizer[
                "email.alert.digest.body", safeTitle, occurrenceCount, alert.Detail ?? string.Empty];
            return (subject, body);
        });

    /// <summary>
    /// Alert email is English-only (there is no per-org language on <see cref="AlertRecord"/> to key
    /// a culture off), so <see cref="CultureInfo.CurrentUICulture"/> is pinned to English for the
    /// duration of <paramref name="render"/> regardless of what a request thread left it at, then
    /// restored — regardless of whether <paramref name="render"/> throws.
    /// </summary>
    private static (string Subject, string Body) WithPinnedCulture(
        Func<(string Subject, string Body)> render)
    {
        var original = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentUICulture = new CultureInfo(LanguageCodes.Default);
            return render();
        }
        finally
        {
            CultureInfo.CurrentUICulture = original;
        }
    }

    // The title is CR/LF-stripped defensively before formatting — SmtpMailSender strips the final
    // joined subject too, but stripping the raw title here keeps the placeholder substitutions from
    // ever reintroducing a header-injection vector.
    private static string StripCrLf(string value) => value.Replace("\r", "").Replace("\n", "");
}
