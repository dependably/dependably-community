using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Mail;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure.Mail;

/// <summary>
/// <see cref="EmailOutboxRepository.FindCoalesceTargetAsync"/> and
/// <see cref="EmailOutboxRepository.TryCoalesceAsync"/> directly against the store — the (org,
/// coalesce_key) match, its NULL-org-safety, and the race with a concurrent claim. The write side
/// that decides WHEN to coalesce and renders the digest text is
/// <c>AlertEmailQueueTests.NotifyAsync_BurstOfIdenticalAlerts_*</c>; these tests pin the store-level
/// contract that write side depends on.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EmailOutboxCoalescingTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org1', 'acme')");
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('org2', 'beta')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private EmailOutboxRepository BuildOutbox() => new(_db, _clock);

    private static readonly EmailOutboxPolicy Policy = new(new ConfigurationBuilder().Build());

    private static NewEmailOutboxMessage Message(string? orgId, string coalesceKey) => new(
        OrgId: orgId,
        MessageKind: EmailOutboxMessageKinds.Alert,
        CoalesceKey: coalesceKey,
        CorrelationId: Guid.NewGuid().ToString("N"),
        Recipients: ["ops@example.com"],
        Subject: "original subject",
        Body: "original body");

    private async Task<int> CountRowsAsync()
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM email_outbox");
    }

    // ── The core NULL-safety trap: two operator-scope (org_id = NULL) rows ───

    /// <summary>
    /// Two rows sharing the same coalesce key with NULL org_id must find each other. A naive
    /// <c>org_id = @orgId</c> predicate never matches two NULLs (SQL's three-valued logic), which
    /// would silently defeat coalescing for every operator-scope message — exactly the trap the
    /// <c>IS NOT DISTINCT FROM</c> comparison exists to avoid.
    /// </summary>
    [Fact]
    public async Task FindCoalesceTarget_TwoNullOrgRows_SameKey_FindsTheOther()
    {
        var outbox = BuildOutbox();
        Assert.True(await outbox.TryEnqueueAsync(Message(orgId: null, coalesceKey: "k1"), Policy));

        var target = await outbox.FindCoalesceTargetAsync(orgId: null, coalesceKey: "k1");

        Assert.NotNull(target);
        Assert.Equal(1, target!.OccurrenceCount);
    }

    /// <summary>
    /// Folding a second NULL-org occurrence into the first bumps <c>occurrence_count</c> and leaves
    /// exactly one row — the digest, not two independent operator-scope messages.
    /// </summary>
    [Fact]
    public async Task TryCoalesce_TwoNullOrgOccurrences_CollapseToOneRowWithOccurrenceCountTwo()
    {
        var outbox = BuildOutbox();
        await outbox.TryEnqueueAsync(Message(orgId: null, coalesceKey: "k1"), Policy);

        var target = await outbox.FindCoalesceTargetAsync(orgId: null, coalesceKey: "k1");
        bool coalesced = await outbox.TryCoalesceAsync(
            target!.Id, occurrenceCount: 2, subject: "digest subject", body: "digest body");

        Assert.True(coalesced);
        Assert.Equal(1, await CountRowsAsync());

        await using var conn = await _db.OpenAsync();
        (long occurrenceCount, string subject, string body) = await conn.QuerySingleAsync<
            (long OccurrenceCount, string Subject, string Body)>(
            "SELECT occurrence_count AS OccurrenceCount, subject AS Subject, body AS Body "
            + "FROM email_outbox WHERE id = @id",
            new { id = target.Id });

        Assert.Equal(2, occurrenceCount);
        Assert.Equal("digest subject", subject);
        Assert.Equal("digest body", body);
    }

    // ── The must-NOT twin: NULL org never coalesces with a real org ─────────

    /// <summary>
    /// A NULL-org row and an org-scoped row sharing the same coalesce key text must stay two
    /// distinct rows. This is the must-NOT twin of the NULL-safety test above: proving two NULLs
    /// match each other is not enough — NULL must also never match a real value.
    /// </summary>
    [Fact]
    public async Task FindCoalesceTarget_NullOrgAndRealOrg_SameKeyText_NeverMatchEachOther()
    {
        var outbox = BuildOutbox();
        await outbox.TryEnqueueAsync(Message(orgId: null, coalesceKey: "shared-key"), Policy);
        await outbox.TryEnqueueAsync(Message(orgId: "org1", coalesceKey: "shared-key"), Policy);

        Assert.Equal(2, await CountRowsAsync());

        var nullOrgTarget = await outbox.FindCoalesceTargetAsync(orgId: null, coalesceKey: "shared-key");
        var org1Target = await outbox.FindCoalesceTargetAsync(orgId: "org1", coalesceKey: "shared-key");

        Assert.NotNull(nullOrgTarget);
        Assert.NotNull(org1Target);
        Assert.NotEqual(nullOrgTarget!.Id, org1Target!.Id);
    }

    /// <summary>Two different real orgs sharing the same coalesce key text never coalesce either —
    /// the key is always grouped with org_id, per org.</summary>
    [Fact]
    public async Task FindCoalesceTarget_TwoDifferentOrgs_SameKeyText_NeverMatchEachOther()
    {
        var outbox = BuildOutbox();
        await outbox.TryEnqueueAsync(Message(orgId: "org1", coalesceKey: "shared-key"), Policy);
        await outbox.TryEnqueueAsync(Message(orgId: "org2", coalesceKey: "shared-key"), Policy);

        var org1Target = await outbox.FindCoalesceTargetAsync(orgId: "org1", coalesceKey: "shared-key");
        var org2Target = await outbox.FindCoalesceTargetAsync(orgId: "org2", coalesceKey: "shared-key");

        Assert.NotNull(org1Target);
        Assert.NotNull(org2Target);
        Assert.NotEqual(org1Target!.Id, org2Target!.Id);
        Assert.Equal(2, await CountRowsAsync());
    }

    // ── Coalescing only ever targets a still-pending row ─────────────────────

    /// <summary>
    /// A row already claimed for delivery (<c>sending</c>) is not a valid coalesce target: it might
    /// be mid-SMTP-conversation. <see cref="EmailOutboxRepository.TryCoalesceAsync"/> guards on
    /// <c>state = 'pending'</c> and reports the loss so the caller can fall back to a fresh enqueue
    /// rather than losing the occurrence.
    /// </summary>
    [Fact]
    public async Task TryCoalesce_RowNoLongerPending_ReturnsFalse_AndChangesNothing()
    {
        var outbox = BuildOutbox();
        await outbox.TryEnqueueAsync(Message(orgId: "org1", coalesceKey: "k2"), Policy);
        var target = await outbox.FindCoalesceTargetAsync(orgId: "org1", coalesceKey: "k2");

        // Simulate the delivery worker claiming the row in the window between the read above and
        // the coalescing write below.
        var claimed = await outbox.ClaimDueAsync(batchSize: 10);
        Assert.Single(claimed);

        bool coalesced = await outbox.TryCoalesceAsync(
            target!.Id, occurrenceCount: 2, subject: "digest subject", body: "digest body");

        Assert.False(coalesced);

        await using var conn = await _db.OpenAsync();
        string? subject = await conn.ExecuteScalarAsync<string?>(
            "SELECT subject FROM email_outbox WHERE id = @id", new { id = target.Id });
        Assert.Equal("original subject", subject); // untouched by the failed coalesce
    }
}
