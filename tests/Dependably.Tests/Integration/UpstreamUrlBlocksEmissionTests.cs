using System.Data.Common;
using System.Diagnostics.Metrics;
using System.Net;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Data.Sqlite;

namespace Dependably.Tests.Integration;

/// <summary>
/// Proves that each seam emits a correctly-attributed
/// <c>dependably.security.upstream_url_blocks</c> measurement, and that the
/// redirect-block path emits exactly one measurement (double-count fix).
/// </summary>
// Attaches a MeterListener filtered only by DependablyMeter.MeterName + instrument name and
// asserts exact counts — must run alone against the process-wide static meter.
// See MeterSensitiveCollection.
[Trait("Category", "Integration")]
[Collection("MeterSensitive")]
public sealed class UpstreamUrlBlocksEmissionTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── blocked_range ─────────────────────────────────────────────────────────

    /// <summary>
    /// Calling <see cref="UpstreamUrlValidatorExtensions.IsAllowedAsync"/> on an IP in a
    /// blocked range (127.0.0.1 is loopback → SsrfGuard blocks it) emits one measurement
    /// with <c>reason=blocked_range</c>.
    /// </summary>
    [Fact]
    public async Task IsAllowedAsync_BlockedIpRange_EmitsBlockedRangeReason()
    {
        var validator = new UpstreamUrlValidator(new AuditRepository(_db), TestEdgeMode.Disabled());
        long count = 0;
        string? capturedReason = null;

        using var listener = UrlBlocksListener((measurement, tags) =>
        {
            count += measurement;
            capturedReason = TagValue(tags, "reason");
        });

        bool allowed = await validator.IsAllowedAsync("http://127.0.0.1/sensitive", orgId: null);

        Assert.False(allowed);
        Assert.Equal(1, count);
        Assert.Equal("blocked_range", capturedReason);
    }

    // ── dns_failure ───────────────────────────────────────────────────────────

    /// <summary>
    /// An unresolvable hostname causes DNS resolution to fail. The validator returns
    /// <see cref="UpstreamUrlBlock.DnsFailure"/> and the extension emits one measurement
    /// with <c>reason=dns_failure</c>. Fail-closed.
    /// </summary>
    [Fact]
    public async Task IsAllowedAsync_DnsFailure_EmitsDnsFailureReason()
    {
        var validator = new UpstreamUrlValidator(new AuditRepository(_db), TestEdgeMode.Disabled());
        long count = 0;
        string? capturedReason = null;

        using var listener = UrlBlocksListener((measurement, tags) =>
        {
            count += measurement;
            capturedReason = TagValue(tags, "reason");
        });

        // nonexistent.invalid. is guaranteed unresolvable (IANA reserved)
        bool allowed = await validator.IsAllowedAsync("http://nonexistent.invalid./", orgId: null);

        Assert.False(allowed);
        Assert.Equal(1, count);
        Assert.Equal("dns_failure", capturedReason);
    }

    // ── redirect_to_internal (double-count fix) ───────────────────────────────

    /// <summary>
    /// When <see cref="SsrfAwareRedirectHandler"/> follows a redirect whose target is blocked,
    /// exactly ONE <c>upstream_url_blocks</c> measurement is emitted with
    /// <c>reason=redirect_to_internal</c>. Verifies the double-count fix: the old code emitted
    /// once inside <c>UpstreamUrlValidator.IsAllowedAsync</c> and once in the handler itself.
    /// </summary>
    [Fact]
    public async Task SsrfAwareRedirectHandler_RedirectToBlockedUrl_EmitsExactlyOneRedirectToInternalMeasurement()
    {
        // A real UpstreamUrlValidator that blocks 169.254.0.0/16 (link-local).
        var validator = new UpstreamUrlValidator(new AuditRepository(_db), TestEdgeMode.Disabled());
        var inner = new QueuedInnerHandler();
        inner.Enqueue(new HttpResponseMessage(HttpStatusCode.Found)
        {
            Headers = { Location = new Uri("http://169.254.169.254/latest/meta-data/") }
        });

        var handler = new SsrfAwareRedirectHandler(validator) { InnerHandler = inner };
        using var client = new HttpClient(handler);

        long count = 0;
        string? capturedReason = null;

        using var listener = UrlBlocksListener((measurement, tags) =>
        {
            count += measurement;
            capturedReason = TagValue(tags, "reason");
        });

        await Assert.ThrowsAsync<SsrfBlockedException>(
            () => client.GetAsync("https://upstream.example.com/pkg"));

        // Exactly one increment — redirect_to_internal, not blocked_range (the DNS check on
        // 169.254.169.254 resolves to itself and SsrfGuard blocks it, but the metric is
        // emitted by the handler with the redirect_to_internal reason, not by the extension).
        Assert.Equal(1, count);
        Assert.Equal("redirect_to_internal", capturedReason);
    }

    // ── dns_rebind ────────────────────────────────────────────────────────────

    /// <summary>
    /// When a send function throws <see cref="HttpRequestException"/> wrapping
    /// <see cref="SsrfBlockedException"/> (the connect-time SSRF gate),
    /// <see cref="UpstreamClient.UnwrapSsrfAsync"/> emits one measurement with
    /// <c>reason=dns_rebind</c>.
    /// </summary>
    [Fact]
    public async Task UnwrapSsrfAsync_ConnectTimeBlock_EmitsDnsRebindReason()
    {
        long count = 0;
        string? capturedReason = null;

        using var listener = UrlBlocksListener((measurement, tags) =>
        {
            count += measurement;
            capturedReason = TagValue(tags, "reason");
        });

        var ssrf = new SsrfBlockedException("http://10.0.0.1/data");
        var wrapped = new HttpRequestException("SSRF blocked at connect time", ssrf);

        await Assert.ThrowsAsync<SsrfBlockedException>(
            () => UpstreamClient.UnwrapSsrfAsync<string>(() => throw wrapped));

        Assert.Equal(1, count);
        Assert.Equal("dns_rebind", capturedReason);
    }

    // ── AllowlistBlocks{ecosystem} ────────────────────────────────────────────

    /// <summary>
    /// <see cref="AllowlistService.IsAllowedAsync"/> with an unlisted npm PURL emits one
    /// <c>dependably.security.allowlist_blocks</c> measurement with <c>ecosystem=npm</c>.
    /// The emit site is unchanged — this is an acceptance-criteria test only.
    /// </summary>
    [Fact]
    public async Task AllowlistService_UnlistedPurl_EmitsAllowlistBlocksWithEcosystem()
    {
        string orgId = await OrgSeeder.InsertAsync(_db, $"o-{Guid.NewGuid():N}");
        var svc = new AllowlistService(_db, new AuditRepository(_db));

        long count = 0;
        string? capturedEcosystem = null;

        using var listener = AllowlistBlocksListener((measurement, tags) =>
        {
            count += measurement;
            capturedEcosystem = TagValue(tags, "ecosystem");
        });

        bool allowed = await svc.IsAllowedAsync(orgId, "pkg:npm/evil-pkg@1.0.0");

        Assert.False(allowed);
        Assert.True(count >= 1);
        Assert.Equal("npm", capturedEcosystem);
    }

    // ── mixed partial-failure: blocked + allowed + blocked in sequence ─────────

    /// <summary>
    /// Three sequential calls to <see cref="UpstreamUrlValidatorExtensions.IsAllowedAsync"/>:
    /// loopback (blocked_range) → public host (none) → unresolvable (dns_failure).
    /// Verifies that the listener accumulates only the two blocked increments and that
    /// each reason is independent — the allowed call does not emit.
    /// </summary>
    [Fact]
    public async Task IsAllowedAsync_MixedBatch_EmitsOnlyForBlockedCalls()
    {
        var validator = new UpstreamUrlValidator(new AuditRepository(_db), TestEdgeMode.Disabled());
        var reasons = new List<string?>();

        using var listener = UrlBlocksListener((_, tags) =>
            reasons.Add(TagValue(tags, "reason")));

        // 1. Blocked — loopback IP (literal, no DNS)
        bool r1 = await validator.IsAllowedAsync("http://127.0.0.1/", orgId: null);
        // 2. Allowed — literal public IP (8.8.8.8 is public; Dns.GetHostAddressesAsync parses
        //    it directly without a network query, so this is deterministic in air-gapped CI)
        bool r2 = await validator.IsAllowedAsync("http://8.8.8.8/", orgId: null);
        // 3. Blocked — IANA-reserved NXDOMAIN, unresolvable
        bool r3 = await validator.IsAllowedAsync("http://nonexistent.invalid./", orgId: null);

        Assert.False(r1);
        Assert.True(r2);
        Assert.False(r3);

        // Exactly two measurements — one per blocked call; the allowed call emits nothing.
        Assert.Equal(2, reasons.Count);
        Assert.Contains("blocked_range", reasons);
        Assert.Contains("dns_failure", reasons);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static MeterListener UrlBlocksListener(
        Action<long, ReadOnlySpan<KeyValuePair<string, object?>>> onMeasurement)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == DependablyMeter.MeterName &&
                    instrument.Name == "dependably.security.upstream_url_blocks")
                {
                    l.EnableMeasurementEvents(instrument);
                }
            }
        };
        listener.SetMeasurementEventCallback<long>(
            (_, measurement, tags, _) => onMeasurement(measurement, tags));
        listener.Start();
        return listener;
    }

    private static MeterListener AllowlistBlocksListener(
        Action<long, ReadOnlySpan<KeyValuePair<string, object?>>> onMeasurement)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == DependablyMeter.MeterName &&
                    instrument.Name == "dependably.security.allowlist_blocks")
                {
                    l.EnableMeasurementEvents(instrument);
                }
            }
        };
        listener.SetMeasurementEventCallback<long>(
            (_, measurement, tags, _) => onMeasurement(measurement, tags));
        listener.Start();
        return listener;
    }

    private static string? TagValue(ReadOnlySpan<KeyValuePair<string, object?>> tags, string attributeName)
    {
        foreach (var kv in tags)
        {
            if (string.Equals(kv.Key, attributeName, StringComparison.Ordinal))
            {
                return kv.Value?.ToString();
            }
        }
        return null;
    }

    /// <summary>
    /// Minimal HttpMessageHandler backed by a queue. Returns 200 OK when the queue is empty.
    /// </summary>
    private sealed class QueuedInnerHandler : HttpMessageHandler
    {
        private readonly Queue<HttpResponseMessage> _responses = new();

        public void Enqueue(HttpResponseMessage response) => _responses.Enqueue(response);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(
                _responses.Count > 0
                    ? _responses.Dequeue()
                    : new HttpResponseMessage(HttpStatusCode.OK));
    }

    /// <summary>
    /// Minimal in-memory metadata store with only the audit_log table.
    /// Prevents real DNS/disk I/O in tests that only need audit logging.
    /// </summary>
    private sealed class AuditOnlyMetadataStore : IMetadataStore
    {
        private readonly string _cs;
        private readonly SqliteConnection _anchor;

        public AuditOnlyMetadataStore()
        {
            string name = $"audit_only_{Guid.NewGuid():N}";
            _cs = $"Data Source={name};Mode=Memory;Cache=Shared";
            _anchor = new SqliteConnection(_cs);
            _anchor.Open();
            using var cmd = _anchor.CreateCommand();
            cmd.CommandText = """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id TEXT PRIMARY KEY,
                    scope TEXT NOT NULL DEFAULT 'tenant',
                    org_id TEXT, actor_id TEXT, actor_kind TEXT, action TEXT NOT NULL,
                    ecosystem TEXT, purl TEXT, detail TEXT, source_ip TEXT,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
                );
                CREATE TABLE IF NOT EXISTS activity (id TEXT PRIMARY KEY);
                """;
            cmd.ExecuteNonQuery();
        }

        public DbProvider Provider => DbProvider.Sqlite;

        public async Task<DbConnection> OpenAsync(CancellationToken ct = default)
        {
            var conn = new SqliteConnection(_cs);
            await conn.OpenAsync(ct);
            return conn;
        }

        public async ValueTask DisposeAsync() => await _anchor.DisposeAsync();
    }
}
