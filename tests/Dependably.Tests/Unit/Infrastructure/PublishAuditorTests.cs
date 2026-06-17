using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Audit.Events;
using Dependably.Infrastructure.Publish;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Covers <see cref="PublishAuditor"/>'s branching: import vs push vs replace,
/// system vs user actorType, batch_id/import_mode extraction edge cases, and the
/// "import never dual-writes audit_log" guard (per the 5f6e1f0 invariant).
/// </summary>
[Trait("Category", "Unit")]
public sealed class PublishAuditorTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly RecordingAuditEmitter _emitter = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private PublishAuditor Build() => new(new AuditRepository(_db), _emitter);

    private static PublishRequest Sample(
        string auditAction = "push",
        string? auditDetail = null,
        string? actorUserId = "u1",
        string? sourceIp = "10.0.0.1",
        string origin = "uploaded",
        string claimState = "unclaimed",
        long size = 42) => new()
        {
            OrgId = "o1",
            Ecosystem = "npm",
            Name = "lodash",
            PurlName = "lodash",
            Version = "1.2.3",
            Filename = "lodash-1.2.3.tgz",
            Purl = "pkg:npm/lodash@1.2.3",
            ArtifactBytes = new byte[size],
            Origin = origin,
            SizeCap = long.MaxValue,
            ActorUserId = actorUserId,
            AuditAction = auditAction,
            AuditDetail = auditDetail,
            ClaimState = claimState,
            SourceIp = sourceIp,
        };

    private async Task<int> CountAsync(string table)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<int>($"SELECT COUNT(*) FROM {table}");
        // xtenant: test-only count helper across a freshly seeded single-org store.
    }

    private async Task<List<(string Action, string? Detail, string? ActorId)>> AuditRowsAsync()
    {
        await using var conn = await _db.OpenAsync();
        var rows = await conn.QueryAsync<(string Action, string? Detail, string? ActorId)>(
            "SELECT action AS Action, detail AS Detail, actor_id AS ActorId FROM audit_log ORDER BY created_at, id");
        return rows.ToList();
    }

    private async Task<List<(string EventType, string? Detail, string? SourceIp, string? ActorId)>> ActivityRowsAsync()
    {
        await using var conn = await _db.OpenAsync();
        var rows = await conn.QueryAsync<(string EventType, string? Detail, string? SourceIp, string? ActorId)>(
            "SELECT event_type AS EventType, detail AS Detail, source_ip AS SourceIp, actor_id AS ActorId FROM activity ORDER BY created_at, id");
        return rows.ToList();
    }

    // ─── push branch ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Push_writes_audit_log_and_activity_and_emits_typed_publish()
    {
        var auditor = Build();
        await auditor.RecordAsync(Sample(auditAction: "push", auditDetail: "{\"foo\":\"bar\"}"),
            sha256: "abc123", existing: null, sizeBytes: 42L, ct: default);

        // Both tables hit (push dual-writes).
        Assert.Equal(1, await CountAsync("audit_log"));
        Assert.Equal(1, await CountAsync("activity"));

        var audit = (await AuditRowsAsync()).Single();
        Assert.Equal("push", audit.Action);
        Assert.Equal("{\"foo\":\"bar\"}", audit.Detail);
        Assert.Equal("u1", audit.ActorId);
        var (EventType, _, SourceIp, _) = (await ActivityRowsAsync()).Single();
        Assert.Equal("push", EventType);
        Assert.Equal("10.0.0.1", SourceIp);

        var typed = Assert.Single(_emitter.Emitted);
        Assert.Equal(PackageEvents.TypePublish, typed.EventType);
        Assert.Equal("user", typed.ActorType);
        Assert.Equal("accepted", typed.Outcome);
        using var doc = JsonDocument.Parse(typed.PayloadJson);
        Assert.Equal("sha256:abc123", doc.RootElement.GetProperty("artifact_hash").GetString());
        Assert.Equal(42L, doc.RootElement.GetProperty("size_bytes").GetInt64());
        Assert.Equal("uploaded", doc.RootElement.GetProperty("origin").GetString());
        Assert.Equal("unclaimed", doc.RootElement.GetProperty("claim_state").GetString());
    }

    [Fact]
    public async Task Push_with_null_actor_emits_typed_event_with_system_actorType()
    {
        var auditor = Build();
        await auditor.RecordAsync(Sample(auditAction: "push", actorUserId: null),
            sha256: "deadbeef", existing: null, sizeBytes: 42L, ct: default);

        var typed = Assert.Single(_emitter.Emitted);
        Assert.Equal("system", typed.ActorType);
        Assert.Null(typed.ActorId);

        var audit = (await AuditRowsAsync()).Single();
        Assert.Null(audit.ActorId);
    }

    // ─── import branch (the "never dual-write" guard) ───────────────────────────

    [Fact]
    public async Task Import_writes_only_activity_and_emits_typed_import_with_batch_info()
    {
        var auditor = Build();
        string detail = JsonSerializer.Serialize(new { batch_id = "b-99", import_mode = "bulk" });
        await auditor.RecordAsync(Sample(auditAction: "import", auditDetail: detail),
            sha256: "ff00", existing: null, sizeBytes: 42L, ct: default);

        // The invariant: import is per-version only; audit_log stays empty.
        Assert.Equal(0, await CountAsync("audit_log"));
        Assert.Equal(1, await CountAsync("activity"));
        var (EventType, Detail, _, _) = (await ActivityRowsAsync()).Single();
        Assert.Equal("import", EventType);
        Assert.Equal(detail, Detail);

        var typed = Assert.Single(_emitter.Emitted);
        Assert.Equal(PackageEvents.TypeImport, typed.EventType);
        using var doc = JsonDocument.Parse(typed.PayloadJson);
        Assert.Equal("b-99", doc.RootElement.GetProperty("batch_id").GetString());
        Assert.Equal("bulk", doc.RootElement.GetProperty("import_mode").GetString());
    }

    [Fact]
    public async Task Import_with_null_detail_falls_back_to_single_mode_and_empty_batch_id()
    {
        var auditor = Build();
        await auditor.RecordAsync(Sample(auditAction: "import", auditDetail: null),
            sha256: "11", existing: null, sizeBytes: 42L, ct: default);

        var typed = Assert.Single(_emitter.Emitted);
        Assert.Equal(PackageEvents.TypeImport, typed.EventType);
        using var doc = JsonDocument.Parse(typed.PayloadJson);
        Assert.Equal("", doc.RootElement.GetProperty("batch_id").GetString());
        Assert.Equal("single", doc.RootElement.GetProperty("import_mode").GetString());
    }

    [Fact]
    public async Task Import_with_malformed_json_detail_falls_back_via_catch()
    {
        var auditor = Build();
        await auditor.RecordAsync(Sample(auditAction: "import", auditDetail: "not-json{"),
            sha256: "22", existing: null, sizeBytes: 42L, ct: default);

        var typed = Assert.Single(_emitter.Emitted);
        using var doc = JsonDocument.Parse(typed.PayloadJson);
        Assert.Equal("", doc.RootElement.GetProperty("batch_id").GetString());
        Assert.Equal("single", doc.RootElement.GetProperty("import_mode").GetString());
    }

    [Fact]
    public async Task Import_with_non_string_batch_and_mode_falls_back_to_defaults()
    {
        // Valid JSON but the two fields are numbers, not strings — the ValueKind guard returns defaults.
        var auditor = Build();
        string detail = JsonSerializer.Serialize(new { batch_id = 7, import_mode = 9 });
        await auditor.RecordAsync(Sample(auditAction: "import", auditDetail: detail),
            sha256: "33", existing: null, sizeBytes: 42L, ct: default);

        var typed = Assert.Single(_emitter.Emitted);
        using var doc = JsonDocument.Parse(typed.PayloadJson);
        Assert.Equal("", doc.RootElement.GetProperty("batch_id").GetString());
        Assert.Equal("single", doc.RootElement.GetProperty("import_mode").GetString());
    }

    [Fact]
    public async Task Import_with_partial_detail_extracts_present_fields_only()
    {
        // batch_id present, import_mode absent → mode defaults to "single".
        var auditor = Build();
        string detail = JsonSerializer.Serialize(new { batch_id = "only-batch" });
        await auditor.RecordAsync(Sample(auditAction: "import", auditDetail: detail),
            sha256: "44", existing: null, sizeBytes: 42L, ct: default);

        var typed = Assert.Single(_emitter.Emitted);
        using var doc = JsonDocument.Parse(typed.PayloadJson);
        Assert.Equal("only-batch", doc.RootElement.GetProperty("batch_id").GetString());
        Assert.Equal("single", doc.RootElement.GetProperty("import_mode").GetString());
    }

    // ─── replace branch (existing != null) ──────────────────────────────────────

    [Fact]
    public async Task Push_with_existing_emits_replace_event_and_writes_replace_audit()
    {
        var auditor = Build();
        var existing = new PackageVersion { ChecksumSha256 = "oldhash" };
        await auditor.RecordAsync(Sample(auditAction: "push"),
            sha256: "newhash", existing: existing, sizeBytes: 42L, ct: default);

        // Two audit_log rows: 'push' + 'package.replace'. activity stays at 1.
        var audit = await AuditRowsAsync();
        Assert.Equal(2, audit.Count);
        Assert.Contains(audit, a => a.Action == "push");
        var replace = audit.Single(a => a.Action == "package.replace");

        // replace detail is a JSON blob; the keys are stable.
        using (var doc = JsonDocument.Parse(replace.Detail!))
        {
            Assert.Equal("sha256:oldhash", doc.RootElement.GetProperty("prior_artifact_hash").GetString());
            Assert.Equal("sha256:newhash", doc.RootElement.GetProperty("artifact_hash").GetString());
            Assert.Equal("uploaded", doc.RootElement.GetProperty("origin").GetString());
        }

        // Two typed events: publish + replace.
        Assert.Equal(2, _emitter.Emitted.Count);
        var typedReplace = _emitter.Emitted.Single(e => e.EventType == PackageEvents.TypeReplace);
        using var payload = JsonDocument.Parse(typedReplace.PayloadJson);
        Assert.Equal("sha256:newhash", payload.RootElement.GetProperty("artifact_hash").GetString());
        Assert.Equal("sha256:oldhash", payload.RootElement.GetProperty("prior_artifact_hash").GetString());
    }

    [Fact]
    public async Task Replace_with_null_prior_checksum_serialises_as_sha256_empty()
    {
        // existing exists but its ChecksumSha256 is null — the "?? \"\"" branch fires.
        var auditor = Build();
        var existing = new PackageVersion { ChecksumSha256 = null };
        await auditor.RecordAsync(Sample(auditAction: "push", actorUserId: null),
            sha256: "newhash", existing: existing, sizeBytes: 42L, ct: default);

        var replace = (await AuditRowsAsync()).Single(a => a.Action == "package.replace");
        using var doc = JsonDocument.Parse(replace.Detail!);
        Assert.Equal("sha256:", doc.RootElement.GetProperty("prior_artifact_hash").GetString());

        // Null actor → system actorType propagates into the typed replace event too.
        var typedReplace = _emitter.Emitted.Single(e => e.EventType == PackageEvents.TypeReplace);
        Assert.Equal("system", typedReplace.ActorType);
        Assert.Null(typedReplace.ActorId);
    }

    [Fact]
    public async Task Import_with_existing_emits_both_import_and_replace_events()
    {
        // Import + replace: confirms RecordReplaceAsync fires for imports too,
        // but audit_log only sees the package.replace row (no 'import' row).
        var auditor = Build();
        var existing = new PackageVersion { ChecksumSha256 = "prior" };
        await auditor.RecordAsync(Sample(auditAction: "import", auditDetail: null),
            sha256: "newer", existing: existing, sizeBytes: 42L, ct: default);

        var audit = await AuditRowsAsync();
        Assert.Single(audit);
        Assert.Equal("package.replace", audit[0].Action);

        Assert.Equal(2, _emitter.Emitted.Count);
        Assert.Contains(_emitter.Emitted, e => e.EventType == PackageEvents.TypeImport);
        Assert.Contains(_emitter.Emitted, e => e.EventType == PackageEvents.TypeReplace);
    }

    // ─── test double ────────────────────────────────────────────────────────────

    private sealed class RecordingAuditEmitter : IAuditEmitter
    {
        public List<EmittedEvent> Emitted { get; } = new();

        public Task EmitAsync(string eventType, string? orgId, string actorType,
            string? actorId, string outcome, string payloadJson, CancellationToken ct = default)
        {
            Emitted.Add(new EmittedEvent(eventType, orgId, actorType, actorId, outcome, payloadJson));
            return Task.CompletedTask;
        }
    }

    private sealed record EmittedEvent(
        string EventType, string? OrgId, string ActorType,
        string? ActorId, string Outcome, string PayloadJson);
}
