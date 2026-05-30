using System.Text.Json;
using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Audit.Events;

namespace Dependably.Infrastructure.Publish;

/// <summary>
/// Audit dual-write for <see cref="PackagePublishService"/>: the per-version operator
/// <c>activity</c> row, the tenant-config <c>audit_log</c> row when applicable, and the
/// typed <c>audit_event</c> payload. Pulled out so the branching on action type lives in
/// one place and stays out of the publish service's cognitive budget.
/// </summary>
public sealed class PublishAuditor
{
    private readonly AuditRepository _audit;
    private readonly IAuditEmitter _auditEmitter;

    public PublishAuditor(AuditRepository audit, IAuditEmitter auditEmitter)
    {
        _audit = audit;
        _auditEmitter = auditEmitter;
    }

    public async Task RecordAsync(PublishRequest request, string sha256, PackageVersion? existing, CancellationToken ct)
    {
        // Imports are per-version operator events and belong in `activity` only —
        // `audit_log` is the tenant-level config/security sink. Never dual-write (5f6e1f0).
        // `push` still dual-writes pending the separate sweep called out in that commit.
        if (request.AuditAction != "import")
        {
            await _audit.LogAsync(request.AuditAction, request.OrgId, request.ActorUserId,
                request.ActorKind, request.Ecosystem, request.Purl, detail: request.AuditDetail, ct: ct);
        }
        await _audit.LogActivityAsync(request.OrgId, request.Ecosystem, request.Purl,
            request.AuditAction, request.ActorUserId, actorKind: request.ActorKind,
            detail: request.AuditDetail, sourceIp: request.SourceIp, ct: ct);

        var actorType = request.ActorUserId is null ? "system" : "user";
        await EmitTypedAsync(request, sha256, actorType, ct);

        if (existing is not null)
            await RecordReplaceAsync(request, sha256, existing, actorType, ct);
    }

    private async Task EmitTypedAsync(PublishRequest request, string sha256, string actorType, CancellationToken ct)
    {
        if (request.AuditAction == "import")
        {
            var (batchId, importMode) = ExtractBatchInfo(request.AuditDetail);
            var payload = new PackageEvents.Import(
                request.Ecosystem, request.PurlName, request.Version, request.Filename,
                "sha256:" + sha256, request.ArtifactBytes.LongLength, request.Origin,
                batchId, importMode, request.ClaimState).ToJson();
            await _auditEmitter.EmitAsync(PackageEvents.TypeImport,
                request.OrgId, actorType, request.ActorUserId, "accepted", payload, ct);
        }
        else
        {
            var payload = new PackageEvents.Publish(
                request.Ecosystem, request.PurlName, request.Version, request.Filename,
                "sha256:" + sha256, request.ArtifactBytes.LongLength, request.Origin,
                request.ClaimState).ToJson();
            await _auditEmitter.EmitAsync(PackageEvents.TypePublish,
                request.OrgId, actorType, request.ActorUserId, "accepted", payload, ct);
        }
    }

    private async Task RecordReplaceAsync(PublishRequest request, string sha256, PackageVersion existing,
        string actorType, CancellationToken ct)
    {
        var priorHash = "sha256:" + (existing.ChecksumSha256 ?? "");
        var newHash = "sha256:" + sha256;
        var replaceDetail = JsonSerializer.Serialize(new
        {
            prior_artifact_hash = priorHash,
            artifact_hash = newHash,
            origin = request.Origin,
        });
        await _audit.LogAsync("package.replace", request.OrgId, request.ActorUserId,
            request.ActorKind, request.Ecosystem, request.Purl, detail: replaceDetail, ct: ct);

        var replacePayload = new PackageEvents.Replace(
            request.Ecosystem, request.PurlName, request.Version, request.Filename,
            newHash, priorHash, request.ArtifactBytes.LongLength, request.Origin,
            request.ClaimState).ToJson();
        await _auditEmitter.EmitAsync(PackageEvents.TypeReplace,
            request.OrgId, actorType, request.ActorUserId, "accepted", replacePayload, ct);
    }

    private static (string BatchId, string ImportMode) ExtractBatchInfo(string? detail)
    {
        if (string.IsNullOrEmpty(detail)) return ("", "single");
        try
        {
            using var doc = JsonDocument.Parse(detail);
            var root = doc.RootElement;
            var batchId = root.TryGetProperty("batch_id", out var b) && b.ValueKind == JsonValueKind.String
                ? b.GetString() ?? "" : "";
            var mode = root.TryGetProperty("import_mode", out var m) && m.ValueKind == JsonValueKind.String
                ? m.GetString() ?? "single" : "single";
            return (batchId, mode);
        }
        catch
        {
            return ("", "single");
        }
    }
}
