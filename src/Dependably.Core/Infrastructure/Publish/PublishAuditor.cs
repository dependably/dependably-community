using System.Text.Json;
using Dependably.Infrastructure.Audit;
using Dependably.Infrastructure.Audit.Events;

namespace Dependably.Infrastructure.Publish;

/// <summary>
/// Audit recording for <see cref="PackagePublishService"/>: the per-version operator
/// <c>activity</c> row, the tenant-config <c>audit_log</c> row when applicable, and the
/// typed <c>audit_event</c> payload. Pulled out so the branching on action type lives in
/// one place and stays out of the publish service's cognitive budget. Import and replace
/// are per-version operator actions and go to <c>activity</c> only; <c>push</c> still
/// dual-writes into <c>audit_log</c> pending a separate sweep.
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

    /// <summary>
    /// The value <c>audit_log.actor_id</c> / <c>activity.actor_id</c> must carry, paired with
    /// <see cref="PublishRequest.ActorKind"/>. A service token has no owning user
    /// (<c>TokenRepository.ResolveAsync</c> selects <c>NULL AS user_id</c> for it), so its own
    /// token id is the stable publisher identity — and it is what the audit list queries join
    /// against to render <c>service:&lt;name&gt;</c>. Writing the NULL user id instead leaves the
    /// row indistinguishable from an anonymous one no matter what <c>actor_kind</c> says. Same
    /// principal rule <see cref="PackagePublishService"/> already applies for name ownership.
    /// </summary>
    private static string? ResolveAuditActorId(PublishRequest request)
        => request.ActorKind == ActorKinds.Service ? request.ActorTokenId : request.ActorUserId;

    /// <summary>
    /// The <c>audit_event.actor_type</c> value for a publish. A service-token publish is
    /// <c>api_token</c>, not <c>system</c>: it has a named credential behind it, and calling it
    /// a system event both hides that credential and mixes operator-originated rows in with
    /// tenant-originated ones on the SIEM surface.
    /// </summary>
    private static string ResolveActorType(PublishRequest request) => request switch
    {
        { ActorKind: ActorKinds.Service } => "api_token",
        { ActorUserId: null } => "system",
        _ => "user",
    };

    public async Task RecordAsync(PublishRequest request, string sha256, PackageVersion? existing,
        long sizeBytes, CancellationToken ct)
    {
        string? actorId = ResolveAuditActorId(request);

        // Imports are per-version operator events and belong in `activity` only —
        // `audit_log` is the tenant-level config/security sink. Never dual-write.
        // `push` still dual-writes pending the separate sweep.
        if (request.AuditAction != "import")
        {
            await _audit.LogAsync(request.AuditAction, request.OrgId, actorId,
                request.ActorKind, request.Ecosystem, request.Purl, detail: request.AuditDetail,
                sourceIp: request.SourceIp, ct: ct);
        }
        await _audit.LogActivityAsync(request.OrgId, request.Ecosystem, request.Purl,
            request.AuditAction, actorId, actorKind: request.ActorKind,
            detail: request.AuditDetail, sourceIp: request.SourceIp, ct: ct);

        string actorType = ResolveActorType(request);
        await EmitTypedAsync(request, sha256, sizeBytes, actorType, actorId, ct);

        if (existing is not null)
        {
            await RecordReplaceAsync(request, sha256, sizeBytes, existing, actorType, actorId, ct);
        }
    }

    private async Task EmitTypedAsync(PublishRequest request, string sha256,
        long sizeBytes, string actorType, string? actorId, CancellationToken ct)
    {
        if (request.AuditAction == "import")
        {
            var (batchId, importMode) = ExtractBatchInfo(request.AuditDetail);
            string payload = new PackageEvents.Import(
                request.Ecosystem, request.PurlName, request.Version, request.Filename,
                "sha256:" + sha256, sizeBytes, request.Origin,
                batchId, importMode, request.ClaimState).ToJson();
            await _auditEmitter.EmitAsync(PackageEvents.TypeImport,
                request.OrgId, actorType, actorId, "accepted", payload, ct);
        }
        else
        {
            string payload = new PackageEvents.Publish(
                request.Ecosystem, request.PurlName, request.Version, request.Filename,
                "sha256:" + sha256, sizeBytes, request.Origin,
                request.ClaimState).ToJson();
            await _auditEmitter.EmitAsync(PackageEvents.TypePublish,
                request.OrgId, actorType, actorId, "accepted", payload, ct);
        }
    }

    private async Task RecordReplaceAsync(PublishRequest request, string sha256, long sizeBytes,
        PackageVersion existing, string actorType, string? actorId, CancellationToken ct)
    {
        string priorHash = "sha256:" + (existing.ChecksumSha256 ?? "");
        string newHash = "sha256:" + sha256;
        string replaceDetail = JsonSerializer.Serialize(new
        {
            prior_artifact_hash = priorHash,
            artifact_hash = newHash,
            origin = request.Origin,
        }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail);
        // A replace overwrites an existing version's artifact — a per-version operator
        // action, so it belongs in `activity` only, same as publish and import.
        await _audit.LogActivityAsync(request.OrgId, request.Ecosystem, request.Purl,
            "package.replace", actorId, actorKind: request.ActorKind,
            detail: replaceDetail, sourceIp: request.SourceIp, ct: ct);

        string replacePayload = new PackageEvents.Replace(
            request.Ecosystem, request.PurlName, request.Version, request.Filename,
            newHash, priorHash, sizeBytes, request.Origin,
            request.ClaimState).ToJson();
        await _auditEmitter.EmitAsync(PackageEvents.TypeReplace,
            request.OrgId, actorType, actorId, "accepted", replacePayload, ct);
    }

    /// <summary>
    /// Records the publish-side licence-less warning: <c>license_publish_enforcement_mode=warn</c>
    /// accepted a hosted publish with no declared licence, but the artifact will be denied by the
    /// serve-path gate wherever <c>license_enforcement_mode=block</c> applies. A per-version
    /// operator event — <c>activity</c> only, no <c>audit_log</c> dual-write (mirrors import and
    /// replace).
    /// </summary>
    public Task RecordLicensePublishWarnAsync(PublishRequest request, CancellationToken ct)
    {
        string detail = JsonSerializer.Serialize(
            new { license = Dependably.Protocol.BlockGateService.NoLicenseAssertion },
            Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail);
        return _audit.LogActivityAsync(request.OrgId, request.Ecosystem, request.Purl,
            "license_publish_warn", ResolveAuditActorId(request), actorKind: request.ActorKind,
            detail: detail, sourceIp: request.SourceIp, ct: ct);
    }

    private static (string BatchId, string ImportMode) ExtractBatchInfo(string? detail)
    {
        if (string.IsNullOrEmpty(detail))
        {
            return ("", "single");
        }

        try
        {
            using var doc = JsonDocument.Parse(detail);
            var root = doc.RootElement;
            string batchId = root.TryGetProperty("batch_id", out var b) && b.ValueKind == JsonValueKind.String
                ? b.GetString() ?? "" : "";
            string mode = root.TryGetProperty("import_mode", out var m) && m.ValueKind == JsonValueKind.String
                ? m.GetString() ?? "single" : "single";
            return (batchId, mode);
        }
        catch
        {
            return ("", "single");
        }
    }
}
