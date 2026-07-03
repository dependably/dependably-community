namespace Dependably.Infrastructure.Siem;

/// <summary>
/// Single audit event prepared for outbound SIEM delivery. Distinct from the existing
/// <c>AuditEntry</c> used by the pull API: forwarder DTOs travel through a bounded channel
/// and may be dropped on overflow, so they should be lightweight and stand alone from the
/// repository read model.
/// </summary>
public sealed record SiemEvent(
    string Id,
    string Action,
    string Scope,           // 'tenant' | 'system'
    string? OrgId,
    string? ActorId,
    string? Ecosystem,
    string? Purl,
    string? Detail,         // JSON
    DateTimeOffset CreatedAt);
