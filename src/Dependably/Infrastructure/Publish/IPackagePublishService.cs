using Dependably.Security;

namespace Dependably.Infrastructure.Publish;

/// <summary>
/// Shared tail end of the publish flow used by the protocol controllers and the
/// admin import controller. Each ecosystem's controller still owns its format-specific
/// extraction (npm tarball, PyPI sdist/wheel, NuGet nupkg) and produces a normalised
/// <see cref="PublishRequest"/>; this service handles everything from path safety through
/// to audit emission so the dedup, size, and claim-gate rules stay uniform across surfaces.
///
/// The service does not write blobs that fail validation. A <see cref="PublishResult.Rejected"/>
/// outcome means nothing has been persisted; callers map the status code into their HTTP
/// response (controllers return the status verbatim; ImportController surfaces it as a
/// per-file rejection).
/// </summary>
public interface IPackagePublishService
{
    Task<PublishResult> StoreAndRecordAsync(PublishRequest request, CancellationToken ct = default);

    /// <summary>
    /// Dry-run companion to <see cref="StoreAndRecordAsync"/>: runs every validation
    /// step (path safety, size cap, claim gate, dedup) without writing the blob, creating
    /// the version row, or emitting audit events. Returns the same <see cref="PublishResult"/>
    /// shape so the caller can render projected outcomes verbatim. Used by the bulk-import
    /// endpoints to surface a server-validated pre-import summary before the real upload.
    /// On <see cref="PublishResult.Accepted"/>, <c>VersionId</c> is empty and <c>Sha256</c>
    /// is the computed hash of the input bytes — same value the real path would record.
    /// </summary>
    Task<PublishResult> ValidateAsync(PublishRequest request, CancellationToken ct = default);
}

public sealed record PublishRequest
{
    public required string OrgId { get; init; }

    /// <summary>'npm' | 'pypi' | 'nuget'.</summary>
    public required string Ecosystem { get; init; }

    /// <summary>Display name (e.g. "@scope/foo" for npm, "Newtonsoft.Json" for nuget).</summary>
    public required string Name { get; init; }

    /// <summary>Canonical lookup name (lowercased for nuget/pypi, scope/name for npm).</summary>
    public required string PurlName { get; init; }

    /// <summary>Already-normalised version string.</summary>
    public required string Version { get; init; }

    /// <summary>Filename to store under and validate for path safety.</summary>
    public required string Filename { get; init; }

    /// <summary>Pre-computed PURL.</summary>
    public required string Purl { get; init; }

    public required byte[] ArtifactBytes { get; init; }

    /// <summary>'proxy' (upstream cache) | 'uploaded' (user-pushed file).</summary>
    public required string Origin { get; init; }

    /// <summary>Per-tenant or per-instance upload size cap. Callers compute and pass.</summary>
    public required long SizeCap { get; init; }

    public string? ActorUserId { get; init; }

    /// <summary>
    /// Discriminator persisted alongside <see cref="ActorUserId"/> in
    /// <c>activity.actor_kind</c> / <c>audit_log.actor_kind</c>. Protocol publishes (npm/PyPI/
    /// NuGet push) pass <c>token.ActorKind</c> so service-token pushes resolve as
    /// <c>service:&lt;name&gt;</c> in the audit UI instead of "anonymous". JWT-session callers
    /// (admin import) pass <see cref="ActorKinds.User"/>; background callers leave it NULL.
    /// </summary>
    public string? ActorKind { get; init; }

    /// <summary>Audit action verb. Defaults to 'push' for protocol publishes, 'import' for bulk.</summary>
    public string AuditAction { get; init; } = "push";

    /// <summary>Optional JSON detail string written into the audit row (e.g. {"batch_id":"..."}).</summary>
    public string? AuditDetail { get; init; }

    /// <summary>
    /// When true, a duplicate (name, version) overwrites the existing artefact and emits a
    /// <c>package.replace</c> audit event recording both old and new hashes. Wired from the
    /// per-tenant <c>org_settings.allow_version_overwrite</c> setting. Default false
    /// preserves the strict immutable-coordinate behaviour.
    /// </summary>
    public bool AllowOverwrite { get; init; }

    /// <summary>
    /// The resolved claim state at publish time: <c>unclaimed</c>, <c>local_only</c>,
    /// or <c>mixed</c>. Recorded in the typed audit event payload so forensic correlation
    /// of "what was the policy at the moment this version landed?" is one query, not a
    /// reconstruction. Default <c>unclaimed</c> when the caller doesn't pass one.
    /// </summary>
    public string ClaimState { get; init; } = "unclaimed";

    /// <summary>
    /// Client IP at the time of publish (HTTP-originated calls). Null for background or
    /// non-HTTP callers (e.g. admin import driven from a job). Recorded on the activity
    /// row so the lifecycle feed shows where a push originated.
    /// </summary>
    public string? SourceIp { get; init; }
}

/// <summary>Outcome of a <see cref="IPackagePublishService.StoreAndRecordAsync"/> call.</summary>
public abstract record PublishResult
{
    public sealed record Accepted(string VersionId, string Purl, string Sha256) : PublishResult;

    /// <summary>
    /// <paramref name="HttpStatus"/> is the recommended HTTP status for protocol callers
    /// (409 dedup, 413 size, 403 claim, 422 path-unsafe, etc).
    /// <paramref name="Code"/> is a stable machine-readable identifier; bulk-import callers
    /// surface this in per-file outcomes.
    /// </summary>
    public sealed record Rejected(int HttpStatus, string Code, string Message) : PublishResult;
}
