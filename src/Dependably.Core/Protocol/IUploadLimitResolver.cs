namespace Dependably.Protocol;

/// <summary>
/// Resolves the effective upload size limit for an org+ecosystem combination.
/// Org-level limits cannot exceed the instance default; the lower of the two wins.
/// </summary>
public interface IUploadLimitResolver
{
    /// <summary>
    /// Returns the effective max upload bytes, or null if no limit is configured.
    /// </summary>
    Task<long?> ResolveAsync(string orgId, string ecosystem, CancellationToken ct = default);
}
