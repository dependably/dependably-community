namespace Dependably.Security;

public interface IUpstreamUrlValidator
{
    Task<bool> IsAllowedAsync(string url, string? orgId, CancellationToken ct = default);
}
