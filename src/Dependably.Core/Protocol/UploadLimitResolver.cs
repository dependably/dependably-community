using Dependably.Infrastructure;

namespace Dependably.Protocol;

/// <summary>
/// Resolves upload size limits from org settings and instance defaults, in the documented
/// order: org ecosystem limit → org global limit → instance ecosystem limit (the same chain
/// the controllers use via <see cref="OrgRepository.GetUploadLimitAsync"/>). The
/// <c>MAX_UPLOAD_BYTES</c> instance-wide ceiling is applied on top — org-level overrides
/// cannot exceed it (also enforced at write time in the settings API).
/// </summary>
public sealed class UploadLimitResolver : IUploadLimitResolver
{
    private readonly OrgRepository _orgs;
    private readonly IConfiguration _config;

    public UploadLimitResolver(OrgRepository orgs, IConfiguration config)
    {
        _orgs = orgs;
        _config = config;
    }

    public async Task<long?> ResolveAsync(string orgId, string ecosystem, CancellationToken ct = default)
    {
        var settings = await _orgs.GetSettingsAsync(orgId, ct);

        long? instanceDefault = _config["MAX_UPLOAD_BYTES"] is { } s && long.TryParse(s, out long v) ? v : null;

        // Org ecosystem → org global → instance ecosystem; long.MaxValue means "no tier set".
        long tiered = await _orgs.GetUploadLimitAsync(settings, ecosystem, ct);
        long? orgLimit = tiered == long.MaxValue ? null : tiered;

        if (orgLimit is null && instanceDefault is null)
        {
            return null;
        }

        // The lower of the two wins; org cannot exceed instance default
        return orgLimit is null ? instanceDefault : instanceDefault is null ? orgLimit : Math.Min(orgLimit.Value, instanceDefault.Value);
    }
}
