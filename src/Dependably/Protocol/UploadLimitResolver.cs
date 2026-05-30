using Dependably.Infrastructure;

namespace Dependably.Protocol;

/// <summary>
/// Resolves upload size limits from org settings and instance defaults.
/// Org-level overrides cannot exceed the instance default (enforced at write time in settings API).
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

        long? instanceDefault = _config["MAX_UPLOAD_BYTES"] is { } s && long.TryParse(s, out var v) ? v : null;

        // Ecosystem-specific org override
        long? orgLimit = ecosystem switch
        {
            "pypi"  => settings?.MaxUploadBytesPyPi  ?? settings?.MaxUploadBytes,
            "npm"   => settings?.MaxUploadBytesNpm   ?? settings?.MaxUploadBytes,
            "nuget" => settings?.MaxUploadBytesNuGet ?? settings?.MaxUploadBytes,
            "maven" => settings?.MaxUploadBytesMaven ?? settings?.MaxUploadBytes,
            "rpm"   => settings?.MaxUploadBytesRpm   ?? settings?.MaxUploadBytes,
            "oci"   => settings?.MaxUploadBytesOci   ?? settings?.MaxUploadBytes,
            _       => settings?.MaxUploadBytes,
        };

        if (orgLimit is null && instanceDefault is null)
            return null;

        // The lower of the two wins; org cannot exceed instance default
        if (orgLimit is null) return instanceDefault;
        if (instanceDefault is null) return orgLimit;
        return Math.Min(orgLimit.Value, instanceDefault.Value);
    }
}
