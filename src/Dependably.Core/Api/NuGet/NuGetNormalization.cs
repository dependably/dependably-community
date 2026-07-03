using NuGet.Versioning;

namespace Dependably.Api.NuGetProtocol;

/// <summary>
/// Version normalization helpers for NuGet coordinates. Shared by the registration,
/// flatcontainer, and publish handlers.
/// </summary>
internal static class NuGetNormalization
{
    /// <summary>
    /// Returns the NuGet-canonical normalized version string (lowercase, no trailing zeros).
    /// Falls back to the lowercased input when parsing fails.
    /// </summary>
    internal static string NormalizeVersion(string version) =>
        NuGetVersion.TryParse(version, out var nv)
            ? nv.ToNormalizedString().ToLowerInvariant()
            : version.ToLowerInvariant();
}
