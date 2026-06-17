using System.Text.RegularExpressions;

namespace Dependably.Api.NuGetProtocol;

/// <summary>
/// Validates NuGet package IDs against the allowed character set.
/// A valid NuGet package ID contains only letters, digits, hyphens, underscores, and dots.
/// </summary>
internal static partial class NuGetIdValidator
{
    [GeneratedRegex(@"^[A-Za-z0-9_\-\.]+$")]
    private static partial Regex NuGetIdRegex();

    /// <summary>Returns true when <paramref name="id"/> matches the NuGet package ID character set.</summary>
    internal static bool IsValidId(string id) => NuGetIdRegex().IsMatch(id);
}
