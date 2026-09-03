using System.Text.RegularExpressions;

namespace Dependably.Protocol.Hex;

/// <summary>
/// The identity rules hex.pm enforces on a package name and a release version, applied to every
/// name and version this registry accepts from a client, a tarball or an upstream index.
/// </summary>
public static partial class HexNaming
{
    /// <summary>Lower-case, starts with a letter, letters/digits/underscore, at most 100 characters.</summary>
    [GeneratedRegex(@"^[a-z][a-z0-9_]{0,99}\z")]
    private static partial Regex NameRegex();

    /// <summary>Strict SemVer 2.0, which Hex mandates for every release version.</summary>
    [GeneratedRegex(@"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?\z")]
    private static partial Regex VersionRegex();

    public static bool IsValidPackageName(string? name) => name is not null && NameRegex().IsMatch(name);

    public static bool IsValidVersion(string? version) => version is not null && VersionRegex().IsMatch(version);
}
