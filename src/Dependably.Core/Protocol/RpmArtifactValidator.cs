using System.Text.RegularExpressions;
using Dependably.Security;

namespace Dependably.Protocol;

/// <summary>
/// Surface-level validation for an uploaded .rpm file. Confirms the file is at
/// least minimally structured before we accept it for storage / metadata extraction.
/// Heavy parsing lives in <see cref="RpmHeaderParser"/>; this is the gate that produces
/// a clean 422 for obvious garbage.
/// </summary>
public static partial class RpmArtifactValidator
{
    public const int MinimumValidSize = 96 + 16; // lead + header intro
    public static readonly Regex NameRegex = NameRegexCompiled();

    [GeneratedRegex(@"^[A-Za-z0-9._+\-]+$")]
    private static partial Regex NameRegexCompiled();

    /// <summary>
    /// Returns the parsed header on success; throws <see cref="RpmParseException"/> if the
    /// input isn't a valid RPM (truncated, bad magic, missing NEVRA, illegal name chars).
    /// </summary>
    public static RpmHeaderInfo Validate(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length < MinimumValidSize)
        {
            throw new RpmParseException("RPM bytes too short.");
        }

        var info = RpmHeaderParser.Parse(bytes);

        if (!NameRegex.IsMatch(info.Name))
        {
            throw new RpmParseException($"Invalid RPM name characters: '{info.Name}'");
        }
        if (!NameRegex.IsMatch(info.Version))
        {
            throw new RpmParseException($"Invalid RPM version characters: '{info.Version}'");
        }
        if (!NameRegex.IsMatch(info.Release))
        {
            throw new RpmParseException($"Invalid RPM release characters: '{info.Release}'");
        }
        if (!NameRegex.IsMatch(info.Arch))
        {
            throw new RpmParseException($"Invalid RPM arch characters: '{info.Arch}'");
        }

        // The charset regex alone permits values like ".." — these fields flow into
        // BlobKeys.Hosted path segments, so they get the same path-safety gate as every
        // other ecosystem's blob-key components.
        foreach (var (value, field) in new[]
        {
            (info.Name, "name"),
            (info.Version, "version"),
            (info.Release, "release"),
            (info.Arch, "arch"),
        })
        {
            var safe = PathSafeValidator.Validate(value, field);
            if (!safe.IsValid)
            {
                throw new RpmParseException($"Invalid RPM {field}: {safe.Message}");
            }
        }

        return info;
    }
}
