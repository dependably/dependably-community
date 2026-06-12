using System.Text.RegularExpressions;

namespace Dependably.Protocol;

/// <summary>
/// Single source of truth for npm package-name shape validation. Used by the npm publish
/// controller (URL-derived name) and by <see cref="NpmTarballValidator"/> (manifest-derived
/// name on the import path) so both surfaces enforce identical rules: lowercase, ≤214 chars,
/// URL-safe charset, no leading <c>.</c> or <c>_</c>, and at most a single leading
/// <c>@scope/</c> segment. Any other <c>/</c> is rejected — names land verbatim in blob-key
/// path positions, so extra separators would enable cross-package key overlap.
/// </summary>
public static partial class NpmNameValidator
{
    [GeneratedRegex(@"^(?!node_modules$|favicon\.ico$)(?!\.|_)[a-z0-9][a-z0-9._\-]*$")]
    private static partial Regex NameSegmentRegex();

    private const int MaxLength = 214;

    /// <summary>Validates an unscoped name segment (the part after any <c>@scope/</c>).</summary>
    public static bool IsValidPlainName(string name) =>
        name.Length <= MaxLength && NameSegmentRegex().IsMatch(name);

    /// <summary>
    /// Validates a full npm name: either an unscoped name, or <c>@scope/name</c> where the
    /// scope and name segments each satisfy the segment rules.
    /// </summary>
    public static bool IsValidFullName(string fullName)
    {
        if (string.IsNullOrEmpty(fullName) || fullName.Length > MaxLength)
        {
            return false;
        }

        if (!fullName.StartsWith('@'))
        {
            return IsValidPlainName(fullName);
        }

        int slash = fullName.IndexOf('/');
        if (slash < 0 || slash != fullName.LastIndexOf('/'))
        {
            return false;
        }

        string scope = fullName[1..slash];
        string plain = fullName[(slash + 1)..];
        return NameSegmentRegex().IsMatch(scope) && IsValidPlainName(plain);
    }
}
