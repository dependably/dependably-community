using System.Diagnostics.CodeAnalysis;

namespace Dependably.Protocol;

/// <summary>
/// The line-level readers shared by every consumer of a crate's <c>Cargo.toml</c>: the licence
/// extractor (proxy and backfill paths) and the publish-time coordinate cross-check. Deliberately
/// minimal rather than a TOML dependency — only a handful of scalar keys and one string array are
/// ever read, and only from the crate's own <c>[package]</c> table. crates.io normalizes a published
/// manifest's <c>[package]</c> table onto single <c>key = "value"</c> lines, so line-based scanning
/// is safe for this narrow case.
/// </summary>
internal static class CargoTomlReader
{
    /// <summary>
    /// True for an entry name shaped exactly <c>&lt;root-dir&gt;/Cargo.toml</c> — one path
    /// separator, the crate's own manifest at the tarball root. A deeper path (a
    /// <c>Cargo.toml</c> bundled in a subdirectory) does not match.
    /// </summary>
    public static bool IsRootCargoToml(string entryName)
    {
        int slash = entryName.IndexOf('/');
        return slash > 0
            && entryName[(slash + 1)..].Equals("Cargo.toml", StringComparison.Ordinal)
            && entryName.LastIndexOf('/') == slash;
    }

    /// <summary>
    /// Walks the manifest line by line and hands every <c>[package]</c> string assignment to
    /// <paramref name="onPackageKey"/> as <c>(key, value)</c>; string-array assignments go to
    /// <paramref name="onPackageArray"/> when supplied. A key seen while any other section is
    /// active (a nested <c>[package.metadata]</c> included) is skipped, so it can never be mistaken
    /// for the crate's own value.
    /// </summary>
    public static void ScanPackageTable(
        string text,
        Action<string, string> onPackageKey,
        Action<string, List<string>>? onPackageArray = null)
    {
        string? currentSection = null;
        using var reader = new StringReader(text);
        while (reader.ReadLine() is { } rawLine)
        {
            string line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            if (TryParseSectionHeader(line, out string? section))
            {
                currentSection = section;
                continue;
            }

            if (!string.Equals(currentSection, "package", StringComparison.Ordinal))
            {
                continue;
            }

            if (onPackageArray is not null
                && TryParseStringArrayAssignment(line, out string? arrayKey, out var entries))
            {
                onPackageArray(arrayKey!, entries);
                continue;
            }

            if (TryParseStringAssignment(line, out string? key, out string? value))
            {
                onPackageKey(key, value);
            }
        }
    }

    // Reads a single-line TOML array of strings (`authors = ["A", "B"]`). Deliberately narrow: a
    // multi-line array is left unparsed rather than half-parsed, because a partial author list
    // reads as complete and there is no way for a viewer to tell it was truncated. A quote inside
    // an entry ends it, which is the same tolerance the string-assignment reader already applies.
    public static bool TryParseStringArrayAssignment(
        string line, out string? key, out List<string> entries)
    {
        key = null;
        entries = [];

        int equals = line.IndexOf('=');
        if (equals <= 0)
        {
            return false;
        }

        string rawValue = line[(equals + 1)..].Trim();
        if (!rawValue.StartsWith('[') || !rawValue.EndsWith(']'))
        {
            return false;
        }

        key = line[..equals].Trim();
        foreach (string part in rawValue[1..^1].Split(','))
        {
            string entry = part.Trim().Trim('"', '\'');
            if (entry.Length > 0)
            {
                entries.Add(entry);
            }
        }

        return true;
    }

    // Matches a TOML "[section]" header line, extracting the section name. Returns false (and
    // section = null) for any other line shape, so the caller keeps scanning.
    public static bool TryParseSectionHeader(string line, out string? section)
    {
        if (!line.StartsWith('['))
        {
            section = null;
            return false;
        }

        int end = line.IndexOf(']');
        section = end > 0 ? line[1..end].Trim() : null;
        return true;
    }

    // Matches a `key = "..."` basic-string assignment line, extracting the key and the unquoted
    // value. Returns false for a non-string value (array, literal string, number) or a malformed
    // line, so the caller keeps scanning.
    public static bool TryParseStringAssignment(
        string line,
        [NotNullWhen(true)] out string? key,
        [NotNullWhen(true)] out string? value)
    {
        int eq = line.IndexOf('=');
        if (eq <= 0)
        {
            key = null;
            value = null;
            return false;
        }

        key = line[..eq].Trim();
        value = UnquoteBasicString(line[(eq + 1)..].Trim());
        return value is not null;
    }

    // Extracts the value of a TOML basic (double-quoted) string, ignoring any trailing inline
    // comment. Returns null for any other value shape (literal string, array, etc.) — the
    // narrow line-based parser only supports the form crates.io emits on publish.
    public static string? UnquoteBasicString(string value)
    {
        if (value.Length < 2 || value[0] != '"')
        {
            return null;
        }

        int closingQuote = value.IndexOf('"', 1);
        return closingQuote > 0 ? value[1..closingQuote] : null;
    }
}
