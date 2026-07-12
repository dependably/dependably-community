namespace Dependably.Protocol;

/// <summary>
/// Maps legacy Fedora/RHEL short license tags (as carried in the RPM header
/// <c>License</c> field and mirrored in upstream <c>primary.xml</c>
/// <c>&lt;rpm:license&gt;</c>) to SPDX license identifiers, so RPM-origin license
/// facts land in <c>package_version_licenses</c> in the same vocabulary as every
/// other ecosystem.
///
/// Only unambiguous single-license tags are mapped. Compound Fedora boolean
/// expressions (<c>"GPLv2+ and BSD"</c>, <c>"MIT or Apache-2.0"</c>, anything with
/// parentheses) and tags with no reliable SPDX equivalent (e.g. <c>"Public
/// Domain"</c>) are intentionally left unmapped. Modern Fedora packages (post-2023)
/// already carry an SPDX expression in the License tag — an exact match against a
/// mapper key is honored, but no attempt is made to parse or validate an SPDX
/// expression here.
///
/// Unmapped input is returned trimmed but otherwise verbatim, so it still lands in
/// the license review queue as a non-SPDX string — consistent with how other
/// ecosystems store review-queue candidates that aren't strictly SPDX-shaped
/// (e.g. PyPI's free-text <c>License</c> classifier value).
/// </summary>
public static class RpmLicenseMapper
{
    // Case-insensitive on the trimmed tag — Fedora spec files are inconsistent about
    // casing ("GPLv2+" vs "gplv2+"), and the mapping is unambiguous either way.
    private static readonly Dictionary<string, string> _fedoraToSpdx = new(StringComparer.OrdinalIgnoreCase)
    {
        ["GPLv2"] = "GPL-2.0-only",
        ["GPLv2+"] = "GPL-2.0-or-later",
        ["GPLv3"] = "GPL-3.0-only",
        ["GPLv3+"] = "GPL-3.0-or-later",
        // Fedora's "LGPLv2" denotes LGPL 2.1 (the FSF renamed the v2 LGPL to 2.1;
        // "LGPLv2.0" is the tag Fedora reserves for the rare true 2.0).
        ["LGPLv2"] = "LGPL-2.1-only",
        ["LGPLv2+"] = "LGPL-2.1-or-later",
        ["LGPLv3"] = "LGPL-3.0-only",
        ["LGPLv3+"] = "LGPL-3.0-or-later",
        ["ASL 2.0"] = "Apache-2.0",
        ["ASL 1.1"] = "Apache-1.1",
        ["MIT"] = "MIT",
        ["ISC"] = "ISC",
        ["MPLv2.0"] = "MPL-2.0",
        ["MPLv1.1"] = "MPL-1.1",
        ["zlib"] = "Zlib",
    };

    /// <summary>
    /// Maps a raw RPM <c>License</c> tag to its SPDX identifier. Returns the trimmed
    /// input verbatim when no unambiguous mapping exists (compound expressions,
    /// "Public Domain", or an already-SPDX tag that isn't one of the mapped legacy
    /// short forms).
    /// </summary>
    public static string ToSpdx(string rawLicenseTag)
    {
        string trimmed = rawLicenseTag.Trim();
        return _fedoraToSpdx.TryGetValue(trimmed, out string? spdx) ? spdx : trimmed;
    }
}
