namespace Dependably.Protocol;

/// <summary>
/// Maps an RPM header's <c>Vendor</c> tag (<see cref="RpmHeaderParser.Parse"/> /
/// <see cref="RpmHeaderInfo.Vendor"/>) to the distro namespace segment OSV.dev's RPM ecosystems
/// register, so <see cref="PurlNormalizer.Rpm"/> can emit a purl OSV's server can actually resolve.
///
/// <para>
/// OSV.dev has no bare "rpm" ecosystem — every RPM advisory feed is distro-namespaced. The eight
/// namespaces below are the complete set, cross-checked directly against OSV's own server source
/// (not assumed): the Python purl↔ecosystem table (<c>osv/purl_helpers.py</c>'s
/// <c>ECOSYSTEM_PURL_DATA</c>, keyed by distro display name) and the live Go API server's
/// registration table (<c>go/purl/ecosystems_simple.go</c>'s <c>registerSimple</c> calls), which
/// agree exactly. Both sources carry Fedora and Photon OS as commented-out placeholders with no
/// registered entry — neither resolves to a real OSV feed today, so both are deliberately absent
/// here; a Fedora- or Photon-shaped <c>Vendor</c> string falls through to <c>null</c>, the same as
/// any other distro OSV does not (yet) publish a feed for.
/// </para>
///
/// <para>
/// A real-world <c>Vendor</c> string is not standardized wording — it varies by distro version and
/// build infrastructure (<c>"Red Hat, Inc."</c>, <c>"Rocky Enterprise Software Foundation"</c>,
/// <c>"AlmaLinux OS Foundation"</c>, <c>"SUSE LLC"</c>, <c>"openSUSE"</c>, ...) — so matching is a
/// tolerant, case-insensitive keyword search rather than exact equality against one canonical
/// string. openSUSE is matched before bare SUSE specifically because "opensuse" contains "suse" as
/// a substring: checking the narrower keyword first is what keeps an openSUSE vendor string from
/// being swallowed by the broader SUSE entry.
/// </para>
/// </summary>
public static class RpmVendorDistroResolver
{
    /// <summary>
    /// The complete set of OSV.dev RPM namespace segments, as registered by both
    /// <c>osv/purl_helpers.py</c> and <c>go/purl/ecosystems_simple.go</c>. Shared with
    /// <see cref="PurlNormalizer.RpmHasKnownDistro"/> so the two checks cannot drift apart.
    /// </summary>
    public static readonly IReadOnlyList<string> KnownNamespaces =
    [
        "almalinux",
        "azure-linux",
        "mageia",
        "openeuler",
        "opensuse",
        "redhat",
        "rocky-linux",
        "suse",
    ];

    // Checked in array order — first match wins. "opensuse" is listed ahead of "suse" so an
    // openSUSE vendor string (which always also contains the substring "suse") resolves to the
    // more specific namespace rather than the broader one.
    private static readonly (string Namespace, string[] Keywords)[] Rules =
    [
        ("almalinux", ["almalinux", "alma linux"]),
        ("rocky-linux", ["rocky"]),
        ("redhat", ["red hat", "redhat"]),
        ("openeuler", ["openeuler", "open euler"]),
        ("opensuse", ["opensuse", "open suse"]),
        ("suse", ["suse"]),
        ("azure-linux", ["azure linux", "cbl-mariner", "cbl mariner", "microsoft"]),
        ("mageia", ["mageia"]),
    ];

    /// <summary>
    /// Resolves a raw RPM <c>Vendor</c> header string to an OSV RPM namespace segment, or
    /// <c>null</c> when the vendor is empty, unset, or does not match a distro OSV registers a feed
    /// for (Fedora and Photon OS included — see the class doc comment).
    /// </summary>
    public static string? Resolve(string? vendor)
    {
        if (string.IsNullOrWhiteSpace(vendor))
        {
            return null;
        }

        string normalized = vendor.ToLowerInvariant();
        foreach (var (ns, keywords) in Rules)
        {
            foreach (string keyword in keywords)
            {
                if (normalized.Contains(keyword, StringComparison.Ordinal))
                {
                    return ns;
                }
            }
        }

        return null;
    }
}
