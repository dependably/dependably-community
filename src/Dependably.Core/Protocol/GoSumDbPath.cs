using System.Text.RegularExpressions;

namespace Dependably.Protocol;

/// <summary>The checksum-database request a sumdb path names, or <see cref="Unknown"/>.</summary>
public enum GoSumDbPathKind
{
    /// <summary>Not a path the Go client or the sumdb protocol uses; never forwarded.</summary>
    Unknown,

    /// <summary><c>lookup/{module}@{version}</c>: names a module, so it is reservation-checked.</summary>
    Lookup,

    /// <summary><c>latest</c>: the signed tree head.</summary>
    Latest,

    /// <summary>A canonical <c>tile/…</c> path: a hash or data tile of the transparency log.</summary>
    Tile,
}

/// <summary>
/// Classifies the path a Go client asks the checksum-database passthrough for (the part after
/// <c>sumdb/{name}/</c>). The allowlist is the set the protocol defines: <c>golang.org/x/mod/sumdb</c>
/// serves <c>/lookup/</c>, <c>/latest</c> and <c>/tile/</c>, and the go command adds only the
/// <c>supported</c> probe, which the controller answers itself. Anything else is
/// <see cref="GoSumDbPathKind.Unknown"/> and must not be forwarded: the reservation check only
/// understands a lookup, so any other shape could carry a reserved module name upstream unseen.
/// Matching is case-sensitive, as the checksum database's own routing is.
/// </summary>
public static partial class GoSumDbPath
{
    private const string LookupPrefix = "lookup/";
    private const string TilePrefix = "tile/";

    // golang.org/x/mod/sumdb/tlog: a tile index is written in base-1000 groups of three digits.
    private const int PathBase = 1000;

    // The tile index is an int64, which is at most seven base-1000 groups.
    private const int MaxIndexGroups = 7;

    // Stricter than ParseTilePath, which caps neither the level nor the width's digit count:
    // levels above 63 and 10-digit widths need a tile height above 8, and the go command always
    // uses height 8 (it never calls SetTileHeight), so no real client request is refused. A
    // seven-group index that overflows int64 is still accepted here although Go rejects it; it
    // is digits only, so it cannot carry a module name past the reservation check.
    private const int MaxLevel = 63;

    // tlog.ParseTilePath bounds the tile height to 1..30.
    private const int MaxHeight = 30;

    /// <summary>Classifies <paramref name="sumDbPath"/> against the sumdb allowlist.</summary>
    public static GoSumDbPathKind Classify(string sumDbPath)
    {
        if (string.Equals(sumDbPath, "latest", StringComparison.Ordinal))
        {
            return GoSumDbPathKind.Latest;
        }

        bool isLookup = sumDbPath.StartsWith(LookupPrefix, StringComparison.Ordinal)
            && IsLookupShape(sumDbPath[LookupPrefix.Length..]);
        bool isTile = sumDbPath.StartsWith(TilePrefix, StringComparison.Ordinal) && IsCanonicalTilePath(sumDbPath);
        return isLookup ? GoSumDbPathKind.Lookup
            : isTile ? GoSumDbPathKind.Tile
            : GoSumDbPathKind.Unknown;
    }

    /// <summary>
    /// Whether <paramref name="moduleAtVersion"/> has the shape the checksum database accepts for a
    /// lookup (<c>modVerRE</c> in <c>golang.org/x/mod/sumdb/server.go</c>): one <c>@</c>, then a
    /// <c>v</c>-prefixed semantic version. The module part is still bang-encoded; the reservation
    /// check decodes it.
    /// </summary>
    public static bool IsLookupShape(string moduleAtVersion) => LookupRegex().IsMatch(moduleAtVersion);

    /// <summary>
    /// Whether <paramref name="path"/> is a tile path in the form
    /// <c>golang.org/x/mod/sumdb/tlog.ParseTilePath</c> accepts, which only accepts a path that
    /// round-trips through <c>Tile.Path()</c>: <c>tile/{H}/{L|data}/[x{NNN}/…]{NNN}[.p/{W}]</c>
    /// with <c>1 ≤ H ≤ 30</c>, <c>1 ≤ W &lt; 2^H</c>, decimal numbers without leading zeros, every
    /// index group three digits, and no leading <c>x000</c> group.
    /// </summary>
    public static bool IsCanonicalTilePath(string path)
    {
        string[] f = path.Split('/');
        if (f.Length < 4 || f[0] != "tile")
        {
            return false;
        }

        if (!TryParseCanonical(f[1], out int height) || height < 1 || height > MaxHeight)
        {
            return false;
        }

        if (f[2] != "data" && (!TryParseCanonical(f[2], out int level) || level > MaxLevel))
        {
            return false;
        }

        string[] index = f[3..];
        if (index.Length >= 2 && index[^2].EndsWith(".p", StringComparison.Ordinal))
        {
            // A partial tile names its width; a full-width tile is written without the suffix.
            if (!TryParseCanonical(index[^1], out int width) || width < 1 || width >= 1 << height)
            {
                return false;
            }

            index[^2] = index[^2][..^".p".Length];
            index = index[..^1];
        }

        return AreCanonicalIndexGroups(index);
    }

    // The NNN groups of a tile path: x{NNN} for every group but the last, three digits each, and no
    // leading zero group (Tile.Path() never writes one).
    private static bool AreCanonicalIndexGroups(string[] index)
    {
        if (index.Length is 0 or > MaxIndexGroups)
        {
            return false;
        }

        for (int i = 0; i < index.Length; i++)
        {
            bool isLast = i == index.Length - 1;
            string group = isLast ? index[i] : StripX(index[i]);
            if (group.Length != 3 || !group.All(char.IsAsciiDigit))
            {
                return false;
            }

            if (i == 0 && !isLast && int.Parse(group, System.Globalization.CultureInfo.InvariantCulture) % PathBase == 0)
            {
                return false;
            }
        }

        return true;
    }

    // An index group other than the last is written x{NNN}; anything else cannot be a group.
    private static string StripX(string group) =>
        group.Length == 4 && group[0] == 'x' ? group[1..] : string.Empty;

    // A decimal as fmt.Sprintf("%d") writes it: ASCII digits, no sign, no leading zero.
    private static bool TryParseCanonical(string s, out int value)
    {
        value = 0;
        if (s.Length is 0 or > 9 || !s.All(char.IsAsciiDigit) || (s.Length > 1 && s[0] == '0'))
        {
            return false;
        }

        value = int.Parse(s, System.Globalization.CultureInfo.InvariantCulture);
        return true;
    }

    [GeneratedRegex(@"\A[^@]+@v[0-9]+\.[0-9]+\.[0-9]+(-[^@]*)?(\+incompatible)?\z", RegexOptions.CultureInvariant)]
    private static partial Regex LookupRegex();
}
