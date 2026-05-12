namespace Dependably.Protocol;

/// <summary>
/// Parser for <c>sha256sums</c>-format sidecar files (#46): one line per artefact, of the
/// form <c>&lt;hex digest&gt;  &lt;filename&gt;</c>. Whitespace separator is one or more
/// spaces (the canonical GNU coreutils format uses two spaces). Empty lines and lines
/// beginning with <c>#</c> are ignored. Filenames may contain spaces — only the first
/// run of whitespace separates the digest from the rest of the line.
/// </summary>
public static class Sha256SumsParser
{
    public sealed record Entry(string Sha256Hex, string Filename);

    /// <summary>
    /// Parses the sidecar text into a map keyed by filename. Returns an empty map for an
    /// empty / whitespace-only input. Throws <see cref="InvalidDataException"/> on malformed
    /// lines (no separator, non-hex digest, wrong digest length).
    /// </summary>
    public static IReadOnlyDictionary<string, string> Parse(string text)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(text)) return map;

        var lineNo = 0;
        foreach (var rawLine in text.Split('\n'))
        {
            lineNo++;
            var line = rawLine.TrimEnd('\r');
            if (line.Length == 0) continue;
            if (line[0] == '#') continue;

            var sep = FirstWhitespaceRun(line, out var sepLen);
            if (sep < 0)
                throw new InvalidDataException(
                    $"sha256sums line {lineNo}: missing separator between digest and filename.");

            var digest = line[..sep];
            var filename = line[(sep + sepLen)..].TrimStart();

            ValidateDigest(digest, lineNo);
            if (filename.Length == 0)
                throw new InvalidDataException(
                    $"sha256sums line {lineNo}: filename is empty.");

            map[filename] = digest.ToLowerInvariant();
        }
        return map;
    }

    private static int FirstWhitespaceRun(string s, out int length)
    {
        for (var i = 0; i < s.Length; i++)
        {
            if (s[i] is ' ' or '\t')
            {
                var j = i;
                while (j < s.Length && s[j] is ' ' or '\t') j++;
                length = j - i;
                return i;
            }
        }
        length = 0;
        return -1;
    }

    private static void ValidateDigest(string digest, int lineNo)
    {
        if (digest.Length != 64)
            throw new InvalidDataException(
                $"sha256sums line {lineNo}: digest must be 64 hex characters (got {digest.Length}).");
        for (var i = 0; i < digest.Length; i++)
        {
            var c = digest[i];
            var ok = c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';
            if (!ok)
                throw new InvalidDataException(
                    $"sha256sums line {lineNo}: digest contains non-hex character '{c}'.");
        }
    }
}
