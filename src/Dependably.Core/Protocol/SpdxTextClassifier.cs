using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Dependably.Protocol;

/// <summary>
/// Classifies raw LICENSE-file text against the bundled SPDX license-text corpus, returning the
/// best-matching canonical (non-deprecated) SPDX identifier or <c>null</c> when no match is
/// confident enough. This is the proxy-side signal for ecosystems whose package format carries no
/// declared license metadata (Go modules) — <see cref="LicenseExtractor.FromGoModuleZip"/> is the
/// only caller.
///
/// <para>The corpus (~10-15 MB of bundled license text, parsed once) materializes lazily on first
/// use — mirrors <see cref="LicenseNormalizer"/>'s process-lifetime lazy caching — so it never
/// costs anything on boot and only pays its parse cost on the first Go module zip fetch that needs
/// license classification.</para>
/// </summary>
public static class SpdxTextClassifier
{
    private const string LicensesResourceLeaf = "spdx-licenses-3.28.0.json";
    private const string LicenseTextsResourceLeaf = "spdx-license-texts-3.28.0.json";

    // Minimum Dice coefficient (2 * |intersection| / (|A| + |B|), over token multisets) required
    // to accept a fuzzy match. 0.95 tolerates line-wrap/whitespace/copyright-line drift between a
    // vendored LICENSE file and the canonical SPDX text without accepting a merely similar license.
    private const double DiceThreshold = 0.95;

    private static readonly Lazy<Corpus> _corpus =
        new(BuildCorpus, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>
    /// Classifies <paramref name="licenseText"/> against the bundled SPDX corpus. Returns the
    /// canonical (never-deprecated) SPDX identifier of the best match, or <c>null</c> when the
    /// input is empty or no corpus entry clears the confidence threshold.
    /// </summary>
    public static string? Classify(string licenseText)
    {
        if (string.IsNullOrWhiteSpace(licenseText))
        {
            return null;
        }

        string normalized = NormalizeText(licenseText);
        if (normalized.Length == 0)
        {
            return null;
        }

        var corpus = _corpus.Value;

        // Exact match: the overwhelming common case for an unmodified vendored LICENSE file.
        string hash = HashHex(normalized);
        if (corpus.ExactByHash.TryGetValue(hash, out string? exactId))
        {
            return exactId;
        }

        // Fuzzy fallback: token-multiset Dice similarity, linear over the corpus. 727 entries is
        // cheap enough to scan directly (this runs once per first-ever fetch of a given module
        // version, never on a cache hit) — no secondary index is worth the complexity here.
        var (tokens, total) = Tokenize(normalized);
        if (total == 0)
        {
            return null;
        }

        var (bestId, bestScore) = FindBestFuzzyMatch(tokens, total, corpus);
        return bestScore >= DiceThreshold ? bestId : null;
    }

    // Linear scan over the corpus for the highest-Dice-score entry. The cheap
    // maximum-possible-Dice bound (computed from the totals alone) skips entries whose length
    // differs too much from the input (roughly outside a ~10.5% band around it) before paying for
    // the O(tokens) intersection pass. Ties break on the lexicographically earlier SPDX id.
    private static (string? BestId, double BestScore) FindBestFuzzyMatch(
        Dictionary<string, int> tokens, int total, Corpus corpus)
    {
        string? bestId = null;
        double bestScore = 0;
        foreach (var entry in corpus.Entries)
        {
            if (entry.TotalTokens == 0)
            {
                continue;
            }

            double maxPossibleDice = 2.0 * Math.Min(total, entry.TotalTokens) / (total + entry.TotalTokens);
            if (maxPossibleDice < DiceThreshold)
            {
                continue;
            }

            int intersection = 0;
            foreach (var (token, countA) in tokens)
            {
                if (entry.Tokens.TryGetValue(token, out int countB))
                {
                    intersection += Math.Min(countA, countB);
                }
            }

            double dice = 2.0 * intersection / (total + entry.TotalTokens);
            bool better = dice > bestScore
                || (dice == bestScore && bestId is not null && string.CompareOrdinal(entry.Id, bestId) < 0);
            if (better)
            {
                bestScore = dice;
                bestId = entry.Id;
            }
        }

        return (bestId, bestScore);
    }

    // ── Normalization ────────────────────────────────────────────────────────

    // Shared by corpus construction and classification input so both sides of every comparison go
    // through the exact same transform: lowercase, drop copyright-attribution lines (their author
    // names are the one part of a license text that legitimately varies per vendor), collapse every
    // run of non-alphanumeric characters (whitespace, punctuation) to a single space, then trim.
    private static string NormalizeText(string text)
    {
        string lowered = text.ToLowerInvariant();

        var keptLines = new StringBuilder(lowered.Length);
        foreach (string rawLine in lowered.Split('\n'))
        {
            string trimmedLine = rawLine.Trim();
            if (trimmedLine.StartsWith("copyright", StringComparison.Ordinal)
                || trimmedLine.StartsWith("(c)", StringComparison.Ordinal)
                || trimmedLine.StartsWith('©'))
            {
                continue;
            }
            keptLines.Append(rawLine).Append('\n');
        }

        var collapsed = new StringBuilder(keptLines.Length);
        bool prevWasSpace = false;
        foreach (char c in keptLines.ToString())
        {
            if (char.IsLetterOrDigit(c))
            {
                collapsed.Append(c);
                prevWasSpace = false;
            }
            else if (!prevWasSpace)
            {
                collapsed.Append(' ');
                prevWasSpace = true;
            }
        }

        return collapsed.ToString().Trim();
    }

    private static string HashHex(string normalized) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalized)));

    private static (Dictionary<string, int> Tokens, int Total) Tokenize(string normalized)
    {
        var tokens = new Dictionary<string, int>(StringComparer.Ordinal);
        int total = 0;
        foreach (string token in normalized.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            tokens[token] = tokens.GetValueOrDefault(token) + 1;
            total++;
        }
        return (tokens, total);
    }

    // ── Corpus construction ─────────────────────────────────────────────────

    private static Corpus BuildCorpus()
    {
        var deprecatedIds = LoadDeprecatedIds();
        var texts = LoadLicenseTexts();

        // Group non-deprecated ids by their normalized-text hash. Deprecated ids are dropped
        // entirely at this step — they never become a corpus entry and so can never be returned
        // by Classify, regardless of how similar their text is to anything else.
        var normalizedById = new Dictionary<string, string>(StringComparer.Ordinal);
        var idsByHash = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var (id, text) in texts)
        {
            if (deprecatedIds.Contains(id))
            {
                continue;
            }

            string normalized = NormalizeText(text);
            if (normalized.Length == 0)
            {
                continue;
            }

            normalizedById[id] = normalized;
            string hash = HashHex(normalized);
            if (!idsByHash.TryGetValue(hash, out var group))
            {
                group = new List<string>();
                idsByHash[hash] = group;
            }
            group.Add(id);
        }

        var exactByHash = new Dictionary<string, string>(StringComparer.Ordinal);
        var entries = new List<CorpusEntry>(idsByHash.Count);
        foreach (var (hash, ids) in idsByHash)
        {
            // Deterministic tie-break within a duplicate-text group: shortest identifier wins,
            // then ordinal sort breaks any remaining tie. This is what makes GPL-2.0-only (not
            // GPL-2.0-or-later), MPL-2.0 (not MPL-2.0-no-copyleft-exception), CAL-1.0 (not
            // CAL-1.0-Combined-Work-Exception), and OFL-1.1 (not OFL-1.1-RFN /
            // OFL-1.1-no-RFN) the canonical id for their respective duplicate-text groups.
            string winner = ids.OrderBy(id => id.Length).ThenBy(id => id, StringComparer.Ordinal).First();
            exactByHash[hash] = winner;

            var (tokens, total) = Tokenize(normalizedById[winner]);
            entries.Add(new CorpusEntry(winner, tokens, total));
        }

        return new Corpus(exactByHash, entries);
    }

    private static HashSet<string> LoadDeprecatedIds()
    {
        string json = ReadEmbedded(LicensesResourceLeaf);
        using var doc = JsonDocument.Parse(json);
        var arr = doc.RootElement.GetProperty("licenses");

        var deprecated = new HashSet<string>(StringComparer.Ordinal);
        foreach (var el in arr.EnumerateArray())
        {
            if (!el.TryGetProperty("isDeprecatedLicenseId", out var dep) || !dep.GetBoolean())
            {
                continue;
            }

            string? id = el.TryGetProperty("licenseId", out var idEl) ? idEl.GetString() : null;
            if (!string.IsNullOrEmpty(id))
            {
                deprecated.Add(id);
            }
        }
        return deprecated;
    }

    private static Dictionary<string, string> LoadLicenseTexts()
    {
        string json = ReadEmbedded(LicenseTextsResourceLeaf);
        using var doc = JsonDocument.Parse(json);
        var texts = doc.RootElement.GetProperty("texts");

        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var prop in texts.EnumerateObject())
        {
            string? text = prop.Value.GetString();
            if (!string.IsNullOrEmpty(text))
            {
                map[prop.Name] = text;
            }
        }
        return map;
    }

    private static string ReadEmbedded(string leafName)
    {
        var assembly = typeof(SpdxTextClassifier).Assembly;
        string name = assembly.GetManifestResourceNames().SingleOrDefault(n => n.EndsWith(leafName, StringComparison.Ordinal))
            ?? throw new InvalidOperationException($"Embedded resource '{leafName}' not found.");
        using var stream = assembly.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private sealed record Corpus(
        Dictionary<string, string> ExactByHash,
        IReadOnlyList<CorpusEntry> Entries);

    private sealed record CorpusEntry(string Id, Dictionary<string, int> Tokens, int TotalTokens);
}
