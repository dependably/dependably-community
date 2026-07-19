using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;

namespace Dependably.Protocol;

/// <summary>
/// Resolves a raw license leaf string (one SPDX identifier, or a name/alias variant a package
/// manifest declared) to its canonical SPDX identifier. Registered as a DI singleton — the
/// <c>spdx_license</c> reference table + alias overlay are loaded once, lazily, on first use and
/// cached for the process lifetime (reseeding only ever happens at boot before traffic, so no
/// runtime invalidation is needed). <see cref="Normalize"/> never queries the database.
/// </summary>
public sealed class LicenseNormalizer
{
    private const string AliasResourceLeaf = "spdx-license-aliases.json";
    private const string SpdxListVersionKey = "spdx_list_version";
    private const string WithSeparator = " WITH ";

    private readonly IMetadataStore _db;
    private readonly ILogger<LicenseNormalizer> _logger;
    private readonly Lazy<Maps> _maps;

    public LicenseNormalizer(IMetadataStore db, ILogger<LicenseNormalizer> logger)
    {
        _db = db;
        _logger = logger;
        _maps = new Lazy<Maps>(BuildMaps, LazyThreadSafetyMode.ExecutionAndPublication);
    }

    /// <summary>
    /// Resolves <paramref name="rawLeaf"/> to a canonical SPDX identifier. A <c>"base WITH
    /// exception"</c> leaf normalizes only the base id and re-appends the exception verbatim.
    /// Unknown/custom strings pass through unchanged (trimmed) — this never throws and never
    /// rejects input, matching today's tolerant behavior for licenses outside the bundled list.
    /// </summary>
    public string Normalize(string rawLeaf)
    {
        if (string.IsNullOrWhiteSpace(rawLeaf))
        {
            return string.Empty;
        }

        string trimmed = rawLeaf.Trim();

        int withIndex = trimmed.IndexOf(WithSeparator, StringComparison.OrdinalIgnoreCase);
        if (withIndex > 0 && withIndex + WithSeparator.Length < trimmed.Length)
        {
            string baseId = trimmed[..withIndex];
            string exceptionId = trimmed[(withIndex + WithSeparator.Length)..].Trim();
            return $"{NormalizeSingle(baseId)} WITH {exceptionId}";
        }

        return NormalizeSingle(trimmed);
    }

    private string NormalizeSingle(string rawId)
    {
        string trimmed = rawId.Trim();
        if (trimmed.Length == 0)
        {
            return trimmed;
        }

        // Step 1: strip a trailing '+' (or-later suffix) for lookup purposes only — the
        // fallback below returns the original trimmed form, '+' included.
        string lookupKey = trimmed.EndsWith('+') ? trimmed[..^1] : trimmed;

        var maps = _maps.Value;

        // Step 2: exact identifier hit (case-insensitive) — returns the canonical-cased id.
        if (maps.ByIdentifier.TryGetValue(lookupKey, out string? byIdentifier))
        {
            return byIdentifier;
        }

        // Step 3: normalized-name key against spdx_license.name.
        string normalizedName = LicenseExtractor.NormalizeName(lookupKey);
        if (maps.ByName.TryGetValue(normalizedName, out string? byName))
        {
            return byName;
        }

        // Step 4: curated alias overlay.
        if (maps.ByAlias.TryGetValue(normalizedName, out string? byAlias))
        {
            return byAlias;
        }

        // Step 5: unknown/custom — pass through unchanged.
        return trimmed;
    }

    private Maps BuildMaps() => LoadMapsAsync().GetAwaiter().GetResult();

    private async Task<Maps> LoadMapsAsync()
    {
        await using var conn = await _db.OpenAsync();

        // xtenant: spdx_license is a global reference table, no org scoping
        var rows = await conn.QueryAsync<LicenseRow>(
            "SELECT identifier AS Identifier, name AS Name, is_deprecated AS IsDeprecated FROM spdx_license");

        string? listVersion = await conn.ExecuteScalarAsync<string?>(
            "SELECT value FROM instance_settings WHERE key = @key",
            new { key = SpdxListVersionKey });

        var byIdentifier = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var byNameRanked = new Dictionary<string, (string Id, bool Deprecated)>(StringComparer.Ordinal);

        foreach (var row in rows)
        {
            byIdentifier.TryAdd(row.Identifier, row.Identifier);

            string nameKey = LicenseExtractor.NormalizeName(row.Name);
            if (!byNameRanked.TryGetValue(nameKey, out var existing))
            {
                // First occurrence for this name — deterministic first-wins when a later
                // duplicate has the same deprecation status.
                byNameRanked[nameKey] = (row.Identifier, row.IsDeprecated);
            }
            else if (existing.Deprecated && !row.IsDeprecated)
            {
                // Name-collision guard: a non-deprecated id always wins over a deprecated one
                // sharing the same name (e.g. "GNU General Public License v3.0 only" maps to
                // both the deprecated GPL-3.0 and the current GPL-3.0-only).
                byNameRanked[nameKey] = (row.Identifier, row.IsDeprecated);
            }
        }

        var byName = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var kv in byNameRanked)
        {
            byName[kv.Key] = kv.Value.Id;
        }

        var byAlias = LoadAliasOverlay();

        _logger.LogInformation(
            "LicenseNormalizer maps built: {IdentifierCount} identifiers, {NameCount} names, " +
            "{AliasCount} aliases (spdx_list_version={Version}).",
            byIdentifier.Count, byName.Count, byAlias.Count, listVersion ?? "(unknown)");

        return new Maps(byIdentifier, byName, byAlias);
    }

    // Mirrors SpdxLicenseSeeder.LoadCopyleftOverlay: a hand-curated embedded JSON overlay keyed
    // by canonical SPDX id, whose values are normalized to lookup keys the same way spdx_license
    // rows are (LicenseExtractor.NormalizeName), so one algorithm governs every name/alias key.
    private static Dictionary<string, string> LoadAliasOverlay()
    {
        string json = ReadEmbedded(AliasResourceLeaf);
        using var doc = JsonDocument.Parse(json);
        var aliases = doc.RootElement.GetProperty("aliases");

        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var canonical in aliases.EnumerateObject())
        {
            string canonicalId = canonical.Name;
            foreach (var variantEl in canonical.Value.EnumerateArray())
            {
                string? variant = variantEl.GetString();
                if (string.IsNullOrEmpty(variant))
                {
                    continue;
                }

                string key = LicenseExtractor.NormalizeName(variant);
                if (map.TryGetValue(key, out string? existingId)
                    && !existingId.Equals(canonicalId, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        $"License alias '{variant}' normalizes to a key already mapped to a " +
                        $"different canonical id ('{existingId}' vs '{canonicalId}').");
                }

                map[key] = canonicalId;
            }
        }
        return map;
    }

    private static string ReadEmbedded(string leafName)
    {
        var assembly = typeof(LicenseNormalizer).Assembly;
        string name = assembly.GetManifestResourceNames().SingleOrDefault(n => n.EndsWith(leafName, StringComparison.Ordinal))
            ?? throw new InvalidOperationException($"Embedded resource '{leafName}' not found.");
        using var stream = assembly.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private sealed record Maps(
        Dictionary<string, string> ByIdentifier,
        Dictionary<string, string> ByName,
        Dictionary<string, string> ByAlias);

    // A plain settable-property POCO (not a positional record) so Dapper maps rows via property
    // assignment — which coerces the SQLite INTEGER 0/1 storage class to bool — rather than
    // trying to match a constructor parameter list by exact type.
    [SuppressMessage("Minor Code Smell", "S3459:Unassigned members should be removed", Justification = "Dapper sets this prop by reflection; not statically visible as assigned.")]
    [SuppressMessage("Major Code Smell", "S1144:Unused private types or members should be removed", Justification = "Dapper sets this prop's setter by reflection; not statically visible as used.")]
    private sealed class LicenseRow
    {
        public string Identifier { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public bool IsDeprecated { get; set; }
    }
}
