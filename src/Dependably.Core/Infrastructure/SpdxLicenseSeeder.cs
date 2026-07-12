using System.Data.Common;
using System.Text.Json;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Populates the <c>spdx_license</c> reference table from the embedded SPDX license-list-data
/// JSON (<c>spdx-licenses-{version}.json</c>) joined with a hand-curated copyleft overlay
/// (<c>spdx-copyleft.json</c>). SPDX itself does not publish copyleft strength.
///
/// Invoked from <see cref="SchemaInitializer"/> on every boot. The value stored in
/// <c>instance_settings.spdx_list_version</c> gates the work: it is the SPDX list version
/// composed with a local seed revision (<c>{licenseListVersion}+r{SeedRevision}</c>), so both
/// an upstream list bump and a local revision bump trigger a reseed. Matching value is a no-op;
/// mismatch triggers DELETE+INSERT in a single transaction. ~700 rows — bulk replacement is
/// simpler than UPSERT + orphan reconciliation when SPDX retires an ID. The multi-MB bundled
/// license-text resource is parsed only on the reseed path, never on a no-op boot.
///
/// This must NOT be wired through <see cref="FirstBootService"/>: that service only runs on
/// empty installs, but the SPDX list needs to refresh on every upgrade.
/// </summary>
public sealed class SpdxLicenseSeeder
{
    private const string VersionKey = "spdx_list_version";
    private const string LicensesResourceLeaf = "spdx-licenses-3.28.0.json";
    private const string LicenseTextsResourceLeaf = "spdx-license-texts-3.28.0.json";
    private const string CopyleftResourceLeaf = "spdx-copyleft.json";

    /// <summary>
    /// Local seed revision, bumped whenever the seeder writes a new column or otherwise
    /// changes the shape of a row without the upstream SPDX list version changing. The stored
    /// gate value is <c>{licenseListVersion}+r{SeedRevision}</c>, so bumping this forces a
    /// DELETE+INSERT reseed on databases already at the same SPDX list version — required to
    /// backfill columns like <c>license_text</c> that a plain list-version match would skip.
    /// Revision "2" introduces bundled license texts.
    /// </summary>
    private const string SeedRevision = "2";

    private static readonly HashSet<string> ValidCopyleft = new(StringComparer.Ordinal)
    {
        "permissive","weak-copyleft","strong-copyleft","network-copyleft","public-domain","unclassified"
    };

    private readonly ILogger<SpdxLicenseSeeder> _logger;

    public SpdxLicenseSeeder(ILogger<SpdxLicenseSeeder> logger)
    {
        _logger = logger;
    }

    public async Task RunAsync(DbConnection conn, CancellationToken ct = default)
    {
        var (licenses, embeddedVersion) = LoadLicensesFromResource();
        var copyleftByIdentifier = LoadCopyleftOverlay();

        // Gate on the SPDX list version composed with the local seed revision, so a revision
        // bump reseeds even when the upstream list version is unchanged (backfills new columns).
        string gateValue = $"{embeddedVersion}+r{SeedRevision}";

        string? storedVersion = await conn.ExecuteScalarAsync<string?>(
            "SELECT value FROM instance_settings WHERE key = @key",
            new { key = VersionKey });

        if (string.Equals(storedVersion, gateValue, StringComparison.Ordinal))
        {
            _logger.LogInformation("spdx_license already at version {Version}, skipping seed.", gateValue);
            return;
        }

        // Only the multi-MB license-text bundle is parsed on the reseed path — never eagerly
        // on a no-op boot, which returned above.
        var textsByIdentifier = LoadLicenseTexts();

        _logger.LogInformation(
            "Seeding spdx_license: {Stored} -> {Embedded} ({Count} licenses, {OverlayCount} copyleft mappings, {TextCount} texts).",
            storedVersion ?? "(empty)", gateValue, licenses.Count, copyleftByIdentifier.Count, textsByIdentifier.Count);

        // Note: SQL keywords are multi-token because Dapper's CommandType inference treats
        // single-word strings as stored-procedure names — see Dapper's InferCommandType.
        await conn.ExecuteAsync("BEGIN TRANSACTION");
        try
        {
            await conn.ExecuteAsync("DELETE FROM spdx_license");

            foreach (var lic in licenses)
            {
                copyleftByIdentifier.TryGetValue(lic.Identifier, out string? copyleft);
                copyleft ??= "unclassified";
                await conn.ExecuteAsync(
                    """
                    INSERT INTO spdx_license
                      (identifier, name, is_osi_approved, is_fsf_libre, is_deprecated, reference_url, copyleft, license_text)
                    VALUES (@identifier, @name, @osi, @fsf, @deprecated, @url, @copyleft, @licenseText)
                    """,
                    new
                    {
                        identifier = lic.Identifier,
                        name = lic.Name,
                        osi = lic.IsOsiApproved ? 1 : 0,
                        fsf = lic.IsFsfLibre ? 1 : 0,
                        deprecated = lic.IsDeprecated ? 1 : 0,
                        url = lic.ReferenceUrl,
                        copyleft,
                        licenseText = textsByIdentifier.GetValueOrDefault(lic.Identifier)
                    });
            }

            await conn.ExecuteAsync(
                """
                INSERT INTO instance_settings (key, value) VALUES (@key, @value)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                new { key = VersionKey, value = gateValue });

            await conn.ExecuteAsync("COMMIT TRANSACTION");
        }
        catch
        {
            await conn.ExecuteAsync("ROLLBACK TRANSACTION");
            throw;
        }

        _logger.LogInformation("spdx_license seeded to version {Version}.", gateValue);
    }

    private static (List<LicenseRow> Rows, string Version) LoadLicensesFromResource()
    {
        string json = ReadEmbedded(LicensesResourceLeaf);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        string version = root.GetProperty("licenseListVersion").GetString()
            ?? throw new InvalidOperationException("SPDX JSON missing 'licenseListVersion'.");

        var arr = root.GetProperty("licenses");
        var rows = new List<LicenseRow>(arr.GetArrayLength());
        foreach (var el in arr.EnumerateArray())
        {
            string? id = el.GetProperty("licenseId").GetString();
            string? name = el.GetProperty("name").GetString();
            if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(name))
            {
                continue;
            }

            rows.Add(new LicenseRow(
                Identifier: id,
                Name: name,
                IsOsiApproved: el.TryGetProperty("isOsiApproved", out var osi) && osi.GetBoolean(),
                IsFsfLibre: el.TryGetProperty("isFsfLibre", out var fsf) && fsf.GetBoolean(),
                IsDeprecated: el.TryGetProperty("isDeprecatedLicenseId", out var dep) && dep.GetBoolean(),
                ReferenceUrl: el.TryGetProperty("reference", out var refEl) ? refEl.GetString() : null));
        }
        return (rows, version);
    }

    private static Dictionary<string, string> LoadCopyleftOverlay()
    {
        string json = ReadEmbedded(CopyleftResourceLeaf);
        using var doc = JsonDocument.Parse(json);
        var categories = doc.RootElement.GetProperty("categories");
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var cat in categories.EnumerateObject())
        {
            if (!ValidCopyleft.Contains(cat.Name))
            {
                throw new InvalidOperationException(
                    $"Copyleft overlay contains unknown category '{cat.Name}'. " +
                    $"Allowed: {string.Join(", ", ValidCopyleft)}.");
            }

            foreach (var idEl in cat.Value.EnumerateArray())
            {
                string? id = idEl.GetString();
                if (string.IsNullOrEmpty(id))
                {
                    continue;
                }

                if (map.ContainsKey(id))
                {
                    throw new InvalidOperationException(
                        $"SPDX identifier '{id}' appears in multiple copyleft categories.");
                }

                map[id] = cat.Name;
            }
        }
        return map;
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
        var assembly = typeof(SpdxLicenseSeeder).Assembly;
        string name = assembly.GetManifestResourceNames().SingleOrDefault(n => n.EndsWith(leafName, StringComparison.Ordinal))
            ?? throw new InvalidOperationException($"Embedded resource '{leafName}' not found.");
        using var stream = assembly.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private sealed record LicenseRow(
        string Identifier,
        string Name,
        bool IsOsiApproved,
        bool IsFsfLibre,
        bool IsDeprecated,
        string? ReferenceUrl);
}
