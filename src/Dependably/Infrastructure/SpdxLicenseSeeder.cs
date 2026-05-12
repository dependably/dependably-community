using System.Data.Common;
using System.Text.Json;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Populates the <c>spdx_license</c> reference table from the embedded SPDX license-list-data
/// JSON (<c>spdx-licenses-{version}.json</c>) joined with a hand-curated copyleft overlay
/// (<c>spdx-copyleft.json</c>). SPDX itself does not publish copyleft strength.
///
/// Invoked from <see cref="SchemaInitializer"/> on every boot. The version stored in
/// <c>instance_settings.spdx_list_version</c> gates the work: matching version is a no-op;
/// mismatched version triggers TRUNCATE+INSERT in a single transaction. ~700 rows — bulk
/// replacement is simpler than UPSERT + orphan reconciliation when SPDX retires an ID.
///
/// This must NOT be wired through <see cref="FirstBootService"/>: that service only runs on
/// empty installs, but the SPDX list needs to refresh on every upgrade.
/// </summary>
public sealed class SpdxLicenseSeeder
{
    private const string VersionKey = "spdx_list_version";
    private const string LicensesResourceLeaf = "spdx-licenses-3.28.0.json";
    private const string CopyleftResourceLeaf = "spdx-copyleft.json";

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

        var storedVersion = await conn.ExecuteScalarAsync<string?>(
            "SELECT value FROM instance_settings WHERE key = @key",
            new { key = VersionKey });

        if (string.Equals(storedVersion, embeddedVersion, StringComparison.Ordinal))
        {
            _logger.LogInformation("spdx_license already at version {Version}, skipping seed.", embeddedVersion);
            return;
        }

        _logger.LogInformation(
            "Seeding spdx_license: {Stored} -> {Embedded} ({Count} licenses, {OverlayCount} copyleft mappings).",
            storedVersion ?? "(empty)", embeddedVersion, licenses.Count, copyleftByIdentifier.Count);

        // Note: SQL keywords are multi-token because Dapper's CommandType inference treats
        // single-word strings as stored-procedure names — see Dapper's InferCommandType.
        await conn.ExecuteAsync("BEGIN TRANSACTION");
        try
        {
            await conn.ExecuteAsync("DELETE FROM spdx_license");

            foreach (var lic in licenses)
            {
                copyleftByIdentifier.TryGetValue(lic.Identifier, out var copyleft);
                copyleft ??= "unclassified";
                await conn.ExecuteAsync(
                    """
                    INSERT INTO spdx_license
                      (identifier, name, is_osi_approved, is_fsf_libre, is_deprecated, reference_url, copyleft)
                    VALUES (@identifier, @name, @osi, @fsf, @deprecated, @url, @copyleft)
                    """,
                    new
                    {
                        identifier = lic.Identifier,
                        name = lic.Name,
                        osi = lic.IsOsiApproved ? 1 : 0,
                        fsf = lic.IsFsfLibre ? 1 : 0,
                        deprecated = lic.IsDeprecated ? 1 : 0,
                        url = lic.ReferenceUrl,
                        copyleft
                    });
            }

            await conn.ExecuteAsync(
                """
                INSERT INTO instance_settings (key, value) VALUES (@key, @value)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                new { key = VersionKey, value = embeddedVersion });

            await conn.ExecuteAsync("COMMIT TRANSACTION");
        }
        catch
        {
            await conn.ExecuteAsync("ROLLBACK TRANSACTION");
            throw;
        }

        _logger.LogInformation("spdx_license seeded to version {Version}.", embeddedVersion);
    }

    private static (List<LicenseRow> Rows, string Version) LoadLicensesFromResource()
    {
        var json = ReadEmbedded(LicensesResourceLeaf);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var version = root.GetProperty("licenseListVersion").GetString()
            ?? throw new InvalidOperationException("SPDX JSON missing 'licenseListVersion'.");

        var arr = root.GetProperty("licenses");
        var rows = new List<LicenseRow>(arr.GetArrayLength());
        foreach (var el in arr.EnumerateArray())
        {
            var id = el.GetProperty("licenseId").GetString();
            var name = el.GetProperty("name").GetString();
            if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(name)) continue;

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
        var json = ReadEmbedded(CopyleftResourceLeaf);
        using var doc = JsonDocument.Parse(json);
        var categories = doc.RootElement.GetProperty("categories");
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var cat in categories.EnumerateObject())
        {
            if (!ValidCopyleft.Contains(cat.Name))
                throw new InvalidOperationException(
                    $"Copyleft overlay contains unknown category '{cat.Name}'. " +
                    $"Allowed: {string.Join(", ", ValidCopyleft)}.");

            foreach (var idEl in cat.Value.EnumerateArray())
            {
                var id = idEl.GetString();
                if (string.IsNullOrEmpty(id)) continue;
                if (map.ContainsKey(id))
                    throw new InvalidOperationException(
                        $"SPDX identifier '{id}' appears in multiple copyleft categories.");
                map[id] = cat.Name;
            }
        }
        return map;
    }

    private static string ReadEmbedded(string leafName)
    {
        var assembly = typeof(SpdxLicenseSeeder).Assembly;
        var name = assembly.GetManifestResourceNames().SingleOrDefault(n => n.EndsWith(leafName, StringComparison.Ordinal))
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
