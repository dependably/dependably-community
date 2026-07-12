using System.Text.Json;
using Dependably.Protocol;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Reads real SPDX license text straight out of the bundled
/// <c>spdx-license-texts-3.28.0.json</c> embedded resource (the same resource
/// <see cref="SpdxTextClassifier"/> and <c>SpdxLicenseSeeder</c> load), so tests exercise the
/// classifier against real corpus text instead of a hand-pasted approximation baked into a test
/// file.
/// </summary>
public static class SpdxTextFixtures
{
    private const string LicenseTextsResourceLeaf = "spdx-license-texts-3.28.0.json";

    private static readonly Lazy<IReadOnlyDictionary<string, string>> _texts = new(Load);

    /// <summary>Returns the bundled license text for <paramref name="spdxId"/>.</summary>
    public static string Text(string spdxId) => _texts.Value[spdxId];

    private static IReadOnlyDictionary<string, string> Load()
    {
        var assembly = typeof(SpdxTextClassifier).Assembly;
        string name = assembly.GetManifestResourceNames()
            .Single(n => n.EndsWith(LicenseTextsResourceLeaf, StringComparison.Ordinal));
        using var stream = assembly.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream);
        string json = reader.ReadToEnd();

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

    /// <summary>Returns every SPDX identifier flagged deprecated in the bundled license list.</summary>
    public static IReadOnlyList<string> DeprecatedIds() =>
        _deprecatedIds.Value;

    private static readonly Lazy<IReadOnlyList<string>> _deprecatedIds = new(LoadDeprecatedIds);

    private static IReadOnlyList<string> LoadDeprecatedIds()
    {
        const string licensesResourceLeaf = "spdx-licenses-3.28.0.json";
        var assembly = typeof(SpdxTextClassifier).Assembly;
        string name = assembly.GetManifestResourceNames()
            .Single(n => n.EndsWith(licensesResourceLeaf, StringComparison.Ordinal));
        using var stream = assembly.GetManifestResourceStream(name)!;
        using var reader = new StreamReader(stream);
        string json = reader.ReadToEnd();

        using var doc = JsonDocument.Parse(json);
        var arr = doc.RootElement.GetProperty("licenses");
        var ids = new List<string>();
        foreach (var el in arr.EnumerateArray())
        {
            if (el.TryGetProperty("isDeprecatedLicenseId", out var dep) && dep.GetBoolean()
                && el.TryGetProperty("licenseId", out var idEl))
            {
                string? id = idEl.GetString();
                if (!string.IsNullOrEmpty(id))
                {
                    ids.Add(id);
                }
            }
        }
        return ids;
    }
}
