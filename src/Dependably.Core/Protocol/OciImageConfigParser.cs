using System.Text.Json;

namespace Dependably.Protocol;

/// <summary>
/// Reads the SPDX license expression an OCI image declares in its config blob. The OCI image
/// spec places freeform annotations under <c>config.Labels</c> (a string→string map); the
/// conventional license key is <c>org.opencontainers.image.licenses</c>, whose value is an
/// SPDX expression (e.g. <c>MIT</c> or <c>GPL-3.0-only AND MIT</c>).
///
/// Property names are matched case-sensitively per the OCI image spec: the config object's
/// <c>config</c> field and its <c>Labels</c> map are both spelled exactly as here. Parsing is
/// best-effort — malformed JSON, a non-object root, a missing config/Labels, an absent label,
/// or a value that fails the SPDX shape check all yield <c>null</c>. This method never throws.
/// </summary>
public static class OciImageConfigParser
{
    private const string LicensesLabel = "org.opencontainers.image.licenses";

    /// <summary>
    /// Returns the trimmed, shape-validated SPDX expression from the config's
    /// <c>org.opencontainers.image.licenses</c> label, or <c>null</c> when it is absent,
    /// implausible, or the bytes are not a valid image config document.
    /// </summary>
    public static string? ParseLicensesLabel(byte[] configBytes)
    {
        try
        {
            using var doc = JsonDocument.Parse(configBytes);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("config", out var config) ||
                config.ValueKind != JsonValueKind.Object ||
                !config.TryGetProperty("Labels", out var labels) ||
                labels.ValueKind != JsonValueKind.Object ||
                !labels.TryGetProperty(LicensesLabel, out var license) ||
                license.ValueKind != JsonValueKind.String)
            {
                return null;
            }

            string? value = license.GetString();
            if (value is null)
            {
                return null;
            }

            string trimmed = value.Trim();
            return LicenseExtractor.IsPlausibleSpdx(trimmed) ? trimmed : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
