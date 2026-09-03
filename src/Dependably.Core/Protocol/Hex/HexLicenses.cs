using System.Text.RegularExpressions;

namespace Dependably.Protocol.Hex;

/// <summary>
/// The licence signal of a Hex package tarball for the proxy first-fetch path: the
/// <c>licenses</c> list of <c>metadata.config</c>, which Mix and Rebar3 fill with SPDX
/// identifiers. Read with a narrow pattern over the term text rather than a full parse, because
/// only this one key is wanted and the extractor must never throw on the first-fetch path.
/// <para>Owns the stream, like every other extractor <see cref="LicenseExtractor"/> exposes.</para>
/// </summary>
public static partial class HexLicenses
{
    [GeneratedRegex(@"\{\s*<<""licenses"">>\s*,\s*\[(?<items>[^\]]*)\]\s*\}", RegexOptions.Singleline)]
    private static partial Regex LicensesTuple();

    [GeneratedRegex(@"<<""(?<v>[^""]*)"">>")]
    private static partial Regex Binary();

    public static LicenseExtractor.ExtractedMetadata FromTarball(Stream tarball)
    {
        try
        {
            using var ms = new MemoryStream();
            tarball.CopyTo(ms);
            var parsed = HexTarball.Parse(ms.ToArray(), maxContentsBytes: ArchiveDecompressLimits.MaxDecompressedBytes);
            return FromMetadataText(parsed.MetadataText);
        }
        catch (Exception ex) when (ex is HexProtocolException or IOException or ArgumentException)
        {
            return LicenseExtractor.ExtractedMetadata.Empty;
        }
        finally
        {
            tarball.Dispose();
        }
    }

    /// <summary>The SPDX identifiers named by a <c>metadata.config</c> body; empty when it names none.</summary>
    public static LicenseExtractor.ExtractedMetadata FromMetadataText(string metadataText)
    {
        var match = LicensesTuple().Match(metadataText);
        if (!match.Success)
        {
            return LicenseExtractor.ExtractedMetadata.Empty;
        }

        var ids = Binary().Matches(match.Groups["items"].Value)
            .Select(m => m.Groups["v"].Value.Trim())
            .Where(v => v.Length > 0 && LicenseExtractor.IsPlausibleSpdx(v))
            .Distinct(StringComparer.Ordinal)
            .ToList();
        return ids.Count == 0 ? LicenseExtractor.ExtractedMetadata.Empty : new LicenseExtractor.ExtractedMetadata(ids, null);
    }
}
