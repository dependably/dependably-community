using System.Text.Json;

namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// Serializes the identifiers <see cref="CycloneDxParser"/> and <see cref="SpdxParser"/> extract
/// into <c>sbom_components.additional_identifiers</c>' JSON array of <c>{"kind","value"}</c>
/// pairs — one shared implementation so the two front ends write byte-identical shapes for the
/// same asserted identifier kind, matching <c>hashes[]</c>'s existing <c>component_hashes</c>
/// convention on the same table. See <see cref="SbomIdentifierKinds"/> for the closed kind
/// vocabulary the export boundary recognizes.
///
/// <para><b>An over-long single VALUE is dropped, never truncated</b> (<see cref="AcceptValue"/>).
/// An identifier is not presentation text — a clipped CPE or SWHID is not a shorter version of
/// the right identifier, it is a DIFFERENT, wrong one, and the export boundary would then assert
/// that wrong value as the component's identity. <see cref="SbomProjectionLimits.MaxTextLength"/>
/// is generous relative to every real identifier syntax this codebase parses (a CPE 2.3 URI binding
/// tops out well under it), so this bound is a defensive ceiling against a hostile document, not
/// one any legitimate identifier should ever hit.</para>
///
/// <para><b>Overflow of the WHOLE array keeps as many entries as fit, never drops the set
/// whole.</b> <see cref="Serialize"/> is called from a context (<c>ReadAdditionalIdentifiers</c>)
/// that also decides <see cref="DependablyExportProperties.IdentifierStatus"/> — a component
/// asserting many identifiers (bulk SWHIDs/OmniBOR ids are exactly the intrinsic-identifier case
/// D13c exists to serve) that dropped the whole set on overflow would render with ZERO
/// identifiers and the export boundary would then emit a POSITIVE "no identifier is known to the
/// author" claim for a component whose source document asserted dozens. Keeping a strict prefix of
/// the asserted entries is not the same claim as recording every one of them, but it is never a
/// FALSE claim the way dropping-to-empty is — every kept entry is exactly what the document
/// asserted, and the identifier-status duty only fires when the kept set is genuinely empty.</para>
/// </summary>
internal static class SbomAdditionalIdentifiers
{
    /// <summary>
    /// The bound on one identifier VALUE. Matches <see cref="SbomProjectionLimits.MaxTextLength"/>
    /// without depending on it — that constant governs presentation fields this class's callers
    /// never touch, and the two ceilings coinciding is not a reason to couple them.
    /// </summary>
    private const int MaxValueLength = 400;

    /// <summary>
    /// The bound on the serialized identifiers array. Wider than <c>component_hashes</c>'s 2000
    /// (which this table's hash column also uses) on purpose: a component rarely asserts more
    /// than one or two hashes per algorithm, but SWHID/OmniBOR are INTRINSIC identifiers — one per
    /// revision of a merged tree is ordinary for the exact use case D13c names — so a handful of
    /// legitimate entries should not already be brushing the ceiling.
    /// </summary>
    private const int MaxJsonLength = 8000;

    /// <summary>
    /// An identifier value within <see cref="MaxValueLength"/>, or null when absent, blank, or too
    /// long — never truncated. See the class doc comment for why a clipped identifier is a
    /// different, wrong identifier rather than a shorter version of the right one.
    /// </summary>
    public static string? AcceptValue(string? raw) =>
        string.IsNullOrWhiteSpace(raw) || raw.Length > MaxValueLength ? null : raw;

    /// <summary>
    /// Serializes as many leading <paramref name="identifiers"/> entries as fit within
    /// <see cref="MaxJsonLength"/>, dropping only the entries beyond that point (never truncating
    /// a kept entry's own JSON) — see the class doc comment for why a partial array is the correct
    /// answer and a fully-dropped one is not.
    /// </summary>
    public static string? Serialize(IReadOnlyList<(string Kind, string Value)> identifiers)
    {
        if (identifiers.Count == 0)
        {
            return null;
        }

        var kept = new List<Dictionary<string, string>>(identifiers.Count);
        string? lastFittingJson = null;
        foreach (var (kind, value) in identifiers)
        {
            kept.Add(new Dictionary<string, string>(StringComparer.Ordinal) { ["kind"] = kind, ["value"] = value });
            string candidate = JsonSerializer.Serialize(kept);
            if (candidate.Length > MaxJsonLength)
            {
                kept.RemoveAt(kept.Count - 1);
                break;
            }

            lastFittingJson = candidate;
        }

        return lastFittingJson;
    }
}
