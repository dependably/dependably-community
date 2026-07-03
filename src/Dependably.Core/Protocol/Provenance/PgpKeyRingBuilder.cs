using System.Text;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Dependably.Protocol.Provenance;

/// <summary>
/// Shared helper that parses ASCII-armored or base64-encoded OpenPGP public key material
/// into a <see cref="PgpPublicKeyRingBundle"/>. Used by RPM and Maven verifiers so the
/// parse logic lives in one place. Per-entry try/skip error isolation is preserved: a
/// corrupt key in a multi-key paste does not prevent the remaining keys from being loaded.
/// </summary>
public static class PgpKeyRingBuilder
{
    /// <summary>
    /// Parses a single ASCII-armored PGP public key block (or base64 blob) into a
    /// <see cref="PgpPublicKeyRingBundle"/>.
    ///
    /// Returns null when <paramref name="material"/> is null, empty, or cannot be parsed.
    /// Parse failures are logged at Warning level; the caller decides whether a null result
    /// should fail-closed or be treated as unconfigured.
    /// </summary>
    public static PgpPublicKeyRingBundle? TryParse(
        string? material,
        ILogger logger,
        string logContext)
    {
        if (string.IsNullOrWhiteSpace(material))
        {
            return null;
        }

        try
        {
            byte[] armored;
            if (material.Contains("-----BEGIN PGP", StringComparison.Ordinal))
            {
                armored = Encoding.UTF8.GetBytes(material);
            }
            else
            {
                // Assume base64-encoded raw binary key ring.
                armored = Convert.FromBase64String(material.Trim());
            }

            using var keyIn = PgpUtilities.GetDecoderStream(new MemoryStream(armored));
            return new PgpPublicKeyRingBundle(keyIn);
        }
        catch (Exception ex)
        {
            logger.LogWarning(
                "{LogContext}: OpenPGP public key material could not be parsed ({ExceptionType}); " +
                "this anchor will not contribute to the trust ring.",
                logContext, ex.GetType().Name);
            return null;
        }
    }

    /// <summary>
    /// Merges a sequence of <see cref="TrustAnchorMaterial"/> rows (all <c>anchor_kind='pgp'</c>)
    /// into a single <see cref="PgpPublicKeyRingBundle"/> by concatenating the individual rings.
    /// Rows that fail to parse are skipped (per-entry isolation), and a Warning is logged.
    /// Returns null when no row yields a valid key ring.
    /// </summary>
    public static PgpPublicKeyRingBundle? BuildFromAnchors(
        IReadOnlyList<Infrastructure.TrustAnchorMaterial> anchors,
        ILogger logger,
        string ecosystem)
    {
        var rings = new List<PgpPublicKeyRing>();

        foreach (var anchor in anchors)
        {
            if (anchor.AnchorKind != "pgp")
            {
                continue;
            }

            var bundle = TryParse(anchor.Material, logger, $"{ecosystem}/anchor:{anchor.Id}");
            if (bundle is null)
            {
                continue;
            }

            foreach (var ring in bundle.GetKeyRings())
            {
                rings.Add(ring);
            }
        }

        return rings.Count == 0 ? null : new PgpPublicKeyRingBundle(rings);
    }

    /// <summary>
    /// Returns the hex fingerprint of the first public key in <paramref name="bundle"/>,
    /// or null when the bundle contains no keys. Used to derive the <c>key_id</c> column
    /// value at anchor-insert time.
    /// </summary>
    public static string? FirstFingerprint(PgpPublicKeyRingBundle bundle)
    {
        return bundle.GetKeyRings()
            .SelectMany(ring => ring.GetPublicKeys())
            .Select(key => Convert.ToHexString(key.GetFingerprint()).ToLowerInvariant())
            .FirstOrDefault();
    }
}
