using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Dependably.Infrastructure;

namespace Dependably.Protocol.Provenance;

/// <summary>
/// Per-org trust anchor store for a supplier's CycloneDX author-signature key(s). Trust anchors
/// are stored as per-org rows in <c>signature_trust_anchor</c> (<c>ecosystem='sbom'</c>,
/// <c>anchor_kind='spki'</c>) — the same shape npm registry anchors use, but under the "sbom"
/// trust namespace rather than a proxyable ecosystem. Each row carries a base64 SPKI DER public
/// key for one keyId; <see cref="SbomSignatureVerifier"/> resolves all rows at verify time from
/// <see cref="IPerOrgTrustAnchorStore"/> and accepts any signature that verifies against a
/// pinned key.
///
/// The trust root is always configured out of band by the operator, resolved from the
/// supplier's own <c>GET /api/v1/sbom-signing-keys</c> response and pinned once — never fetched
/// automatically from the document being verified, which would defeat the check.
///
/// Unparseable entries are logged and skipped (the keyId simply has no anchor, so any signature
/// quoting it fails closed); an org with zero usable keys reports
/// <see cref="IsConfiguredForAsync"/> = false.
/// </summary>
public sealed class SbomSignatureKeyStore
{
    private readonly IPerOrgTrustAnchorStore _store;

    public SbomSignatureKeyStore(IPerOrgTrustAnchorStore store)
    {
        _store = store;
    }

    /// <summary>
    /// Always false — sbom trust anchors are per-org, not instance-wide. Mirrors the
    /// instance-level gate shape used by <see cref="IArtifactProvenanceVerifier"/> implementors
    /// for consistency; code that needs the per-org gate must call
    /// <see cref="IsConfiguredForAsync"/>.
    /// </summary>
    public static bool IsConfigured => false;

    /// <summary>
    /// Returns true when at least one sbom SPKI trust anchor is configured for
    /// <paramref name="orgId"/>. Fail-closed: an org with no anchors cannot enable signature
    /// verification.
    /// </summary>
    public Task<bool> IsConfiguredForAsync(string orgId, CancellationToken ct = default)
        => _store.IsConfiguredForAsync(orgId, "sbom", ct);

    /// <summary>
    /// Resolves the per-org SPKI dictionary keyed by keyId for <paramref name="orgId"/>.
    /// Entries that fail base64 or ECDSA parse are logged and omitted. Returns an empty
    /// dictionary when no anchors are configured.
    /// </summary>
    public Task<IReadOnlyDictionary<string, byte[]>> GetSpkiMapAsync(
        string orgId, CancellationToken ct = default)
        => _store.GetSbomKeysAsync(orgId, ct);

    // Parses a list of TrustAnchorMaterial rows into a keyId->SPKI-bytes map. Skips entries with
    // missing/unparseable material (logged + fail-closed). The map key is the anchor's OWN
    // key_id column — set at insert time by DeriveKeyId below — not re-derived here, so an
    // operator override (a caller-supplied keyId taking precedence over the derived one, per
    // TrustAnchorController.PrepareAnchorMaterial) is honoured.
    internal static IReadOnlyDictionary<string, byte[]> BuildSpkiMap(
        IReadOnlyList<TrustAnchorMaterial> anchors, ILogger logger)
    {
        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var anchor in anchors)
        {
            // Only ("sbom","spki") is registered in TrustAnchorPairs today, so the insert gate
            // already refuses any other anchor_kind under this ecosystem and TryParseSpki fails
            // closed on one regardless — this is defense in depth against a future sbom-namespace
            // pair landing in this map unparsed, the same reason TrustAnchorPairs.Registered's own
            // doc comment gives for filtering on anchor_kind, not ecosystem alone.
            if (!string.Equals(anchor.AnchorKind, "spki", StringComparison.Ordinal))
            {
                continue;
            }

            string keyId = anchor.KeyId ?? "";
            string material = anchor.Material ?? "";
            if (string.IsNullOrWhiteSpace(keyId) || string.IsNullOrWhiteSpace(material))
            {
                continue;
            }

            if (!TryParseSpki(material.Trim(), out byte[]? spki, logger, keyId))
            {
                continue;
            }

            result[keyId] = spki!;
        }

        return result;
    }

    /// <summary>
    /// Derives the key_id an sbom SPKI trust anchor is stored under: the SHA-256 fingerprint of
    /// the DER SubjectPublicKeyInfo, lower-case hex — the same spelling
    /// <c>SbomSigningKeyRepository</c> uses for a key this instance mints, so a supplier's pinned
    /// anchor and the keyId a real signature carries are directly comparable. Returns null when
    /// the material does not parse as a base64 ECDSA SPKI key.
    /// </summary>
    public static string? DeriveKeyId(string material, ILogger logger)
    {
        return TryParseSpki(material, out byte[]? spki, logger, keyId: null)
            ? Convert.ToHexString(SHA256.HashData(spki!)).ToLowerInvariant()
            : null;
    }

    // Parses a single base64 SPKI DER entry. Returns false and logs a warning on failure.
    // Validation now (at load time from the anchor store, or at insert time from the controller)
    // means a typo surfaces as a missing anchor (fail-closed) rather than a per-request crypto
    // throw. keyId is used only for the log message and may be null (e.g. from DeriveKeyId,
    // called before a keyId exists).
    [SuppressMessage("Major Bug", "S1168:Empty arrays and collections should be returned instead of null",
        Justification = "Null output is the intended absent-key sentinel on parse failure.")]
    private static bool TryParseSpki(string b64, out byte[]? spki, ILogger logger, string? keyId)
    {
        spki = null;
        try
        {
            byte[] bytes = Convert.FromBase64String(b64);
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(bytes, out _);
            spki = bytes;
            return true;
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            logger.LogWarning(
                "sbom trust anchor for keyId {KeyId} could not be parsed as a base64 ECDSA SPKI "
                + "key ({ExceptionType}); signatures quoting this keyId fail closed.",
                keyId ?? "(unresolved)", ex.GetType().Name);
            return false;
        }
    }
}
