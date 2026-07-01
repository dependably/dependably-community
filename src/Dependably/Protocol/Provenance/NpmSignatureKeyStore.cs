using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Dependably.Infrastructure;

namespace Dependably.Protocol.Provenance;

/// <summary>
/// Per-org trust anchor store for npm registry signatures. Trust anchors are stored
/// as per-org rows in <c>signature_trust_anchor</c> (<c>ecosystem='npm'</c>,
/// <c>anchor_kind='spki'</c>). Each row carries a base64 SPKI DER public key for one
/// keyid; the verifier resolves all rows at request time from
/// <see cref="IPerOrgTrustAnchorStore"/> and accepts any signature that verifies
/// against a pinned key.
///
/// The trust root is always configured out of band by the operator — never the key
/// the upstream registry serves at <c>/-/npm/v1/keys</c> (fetching the verifier's
/// own trust root from the thing it is verifying would defeat the check).
///
/// Unparseable entries are logged and skipped (the keyid simply has no anchor, so any
/// signature quoting it fails closed); an org with zero usable keys reports
/// <see cref="IsConfiguredForAsync"/> = false.
/// </summary>
public sealed class NpmSignatureKeyStore
{
    private readonly IPerOrgTrustAnchorStore _store;

    public NpmSignatureKeyStore(IPerOrgTrustAnchorStore store)
    {
        _store = store;
    }

    /// <summary>
    /// Always false at the instance level — npm trust anchors are per-org, not instance-wide.
    /// Use <see cref="IsConfiguredForAsync"/> to test whether a specific org has anchors.
    /// This property exists only to satisfy the <see cref="IArtifactProvenanceVerifier"/> interface
    /// contract; code that needs the per-org gate must call <see cref="IsConfiguredForAsync"/>.
    /// </summary>
    public bool IsConfigured => false;

    /// <summary>
    /// Returns true when at least one npm SPKI trust anchor is configured for <paramref name="orgId"/>.
    /// Fail-closed: an org with no anchors cannot enable signature verification.
    /// </summary>
    public Task<bool> IsConfiguredForAsync(string orgId, CancellationToken ct = default)
        => _store.IsConfiguredForAsync(orgId, "npm", ct);

    /// <summary>
    /// Resolves the per-org SPKI dictionary keyed by keyid for <paramref name="orgId"/>.
    /// Entries that fail base64 or ECDSA parse are logged and omitted. Returns an empty
    /// dictionary when no anchors are configured.
    /// </summary>
    public Task<IReadOnlyDictionary<string, byte[]>> GetSpkiMapAsync(
        string orgId, CancellationToken ct = default)
        => _store.GetNpmKeysAsync(orgId, ct);

    // Parses a list of TrustAnchorMaterial rows into a keyid→SPKI-bytes map.
    // Skips entries with missing keyid/material or unparseable SPKI blobs (logged + fail-closed).
    internal static IReadOnlyDictionary<string, byte[]> BuildSpkiMap(
        IReadOnlyList<TrustAnchorMaterial> anchors, ILogger logger)
    {
        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var anchor in anchors)
        {
            string keyId = anchor.KeyId ?? "";
            string material = anchor.Material ?? "";
            if (string.IsNullOrWhiteSpace(keyId) || string.IsNullOrWhiteSpace(material))
            {
                continue;
            }

            if (!TryParseSpki(keyId, material.Trim(), out byte[]? spki, logger))
            {
                continue;
            }

            result[keyId] = spki!;
        }

        return result;
    }

    // Parses a single base64 SPKI DER entry. Returns false and logs a warning on failure.
    // Validation now (at load time from the anchor store) means a typo surfaces as a missing
    // anchor (fail-closed) rather than a per-request crypto throw.
    [SuppressMessage("Major Bug", "S1168:Empty arrays and collections should be returned instead of null",
        Justification = "Null output is the intended absent-key sentinel on parse failure.")]
    internal static bool TryParseSpki(string keyId, string b64, out byte[]? spki, ILogger logger)
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
                "npm trust anchor for keyid {KeyId} could not be parsed as a base64 "
                + "ECDSA SPKI key ({ExceptionType}); signatures quoting this keyid fail closed.",
                keyId, ex.GetType().Name);
            return false;
        }
    }
}
