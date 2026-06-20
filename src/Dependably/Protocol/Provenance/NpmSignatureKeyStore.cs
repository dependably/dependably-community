using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Dependably.Protocol.Provenance;

/// <summary>
/// Operator-pinned trust anchors for npm registry signatures. Mirrors the RPM
/// <c>Rpm:GpgKey</c> posture: the trust root is always configured out of band by the operator,
/// never the key the upstream registry serves at <c>/-/npm/v1/keys</c> (fetching the verifier's
/// own trust root from the thing it is verifying would defeat the check).
///
/// Configuration: <c>Npm:SignatureKeys</c> is an array (like <c>Oci:Upstreams</c>) of
/// <c>{ "keyid": "&lt;keyid&gt;", "key": "&lt;base64 SPKI DER&gt;" }</c> objects. The <c>key</c>
/// is the base64-encoded SubjectPublicKeyInfo (SPKI) DER of the registry's ECDSA P-256 public key
/// — exactly the <c>key</c> field the public registry publishes at <c>/-/npm/v1/keys</c>, which an
/// operator copies in after verifying it out of band. An array (rather than a keyid-keyed object)
/// is required because npm keyids contain a colon (e.g.
/// <c>SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA</c>), which the configuration system
/// treats as a hierarchy separator.
///
/// Unparseable entries are logged and skipped (the keyid simply has no anchor, so any signature
/// quoting it fails closed); a store with zero usable keys reports
/// <see cref="IsConfigured"/> = false.
/// </summary>
public sealed class NpmSignatureKeyStore
{
    private readonly Dictionary<string, byte[]> _spkiByKeyId;
    private readonly ILogger<NpmSignatureKeyStore> _logger;

    public NpmSignatureKeyStore(IConfiguration configuration, ILogger<NpmSignatureKeyStore> logger)
    {
        _logger = logger;
        _spkiByKeyId = LoadKeys(configuration.GetSection("Npm:SignatureKeys"));
    }

    /// <summary>True when at least one pinned key parsed into a usable SPKI blob.</summary>
    public bool IsConfigured => _spkiByKeyId.Count > 0;

    /// <summary>
    /// Returns the pinned SPKI DER for <paramref name="keyId"/>, or null when no anchor is
    /// pinned for that id. A signature quoting an unknown keyid is unverifiable → fail closed.
    /// </summary>
    // Null signals "no anchor for this keyid" to the caller; returning empty bytes would be
    // semantically incorrect (an empty SPKI is not a valid absent-key sentinel).
    [SuppressMessage("Major Bug", "S1168:Empty arrays and collections should be returned instead of null",
        Justification = "Null is the intended absent-key sentinel; an empty byte array is not a valid SPKI.")]
    public byte[]? GetSpki(string keyId) =>
        _spkiByKeyId.TryGetValue(keyId, out byte[]? spki) ? spki : null;

    private Dictionary<string, byte[]> LoadKeys(IConfigurationSection section)
    {
        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var entry in section.GetChildren())
        {
            string? keyId = entry["keyid"];
            string? b64 = entry["key"];
            if (string.IsNullOrWhiteSpace(keyId) || string.IsNullOrWhiteSpace(b64))
            {
                continue;
            }

            try
            {
                byte[] spki = Convert.FromBase64String(b64.Trim());
                // Validate the blob is a real P-256 SPKI now, at load time, so a typo surfaces
                // as a missing anchor (fail-closed) rather than a per-request crypto throw.
                using var ecdsa = ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(spki, out _);
                result[keyId] = spki;
            }
            catch (Exception ex) when (ex is FormatException or CryptographicException)
            {
                _logger.LogWarning(
                    "Npm:SignatureKeys entry for keyid {KeyId} could not be parsed as a base64 "
                    + "ECDSA SPKI key ({ExceptionType}); signatures quoting this keyid fail closed.",
                    keyId, ex.GetType().Name);
            }
        }

        return result;
    }
}
