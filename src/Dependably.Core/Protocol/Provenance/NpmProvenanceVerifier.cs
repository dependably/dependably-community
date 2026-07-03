using System.Security.Cryptography;
using System.Text;
using Dependably.Infrastructure.Observability;

namespace Dependably.Protocol.Provenance;

/// <summary>
/// Verifies npm registry signatures, exactly as <c>npm audit signatures</c> does.
///
/// The npm registry signs each published version. The packument's <c>versions[v].dist</c> carries
/// <c>integrity</c> (an SRI string) and <c>signatures: [{ keyid, sig }]</c>, where <c>sig</c> is the
/// base64 of an ECDSA P-256 (secp256r1) / SHA-256 signature over the exact UTF-8 string
/// <c>"{name}@{version}:{integrity}"</c>. The signature is DER-encoded
/// (<see cref="DSASignatureFormat.Rfc3279DerSequence"/>).
///
/// The trust anchor is the per-org operator-pinned SPKI public key resolved by keyid from
/// <see cref="NpmSignatureKeyStore"/> — never the key the upstream registry serves at
/// <c>/-/npm/v1/keys</c>.
///
/// Never throws on bad input: a missing integrity, malformed base64, an unknown keyid, or a
/// signature that simply doesn't verify all map to a status (<see cref="ProvenanceStatus.Failed"/>
/// or <see cref="ProvenanceStatus.Unsigned"/>) so the proxy ingest path can fail closed.
/// </summary>
public sealed class NpmProvenanceVerifier : IArtifactProvenanceVerifier
{
    private readonly NpmSignatureKeyStore _keys;

    public NpmProvenanceVerifier(NpmSignatureKeyStore keys) => _keys = keys;

    public string Ecosystem => "npm";

    /// <summary>
    /// Always false at the instance level — npm trust anchors are per-org.
    /// Use <see cref="IsConfiguredForAsync"/> to test whether a specific org has anchors.
    /// </summary>
    public bool IsConfigured => false;

    /// <summary>
    /// Returns true when at least one npm SPKI trust anchor is configured for <paramref name="orgId"/>.
    /// Fail-closed: an org with no anchors cannot enable signature verification.
    /// </summary>
    public Task<bool> IsConfiguredForAsync(string orgId, CancellationToken ct = default)
        => _keys.IsConfiguredForAsync(orgId, ct);

    /// <summary>
    /// Resolves per-org keys for <paramref name="orgId"/>, then verifies the signatures
    /// in <paramref name="input"/> against the pinned anchors. Returns
    /// <see cref="ProvenanceResult.NotApplicable"/> when no anchors are configured for the org.
    /// </summary>
    public async Task<ProvenanceResult> VerifyForOrgAsync(
        string orgId, ProvenanceInput input, CancellationToken ct = default)
    {
        var spkiMap = await _keys.GetSpkiMapAsync(orgId, ct);
        return spkiMap.Count == 0
            ? Record(input.Ecosystem, ProvenanceResult.NotApplicable)
            : Record(input.Ecosystem, Verify(input, spkiMap));
    }

    /// <summary>
    /// Instance-level verify: does not resolve per-org keys. Returns
    /// <see cref="ProvenanceResult.NotApplicable"/> because no org context is available.
    /// Callers on the proxy ingest path must use <see cref="VerifyForOrgAsync"/>.
    /// </summary>
    public Task<ProvenanceResult> VerifyAsync(ProvenanceInput input, CancellationToken ct = default)
        => Task.FromResult(ProvenanceResult.NotApplicable);

    private static ProvenanceResult Verify(
        ProvenanceInput input, IReadOnlyDictionary<string, byte[]> spkiMap)
    {
        // No signatures published for this version (older packages predate registry signing).
        if (input.Signatures.Count == 0)
        {
            return ProvenanceResult.Unsigned;
        }

        // The signed payload requires the integrity reference; without it there is nothing the
        // registry could have signed over, so a present-but-unverifiable signature fails closed.
        if (string.IsNullOrEmpty(input.Integrity))
        {
            return ProvenanceResult.Failed;
        }

        byte[] message = Encoding.UTF8.GetBytes(
            $"{input.PackageName}@{input.Version}:{input.Integrity}");

        // npm publishes a signature list; a single valid signature from a pinned key verifies.
        foreach (var sig in input.Signatures)
        {
            if (!spkiMap.TryGetValue(sig.KeyId, out byte[]? spki))
            {
                // No pinned anchor for this keyid — cannot establish trust for this entry.
                continue;
            }

            if (TryVerifyOne(spki, message, sig.Signature))
            {
                return ProvenanceResult.Verified(sig.KeyId);
            }
        }

        // A signature was present but none chained to a pinned key with a valid signature.
        return ProvenanceResult.Failed;
    }

    // Verifies one base64 DER signature against the pinned SPKI. Returns false (never throws) on
    // malformed base64, a bad SPKI, or a signature that doesn't validate.
    private static bool TryVerifyOne(byte[] spki, byte[] message, string base64Signature)
    {
        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(base64Signature);
        }
        catch (FormatException)
        {
            return false;
        }

        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(spki, out _);
            // npm signatures are DER-encoded (Rfc3279DerSequence), SHA-256 over the UTF-8 payload.
            return ecdsa.VerifyData(
                message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    // Emits the OTel result counter. NO per-package labels — only ecosystem + result — to stay
    // inside the cardinality budget. NotApplicable is never recorded here (we only run when a
    // verifier is actually invoked).
    private static ProvenanceResult Record(string ecosystem, ProvenanceResult result)
    {
        if (result.Status == ProvenanceStatus.NotApplicable)
        {
            return result;
        }

        DependablyMeter.ProvenanceVerified.Add(1,
            new KeyValuePair<string, object?>("ecosystem", ecosystem),
            new KeyValuePair<string, object?>("result", ResultLabel(result.Status)));
        return result;
    }

    private static string ResultLabel(ProvenanceStatus status) => status switch
    {
        ProvenanceStatus.Verified => "verified",
        ProvenanceStatus.Failed => "failed",
        ProvenanceStatus.Unsigned => "unsigned",
        _ => "not_applicable",
    };
}
