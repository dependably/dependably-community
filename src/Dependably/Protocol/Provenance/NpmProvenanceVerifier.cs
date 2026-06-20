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
/// The trust anchor is the operator-pinned SPKI public key resolved by keyid from
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

    public bool IsConfigured => _keys.IsConfigured;

    public Task<ProvenanceResult> VerifyAsync(ProvenanceInput input, CancellationToken ct = default)
        => Task.FromResult(Verify(input));

    private ProvenanceResult Verify(ProvenanceInput input)
    {
        // No signatures published for this version (older packages predate registry signing).
        if (input.Signatures.Count == 0)
        {
            return Record(input.Ecosystem, ProvenanceResult.Unsigned);
        }

        // The signed payload requires the integrity reference; without it there is nothing the
        // registry could have signed over, so a present-but-unverifiable signature fails closed.
        if (string.IsNullOrEmpty(input.Integrity))
        {
            return Record(input.Ecosystem, ProvenanceResult.Failed);
        }

        byte[] message = Encoding.UTF8.GetBytes(
            $"{input.PackageName}@{input.Version}:{input.Integrity}");

        // npm publishes a signature list; a single valid signature from a pinned key verifies.
        foreach (var sig in input.Signatures)
        {
            byte[]? spki = _keys.GetSpki(sig.KeyId);
            if (spki is null)
            {
                // No pinned anchor for this keyid — cannot establish trust for this entry.
                continue;
            }

            if (TryVerifyOne(spki, message, sig.Signature))
            {
                return Record(input.Ecosystem, ProvenanceResult.Verified(sig.KeyId));
            }
        }

        // A signature was present but none chained to a pinned key with a valid signature.
        return Record(input.Ecosystem, ProvenanceResult.Failed);
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
