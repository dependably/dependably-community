using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Dependably.Infrastructure.Canonicalization;
using Dependably.Protocol.Provenance;

namespace Dependably.Infrastructure.Sbom;

/// <summary>
/// One document's signature-verification outcome. <see cref="Verified"/>/<see cref="Unsigned"/>/
/// <see cref="Failed"/> are <see cref="ProvenanceStatuses"/>' shared vocabulary; <see cref="Unanchored"/>
/// is SBOM-specific and never appears there — it distinguishes "this registry holds no pinned
/// ('sbom','spki') anchor for the keyId the document claimed" (this registry's own trust-store
/// gap) from a cryptographically invalid signature (<see cref="Failed"/>, the supplier's
/// failure). Both still refuse an upload under <c>block</c> — an unpinned key is not a verified
/// one — but only <see cref="Failed"/> is a claim about what the SUPPLIER did, which is what lets
/// <see cref="SbomConformanceScorer"/> score them differently.
/// </summary>
public sealed record SbomSignatureVerdict(string Status, string? KeyId)
{
    /// <summary>
    /// This registry holds no pinned <c>('sbom','spki')</c> anchor for the document's claimed
    /// keyId — never persisted by <see cref="ProvenanceStatuses"/> (a different column's
    /// vocabulary), spelled here instead so <c>project_documents.signature_status</c> can carry it
    /// without borrowing a string whose established meaning elsewhere is "package-level
    /// provenance, never SBOM signature verdicts".
    /// </summary>
    public const string UnanchoredStatus = "unanchored";

    public static readonly SbomSignatureVerdict Unsigned = new(ProvenanceStatuses.Unsigned, null);

    public static SbomSignatureVerdict Failed(string? keyId) => new(ProvenanceStatuses.Failed, keyId);

    public static SbomSignatureVerdict Verified(string keyId) => new(ProvenanceStatuses.Verified, keyId);

    public static SbomSignatureVerdict Unanchored(string keyId) => new(UnanchoredStatus, keyId);
}

/// <summary>
/// Verifies the enveloped JSF signature on an uploaded CycloneDX document, over the staged
/// bytes, against the org's <c>('sbom','spki')</c> trust anchors (ADR-sbom-author-signature).
///
/// <para>Scope is CycloneDX SBOM documents only — the caller is responsible for not invoking
/// this on a VEX, SARIF or SPDX upload, none of which define a signature carrier this policy
/// covers.</para>
///
/// <para>Never throws on malformed input: an absent signature, an unsupported algorithm, a
/// malformed envelope, an unknown keyId, a signature that simply does not verify, or a document
/// shape that is valid enough for <see cref="CycloneDxParser"/>'s <c>JsonDocument</c>-based read
/// but not for the <c>JsonNode</c> tree or the vendored canonicalizer this method builds from it
/// (a duplicate property at any depth, a number that overflows to Infinity, a lone UTF-16
/// surrogate) all map to <see cref="ProvenanceStatuses.Failed"/> or
/// <see cref="ProvenanceStatuses.Unsigned"/> so the admission path can fail closed under
/// <c>block</c> — and stay usable under <c>warn</c>, which must never refuse an upload — without
/// a parse or encoding exception reaching the caller.</para>
///
/// <para>A concrete type, not an <see cref="Dependably.Protocol.Provenance.IArtifactProvenanceVerifier"/>
/// implementor — that interface is registered and injected nowhere in this codebase, so
/// conforming to it buys shape conformance and no dispatch (see the ADR's Consequences
/// section).</para>
/// </summary>
public sealed class SbomSignatureVerifier
{
    private readonly SbomSignatureKeyStore _keys;

    public SbomSignatureVerifier(SbomSignatureKeyStore keys) => _keys = keys;

    /// <summary>
    /// True when at least one <c>('sbom','spki')</c> trust anchor is configured for
    /// <paramref name="orgId"/>. Fail-closed: an org with no anchors cannot enable verification.
    /// </summary>
    public Task<bool> IsConfiguredForAsync(string orgId, CancellationToken ct = default)
        => _keys.IsConfiguredForAsync(orgId, ct);

    /// <summary>
    /// Verifies <paramref name="documentJson"/> — the exact bytes staged for this upload, parsed
    /// as UTF-8 text — against <paramref name="orgId"/>'s pinned anchors.
    /// </summary>
    public async Task<SbomSignatureVerdict> VerifyAsync(
        string orgId, string documentJson, CancellationToken ct = default)
    {
        // One exception boundary for the whole untrusted-document walk, not one per call site.
        // JsonObject is LAZY: a duplicate property does not throw at JsonNode.Parse itself, but
        // on the FIRST indexer access into whichever JsonObject actually holds the duplicate —
        // which could be the root object (reading ["signature"] below), the envelope object
        // (JsfEnvelope.TryReadFields), or any nested object the canonicalizer's ToJsonString()
        // walks. Two narrower try/catches around only the initial parse and only the
        // canonicalization step each missed a real throw site sitting in between them (proven
        // live: a root-level duplicate property threw ArgumentException from the plain property
        // read a few lines below, caught by neither). keyId is captured as soon as it is known
        // so a failure discovered after that point still reports which key the document claimed.
        string? keyId = null;
        try
        {
            var root = JsonNode.Parse(documentJson);
            if (root is not JsonObject document || document[JsfEnvelope.SignatureProperty] is not JsonObject envelope)
            {
                return SbomSignatureVerdict.Unsigned;
            }

            if (!JsfEnvelope.TryReadFields(envelope, out string? algorithm, out keyId, out string? value))
            {
                return SbomSignatureVerdict.Failed(null);
            }

            if (!string.Equals(algorithm, JsfEnvelope.Es256, StringComparison.Ordinal))
            {
                // Only ES256 is signed or verified by this feature (see the ADR's algorithm
                // rationale) — a document signed under any other JWA algorithm name is present
                // but unverifiable by us, which is a failure, not a NotApplicable: the supplier
                // claimed a signature and we could not check it.
                return SbomSignatureVerdict.Failed(keyId);
            }

            byte[]? signature = JsfEnvelope.TryDecodeValue(value!);
            // P-256 IEEE P1363 (raw R||S) is exactly 64 bytes; anything else is not a signature
            // this algorithm could have produced.
            if (signature is null || signature.Length != 64)
            {
                return SbomSignatureVerdict.Failed(keyId);
            }

            byte[] canonical = JsfEnvelope.CanonicalBytesWithoutValue(document);

            var spkiMap = await _keys.GetSpkiMapAsync(orgId, ct);
            if (!spkiMap.TryGetValue(keyId!, out byte[]? spki))
            {
                // No pinned anchor for this keyid — cannot establish trust for this signature.
                // This registry's own trust-store gap, not a claim the signature itself is
                // invalid, so it is Unanchored rather than Failed (see SbomSignatureVerdict's
                // class doc comment) — the supplier may have signed correctly with a key this
                // org simply never pinned.
                return SbomSignatureVerdict.Unanchored(keyId!);
            }

            bool verified;
            try
            {
                using var ecdsa = ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(spki!, out _);
                verified = ecdsa.VerifyData(
                    canonical, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            catch (CryptographicException)
            {
                verified = false;
            }

            return verified ? SbomSignatureVerdict.Verified(keyId!) : SbomSignatureVerdict.Failed(keyId);
        }
        catch (Exception ex) when (ex is JsonException or IOException or ArgumentException or InvalidOperationException)
        {
            // Every shape here is untrusted-input malformation this parser or the vendored
            // canonicalizer cannot read — never a bug in the caller's own staged bytes: a
            // duplicate property at any depth (ArgumentException, from JsonObject's lazy
            // dictionary construction), a number that overflows to Infinity or a lone UTF-16
            // surrogate that cannot round-trip to UTF-8 (ArgumentException, from the
            // canonicalizer or from ToJsonString() itself), or a malformed token the
            // canonicalizer's own decoder rejects (IOException). A verdict, matching every other
            // malformed-input arm above (never Unsigned — the document DID make a claim, just
            // not one this method could finish reading), rather than an exception the caller has
            // to handle.
            return SbomSignatureVerdict.Failed(keyId);
        }
    }
}
