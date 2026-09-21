using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Dependably.Infrastructure.Canonicalization;
using Dependably.Infrastructure.Sbom;
using Dependably.Protocol.Provenance;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// The signature itself, end to end at the C# API level: attach with
/// <see cref="SbomAuthorSigner"/>, verify with <see cref="SbomSignatureVerifier"/> against a
/// trust anchor built from the signer's own public key — pinning the three behaviours the brief
/// calls out explicitly: a signature that verifies, a document altered after signing that does
/// not, and an unknown/absent key that fails closed rather than passing silently.
///
/// <see cref="Unit.Infrastructure.CanonicalJsonVectorTests"/> is what pins the canonicalizer
/// itself against RFC 8785's own vectors; this file exercises the signing/verifying MECHANICS
/// built on top of it (the JSF envelope shape, the P-256 raw-signature encoding, the trust-anchor
/// key resolution) — a class of bug the vector tests cannot see because they never touch a key.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomAuthorSignatureRoundTripTests
{
    private const string BaseDocument = """
        {"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:8d4f6a3e-2b1c-4c8e-9f2a-7e5d0c1b9a44","version":1,
         "metadata":{"timestamp":"2026-08-01T09:30:00Z","component":{"type":"application","bom-ref":"shipyard-api@3.4.1","name":"shipyard-api","version":"3.4.1"}},
         "components":[{"type":"library","bom-ref":"pkg:npm/lodash@4.17.21","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"}]}
        """;

    private static JsonObject Parse(string json) => (JsonObject)JsonNode.Parse(json)!;

    private static (SbomSigningKey Key, byte[] Spki) NewKey(string orgId = "org-1")
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string id = SbomSigningKeyRepository.ComputeFingerprint(ecdsa);
        return (new SbomSigningKey(id, orgId, ecdsa), ecdsa.ExportSubjectPublicKeyInfo());
    }

    private static SbomSignatureVerifier VerifierFor(string orgId, string keyId, byte[] spki)
    {
        var store = new StubPerOrgTrustAnchorStore();
        store.AddAnchor(orgId, "sbom", new TrustAnchorMaterial
        {
            Id = "anchor-1",
            AnchorKind = "spki",
            KeyId = keyId,
            Material = Convert.ToBase64String(spki),
        });
        return new SbomSignatureVerifier(new SbomSignatureKeyStore(store));
    }

    [Fact]
    public async Task Attach_ThenVerify_WithThePinnedKey_Verifies()
    {
        var (key, spki) = NewKey();
        using (key)
        {
            var doc = Parse(BaseDocument);
            SbomAuthorSigner.Attach(doc, key);

            var verifier = VerifierFor(key.OrgId, key.Id, spki);
            var verdict = await verifier.VerifyAsync(key.OrgId, doc.ToJsonString());

            Assert.Equal(ProvenanceStatuses.Verified, verdict.Status);
            Assert.Equal(key.Id, verdict.KeyId);
        }
    }

    // The mutant: comment out the `document[componentVersion] = "4.17.22"` mutation below (i.e.
    // verify the UNMODIFIED signed document) and this test degrades to a duplicate of the one
    // above — the assertion that must go red is specifically "a byte the signature covers
    // changed", not "verification can fail at all".
    [Fact]
    public async Task Attach_ThenTamperAfterSigning_FailsVerification()
    {
        var (key, spki) = NewKey();
        using (key)
        {
            var doc = Parse(BaseDocument);
            SbomAuthorSigner.Attach(doc, key);

            // Tamper with a byte the signature covers, after signing — the exact CVE-class this
            // element exists to catch (a document edited after the fact, distributed under an
            // unchanged-looking signature block).
            doc["components"]![0]!["version"] = "4.17.22";

            var verifier = VerifierFor(key.OrgId, key.Id, spki);
            var verdict = await verifier.VerifyAsync(key.OrgId, doc.ToJsonString());

            Assert.Equal(ProvenanceStatuses.Failed, verdict.Status);
        }
    }

    [Fact]
    public async Task Verify_AgainstAnAnchorForADifferentKey_IsUnanchored_NeverFailed()
    {
        var (key, _) = NewKey();
        var (otherKey, otherSpki) = NewKey();
        using (key)
        using (otherKey)
        {
            var doc = Parse(BaseDocument);
            SbomAuthorSigner.Attach(doc, key);

            // The pinned anchor is for a DIFFERENT key than the one that actually signed —
            // simulates an operator having pinned the wrong fingerprint, or a signature quoting
            // a keyId that was never registered. This registry's own trust-store gap — it never
            // saw a byte of the signature to judge cryptographically — so the verdict is
            // Unanchored, not Failed: only a signature this registry actually checked and found
            // invalid is the supplier's own failure (SbomSignatureVerdict's class doc comment).
            var verifier = VerifierFor(key.OrgId, otherKey.Id, otherSpki);
            var verdict = await verifier.VerifyAsync(key.OrgId, doc.ToJsonString());

            Assert.Equal(SbomSignatureVerdict.UnanchoredStatus, verdict.Status);
        }
    }

    [Fact]
    public async Task Verify_WithNoTrustAnchorConfigured_ReportsUnanchoredNeverFailed_AndStillFailsClosed()
    {
        var (key, _) = NewKey();
        using (key)
        {
            var doc = Parse(BaseDocument);
            SbomAuthorSigner.Attach(doc, key);

            // Empty anchor set (never seeded) — verifying still runs (this is not the enablement
            // check) and still fails closed under `block` (Unanchored != Verified), but the
            // verdict itself must not read as though this document's signature were
            // cryptographically invalid — this registry simply never had a key to check it
            // against, which is its own trust-store gap, not the supplier's failure.
            var verifier = new SbomSignatureVerifier(new SbomSignatureKeyStore(new StubPerOrgTrustAnchorStore()));
            var verdict = await verifier.VerifyAsync(key.OrgId, doc.ToJsonString());

            Assert.Equal(SbomSignatureVerdict.UnanchoredStatus, verdict.Status);
            Assert.False(await verifier.IsConfiguredForAsync(key.OrgId));
        }
    }

    [Fact]
    public async Task Verify_ADocumentWithNoSignatureMember_IsUnsigned()
    {
        var doc = Parse(BaseDocument);
        var verifier = new SbomSignatureVerifier(new SbomSignatureKeyStore(new StubPerOrgTrustAnchorStore()));

        var verdict = await verifier.VerifyAsync("org-1", doc.ToJsonString());

        Assert.Equal(ProvenanceStatuses.Unsigned, verdict.Status);
        Assert.Null(verdict.KeyId);
    }

    [Fact]
    public async Task Verify_ASignatureUnderAnUnsupportedAlgorithm_Fails()
    {
        var doc = Parse(BaseDocument);
        doc["signature"] = new JsonObject
        {
            ["algorithm"] = "RS256",
            ["keyId"] = "whatever",
            ["value"] = "AA",
        };
        var verifier = new SbomSignatureVerifier(new SbomSignatureKeyStore(new StubPerOrgTrustAnchorStore()));

        var verdict = await verifier.VerifyAsync("org-1", doc.ToJsonString());

        Assert.Equal(ProvenanceStatuses.Failed, verdict.Status);
    }

    // Pins the JSF envelope's real signed-content rule against a naive "remove the whole
    // signature member" canonicalizer: JsfEnvelope removes only `value`, so `algorithm`/`keyId`
    // are themselves covered by the signature. A canonicalizer that dropped the whole member
    // would compute different bytes and would not interoperate with a real JSF verifier even
    // though it might still verify against ITSELF — exactly the failure mode
    // ADR-sbom-author-signature warns about.
    [Fact]
    public void CanonicalBytesWithoutValue_KeepsAlgorithmAndKeyId_DropsOnlyValue()
    {
        var doc = Parse(BaseDocument);
        var envelope = JsfEnvelope.AttachUnsignedEnvelope(doc, "test-key-id");
        envelope["value"] = "placeholder";

        byte[] canonical = JsfEnvelope.CanonicalBytesWithoutValue(doc);
        string text = System.Text.Encoding.UTF8.GetString(canonical);

        Assert.Contains("\"algorithm\":\"ES256\"", text, StringComparison.Ordinal);
        Assert.Contains("\"keyId\":\"test-key-id\"", text, StringComparison.Ordinal);
        Assert.DoesNotContain("placeholder", text, StringComparison.Ordinal);
        // The envelope in the caller's tree is restored afterward, value included.
        Assert.Equal("placeholder", doc["signature"]!["value"]!.GetValue<string>());
    }
}
