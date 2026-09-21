using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Dependably.Infrastructure.Sbom;
using Dependably.Protocol.Provenance;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit.Sbom;

/// <summary>
/// Four uploaded-document shapes that are well-formed enough for
/// <see cref="Dependably.Infrastructure.Sbom.CycloneDxParser"/>'s <c>JsonDocument</c>-based read
/// but throw inside <see cref="SbomSignatureVerifier"/>'s <c>JsonNode</c>/canonicalizer path: a
/// duplicate property (root-level and nested), a lone UTF-16 surrogate, and a number that
/// overflows to Infinity. Each was proven, over live HTTP, to reach the caller as a 500 before
/// the catch clauses were widened — under <c>block</c> that is a refusal with no
/// <c>sbom_signature_blocked</c> audit row; under <c>warn</c>, which must never refuse an
/// upload, it is a hard failure of a legitimate document. Every case here must return
/// <see cref="ProvenanceStatuses.Failed"/> without the exception reaching this test.
///
/// <para>Mutant: reverting either widened catch clause in <see cref="SbomSignatureVerifier"/>
/// back to its single original exception type turns the matching case below from a passing
/// assertion into an unhandled exception — the test does not merely stop asserting true, it
/// stops running at all, which is the loudest possible red.</para>
/// </summary>
[Trait("Category", "Unit")]
public sealed class SbomSignatureVerifierMalformedInputTests
{
    private const string BaseDocument = """
        {"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:8d4f6a3e-2b1c-4c8e-9f2a-7e5d0c1b9a44","version":1,
         "metadata":{"timestamp":"2026-08-01T09:30:00Z","component":{"type":"application","bom-ref":"shipyard-api@3.4.1","name":"shipyard-api","version":"3.4.1"}},
         "components":[{"type":"library","bom-ref":"pkg:npm/lodash@4.17.21","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"}]}
        """;

    private static SbomSignatureVerifier NewVerifier()
        => new(new SbomSignatureKeyStore(new StubPerOrgTrustAnchorStore()));

    // Builds a genuinely signed document (so the verifier reaches the canonicalization step
    // rather than returning Failed earlier for an unrelated reason such as a bad algorithm),
    // then corrupts it at the TEXT level — a JsonNode tree cannot itself hold a duplicate key, an
    // unpaired surrogate that fails to round-trip, or an Infinity-valued number once constructed
    // in memory, so the only way to reproduce what an actual attacker's raw bytes would contain
    // is string substitution on the already-serialized JSON.
    private static string SignedThenCorrupted(string search, string replace)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = new SbomSigningKey(SbomSigningKeyRepository.ComputeFingerprint(ecdsa), "org-1", ecdsa);
        var doc = (JsonObject)JsonNode.Parse(BaseDocument)!;
        SbomAuthorSigner.Attach(doc, key);
        string signed = doc.ToJsonString();

        Assert.Contains(search, signed, StringComparison.Ordinal);
        return signed.Replace(search, replace, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NestedDuplicateProperty_FailsClosed_WithoutThrowing()
    {
        // A second "name" inside metadata.component — JsonObject.Add throws ArgumentException
        // when JsonNode.Parse rebuilds the dictionary from this text.
        string corrupted = SignedThenCorrupted(
            """"name":"shipyard-api","version":"3.4.1"}"""",
            """"name":"shipyard-api","name":"duplicate","version":"3.4.1"}"""");

        var verdict = await NewVerifier().VerifyAsync("org-1", corrupted);

        Assert.Equal(ProvenanceStatuses.Failed, verdict.Status);
    }

    [Fact]
    public async Task RootLevelDuplicateProperty_FailsClosed_WithoutThrowing()
    {
        // A second top-level "version" — same ArgumentException, at the outermost object.
        string corrupted = SignedThenCorrupted(
            """"specVersion":"1.6","serialNumber":"""",
            """"specVersion":"1.6","specVersion":"1.7","serialNumber":"""");

        var verdict = await NewVerifier().VerifyAsync("org-1", corrupted);

        Assert.Equal(ProvenanceStatuses.Failed, verdict.Status);
    }

    [Fact]
    public async Task LoneSurrogate_FailsClosed_WithoutThrowing()
    {
        // \ud800 is a valid JSON string escape (JSON does not require well-formed UTF-16) that
        // System.Text.Json parses without complaint but cannot re-encode to UTF-8 — the
        // canonicalizer's UTF8Encoding(throwOnInvalidBytes: true) raises EncoderFallbackException,
        // which derives from ArgumentException.
        string corrupted = SignedThenCorrupted(
            """"name":"lodash"""",
            """"name":"\ud800"""");

        var verdict = await NewVerifier().VerifyAsync("org-1", corrupted);

        Assert.Equal(ProvenanceStatuses.Failed, verdict.Status);
    }

    [Fact]
    public async Task NumberOverflowingToInfinity_FailsClosed_WithoutThrowing()
    {
        // 1e999 parses as a valid (if enormous) JSON number token, and System.Text.Json accepts
        // it as a double — which overflows to Infinity. The vendored canonicalizer's own
        // NumberToJson.SerializeNumber explicitly rejects Infinity/NaN with ArgumentException,
        // since JSON's number grammar has no representation for either.
        string corrupted = SignedThenCorrupted(
            """"version":"4.17.21","purl"""",
            """"version":"4.17.21","overflow":1e999,"purl"""");

        var verdict = await NewVerifier().VerifyAsync("org-1", corrupted);

        Assert.Equal(ProvenanceStatuses.Failed, verdict.Status);
    }
}
