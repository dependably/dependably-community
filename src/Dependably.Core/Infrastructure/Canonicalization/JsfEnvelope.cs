using System.Text.Json.Nodes;
using Microsoft.AspNetCore.WebUtilities;

namespace Dependably.Infrastructure.Canonicalization;

/// <summary>
/// Shared mechanics for the enveloped JSON Signature Format (JSF) <c>signature</c> member both
/// <c>SbomAuthorSigner</c> and <c>SbomSignatureVerifier</c> use — the wire shape is
/// <c>{"algorithm":"ES256","keyId":"&lt;fingerprint&gt;","value":"&lt;base64url&gt;"}</c>, per the
/// JSF core-signer schema (no <c>publicKey</c> — see ADR-sbom-author-signature).
///
/// <para><b>What gets canonicalized, precisely.</b> JSF's own reference verifier
/// (github.com/cyberphone/node-webpki.org, <c>lib/Jsf.js</c>) removes only the signature
/// object's <c>value</c> property before canonicalizing — <c>algorithm</c> and <c>keyId</c> stay
/// in the signed bytes, because they are themselves part of what the signer asserted. This is
/// narrower than "the signature member removed" and matters for interop: a canonicalizer that
/// drops the whole member produces different bytes than a real JSF implementation, so a
/// signature that verifies here would fail everywhere else. <see cref="CanonicalBytesWithoutValue"/>
/// implements the real rule.</para>
///
/// <para><b>The signature value's binary form.</b> Per JWA (RFC 7518) §3.4, an ES256 signature
/// is the raw 64-byte R||S concatenation — <see cref="System.Security.Cryptography.DSASignatureFormat.IeeeP1363FixedFieldConcatenation"/>
/// in .NET — never the DER SEQUENCE encoding npm's registry signatures use. Encoded as
/// base64url with no padding (<see cref="WebEncoders"/>), matching every other JOSE/JWS binary
/// field.</para>
/// </summary>
public static class JsfEnvelope
{
    /// <summary>The only signature algorithm this feature signs or verifies — see the ADR's
    /// "algorithm, and why ISO/IEC 14888-4 is not its authority" section.</summary>
    public const string Es256 = "ES256";

    public const string SignatureProperty = "signature";
    private const string AlgorithmProperty = "algorithm";
    private const string KeyIdProperty = "keyId";
    private const string ValueProperty = "value";

    /// <summary>
    /// Attaches an envelope carrying <paramref name="keyId"/> and <see cref="Es256"/> — with
    /// <c>value</c> deliberately absent — to <paramref name="document"/>. The caller canonicalizes
    /// the document in this state (via <see cref="CanonicalBytesWithoutValue"/>), signs those
    /// bytes, then calls <see cref="SetValue"/> to complete the envelope. Splitting attach/sign/
    /// set-value into three steps, rather than one "sign and attach" call, is what makes
    /// <c>algorithm</c>/<c>keyId</c> land inside the signed bytes exactly once, in the position
    /// they occupy in the final document.
    /// </summary>
    public static JsonObject AttachUnsignedEnvelope(JsonObject document, string keyId)
    {
        var envelope = new JsonObject
        {
            [AlgorithmProperty] = Es256,
            [KeyIdProperty] = keyId,
        };
        document[SignatureProperty] = envelope;
        return envelope;
    }

    /// <summary>Sets the completed signature value, base64url-encoding <paramref name="raw"/>.</summary>
    public static void SetValue(JsonObject envelope, byte[] raw) =>
        envelope[ValueProperty] = WebEncoders.Base64UrlEncode(raw);

    /// <summary>
    /// Canonicalizes <paramref name="document"/> exactly as JSF requires for signing/verifying:
    /// the whole document, with the signature envelope's <c>value</c> property (and only that
    /// property) absent. Mutates <paramref name="document"/> in place — removes <c>value</c>,
    /// serializes, canonicalizes, then restores whatever <c>value</c> held (or leaves it absent,
    /// if it started that way) so the caller's tree is unchanged afterward.
    /// </summary>
    public static byte[] CanonicalBytesWithoutValue(JsonObject document)
    {
        var envelope = (JsonObject)document[SignatureProperty]!;
        var previousValue = envelope[ValueProperty];
        envelope.Remove(ValueProperty);
        try
        {
            return CanonicalJson.Canonicalize(document.ToJsonString());
        }
        finally
        {
            if (previousValue is not null)
            {
                envelope[ValueProperty] = previousValue;
            }
        }
    }

    /// <summary>
    /// Reads <c>algorithm</c>/<c>keyId</c>/<c>value</c> off an already-parsed signature envelope.
    /// Returns false if any required field is missing or not a string — a malformed envelope
    /// that a genuine signer would never produce.
    /// </summary>
    public static bool TryReadFields(
        JsonObject envelope, out string? algorithm, out string? keyId, out string? value)
    {
        algorithm = AsString(envelope[AlgorithmProperty]);
        keyId = AsString(envelope[KeyIdProperty]);
        value = AsString(envelope[ValueProperty]);
        return algorithm is not null && keyId is not null && value is not null;
    }

    // Reads a JSON value as a string, or null when absent or not a JSON string — never throws,
    // which matters here because every field comes from an untrusted uploaded document.
    private static string? AsString(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue(out string? s) ? s : null;

    /// <summary>Decodes a base64url signature value. Returns null (never throws) on malformed input.</summary>
    // Null is the Try-contract's decode failure. An empty array would make a malformed base64url
    // signature indistinguishable from a legitimately empty value on the verification path.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S1168:Empty arrays and collections should be returned instead of null",
        Justification = "Null is absence, not emptiness: an empty value here would be emitted as a real entry and change the result.")]
    public static byte[]? TryDecodeValue(string base64Url)
    {
        try
        {
            return WebEncoders.Base64UrlDecode(base64Url);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
