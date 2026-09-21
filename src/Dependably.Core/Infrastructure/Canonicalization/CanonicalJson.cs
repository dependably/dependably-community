// A qualified reference to Org.Webpki... written inline (rather than through this using
// directive) fails to compile: Dependably.Infrastructure.Org — the tenant entity model,
// reachable everywhere via this repo's global `using Dependably.Infrastructure` — shadows the
// unrelated `Org` namespace root BouncyCastle and WebPKI's vendored code both share, but only in
// expression position. A `using` directive resolves the namespace directly and is unaffected.
using WebpkiJsonCanonicalizer = Org.Webpki.JsonCanonicalizer.JsonCanonicalizer;

namespace Dependably.Infrastructure.Canonicalization;

/// <summary>
/// The single entry point for RFC 8785 (JSON Canonicalization Scheme) canonicalization in this
/// codebase — used exclusively by the SBOM author-signature feature (ADR-sbom-author-signature)
/// to produce the bytes an enveloped JSF signature covers, on both the signing and verifying
/// sides.
///
/// <para>Delegates to <see cref="WebpkiJsonCanonicalizer"/>, vendored (with three corrections —
/// see its file header) under <c>Infrastructure/Canonicalization/Webpki/</c> — the RFC's own
/// author's reference implementation, chosen over an in-house canonicalizer because ES6 number
/// serialization (required by RFC 8785 §3.2.3) is the one part of this that a naive port gets
/// wrong in a way that verifies against itself and nothing else, which is exactly the failure
/// mode a signature must not have. <c>CanonicalJsonVectorTests</c> pins this file's output
/// against RFC 8785's own published test vectors, vendored under
/// <c>tests/Dependably.Tests/Fixtures/rfc8785-vectors/</c>. Reaches the product's own
/// third-party notices via <c>build/sbom-vendored.json</c>'s curated SBOM entry (its
/// <c>metadata.component.description</c> explains why it exists).</para>
/// </summary>
public static class CanonicalJson
{
    /// <summary>
    /// Canonicalizes <paramref name="json"/> per RFC 8785: object members sorted by UTF-16 code
    /// unit value, minimal string escaping, and ES6/ECMA-262 number serialization. Returns the
    /// canonical form as UTF-8 bytes — what an ES256 signature is computed over and verified
    /// against.
    /// </summary>
    /// <exception cref="System.IO.IOException">
    /// <paramref name="json"/> is not well-formed JSON, or its root is not an object or array.
    /// </exception>
    public static byte[] Canonicalize(string json) =>
        new WebpkiJsonCanonicalizer(json).GetEncodedUTF8();
}
