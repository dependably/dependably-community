using System.Security.Cryptography;
using Dependably.Protocol;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class ChecksumVerifierTests
{
    private static readonly byte[] Payload = "hello world"u8.ToArray();
    private static readonly string Sha256Hex = Convert.ToHexString(SHA256.HashData(Payload)).ToLowerInvariant();
    private static readonly string Sha1Hex = Convert.ToHexString(SHA1.HashData(Payload)).ToLowerInvariant();
    private static readonly byte[] Sha512Bytes = SHA512.HashData(Payload);
    private static readonly string Sha512Hex = Convert.ToHexString(Sha512Bytes).ToLowerInvariant();
    private static readonly string Sha512Base64 = Convert.ToBase64String(Sha512Bytes);

    // ── ParsePyPiUrl ──────────────────────────────────────────────────────────

    [Fact]
    public void ParsePyPiUrl_WithFragment_ReturnsSha256Spec()
    {
        var spec = ChecksumVerifier.ParsePyPiUrl("https://files.pypi/x.whl#sha256=" + Sha256Hex);
        Assert.NotNull(spec);
        Assert.Equal(ChecksumAlgorithm.Sha256, spec!.Algorithm);
        Assert.Equal(Sha256Hex, spec.ExpectedValue);
    }

    [Fact]
    public void ParsePyPiUrl_NoFragment_ReturnsNull()
    {
        Assert.Null(ChecksumVerifier.ParsePyPiUrl("https://files.pypi/x.whl"));
    }

    [Fact]
    public void ParsePyPiUrl_CaseInsensitiveFragment()
    {
        var spec = ChecksumVerifier.ParsePyPiUrl("https://x/y#SHA256=" + Sha256Hex);
        Assert.NotNull(spec);
        Assert.Equal(Sha256Hex, spec!.ExpectedValue);
    }

    // ── ParseNpmIntegrity ─────────────────────────────────────────────────────

    [Fact]
    public void ParseNpmIntegrity_Sha512_TakesPriorityOverShasum()
    {
        var spec = ChecksumVerifier.ParseNpmIntegrity("sha512-" + Sha512Base64, "ignored");
        Assert.NotNull(spec);
        Assert.Equal(ChecksumAlgorithm.Sha512, spec!.Algorithm);
        Assert.Equal(Sha512Base64, spec.ExpectedValue);
    }

    [Fact]
    public void ParseNpmIntegrity_NoSha512_FallsBackToShasum()
    {
        var spec = ChecksumVerifier.ParseNpmIntegrity(null, Sha1Hex);
        Assert.NotNull(spec);
        Assert.Equal(ChecksumAlgorithm.Sha1, spec!.Algorithm);
        Assert.Equal(Sha1Hex, spec.ExpectedValue);
    }

    [Fact]
    public void ParseNpmIntegrity_BothNull_ReturnsNull()
    {
        Assert.Null(ChecksumVerifier.ParseNpmIntegrity(null, null));
    }

    [Fact]
    public void ParseNpmIntegrity_NonSha512Integrity_FallsBackToShasum()
    {
        var spec = ChecksumVerifier.ParseNpmIntegrity("sha256-AAAA", Sha1Hex);
        Assert.NotNull(spec);
        Assert.Equal(ChecksumAlgorithm.Sha1, spec!.Algorithm);
    }

    // ── ParseNuGetHash ────────────────────────────────────────────────────────

    [Fact]
    public void ParseNuGetHash_Sha512_ReturnsSpec()
    {
        var spec = ChecksumVerifier.ParseNuGetHash(Sha512Base64, "SHA512");
        Assert.NotNull(spec);
        Assert.Equal(ChecksumAlgorithm.Sha512, spec!.Algorithm);
        Assert.Equal(Sha512Base64, spec.ExpectedValue);
    }

    [Fact]
    public void ParseNuGetHash_CaseInsensitiveAlgorithm()
    {
        Assert.NotNull(ChecksumVerifier.ParseNuGetHash(Sha512Base64, "sha512"));
    }

    [Theory]
    [InlineData(null, "SHA512")]
    [InlineData("", "SHA512")]
    [InlineData("hash", null)]
    [InlineData("hash", "")]
    [InlineData("hash", "SHA256")]
    public void ParseNuGetHash_InvalidInputs_ReturnNull(string? hash, string? algorithm)
    {
        Assert.Null(ChecksumVerifier.ParseNuGetHash(hash, algorithm));
    }

    // ── Verify ────────────────────────────────────────────────────────────────

    [Fact]
    public void Verify_NullSpec_ReturnsTrue()
    {
        Assert.True(ChecksumVerifier.Verify(Payload, null));
    }

    [Fact]
    public void Verify_Sha256_Match_CaseInsensitive()
    {
        Assert.True(ChecksumVerifier.Verify(Payload, new ChecksumSpec(ChecksumAlgorithm.Sha256, Sha256Hex.ToUpperInvariant())));
    }

    [Fact]
    public void Verify_Sha256_Mismatch_ReturnsFalse()
    {
        Assert.False(ChecksumVerifier.Verify(Payload, new ChecksumSpec(ChecksumAlgorithm.Sha256, new string('0', 64))));
    }

    [Fact]
    public void Verify_Sha1_Match()
    {
        Assert.True(ChecksumVerifier.Verify(Payload, new ChecksumSpec(ChecksumAlgorithm.Sha1, Sha1Hex)));
    }

    [Fact]
    public void Verify_Sha512_Base64Path_NuGetShape()
    {
        Assert.True(ChecksumVerifier.Verify(Payload, new ChecksumSpec(ChecksumAlgorithm.Sha512, Sha512Base64)));
    }

    [Fact]
    public void Verify_Sha512_InvalidBase64_FallsThroughToHexCompare()
    {
        // Underscore is not a valid base64 character, so FromBase64String throws and the
        // fallback path runs. The compare still fails — there's no way to construct an
        // input that both throws on base64 AND matches as hex — but we've exercised the
        // catch branch.
        Assert.False(ChecksumVerifier.Verify(
            Payload, new ChecksumSpec(ChecksumAlgorithm.Sha512, "_invalid_base64_")));
    }

    [Fact]
    public void Verify_Sha512_Mismatch_ReturnsFalse()
    {
        // 64 valid-base64 chars but not the right hash.
        string bogus = Convert.ToBase64String(new byte[64]);
        Assert.False(ChecksumVerifier.Verify(Payload, new ChecksumSpec(ChecksumAlgorithm.Sha512, bogus)));
    }

    [Fact]
    public void Verify_UnknownAlgorithm_ReturnsFalse()
    {
        // Cast an out-of-range int to the enum to hit the switch's default arm (`_ => false`).
        var bogusAlgorithm = (ChecksumAlgorithm)999;
        Assert.False(ChecksumVerifier.Verify(Payload, new ChecksumSpec(bogusAlgorithm, Sha256Hex)));
    }

    // ── ComputeSha256Hex ──────────────────────────────────────────────────────

    [Fact]
    public void ComputeSha256Hex_KnownVector()
    {
        // SHA-256 of "hello world"
        Assert.Equal(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
            ChecksumVerifier.ComputeSha256Hex(Payload));
    }
}
