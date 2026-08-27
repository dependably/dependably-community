using Dependably.Protocol;
using Dependably.Storage;

namespace Dependably.Tests.Unit;

/// <summary>
/// Regression cover for the trailing-newline anchor trap.
///
/// <para>
/// A .NET <c>Regex</c> without <c>RegexOptions.Multiline</c> treats <c>$</c> as "end of string,
/// <em>or</em> immediately before a single trailing <c>\n</c>". Every coordinate-shape validator in
/// this repo was written <c>^…$</c>, so <c>"pkg\n"</c> — delivered as <c>%0A</c> and URL-decoded by
/// routing before the action ever sees it — satisfied the charset check on every ecosystem.
/// </para>
///
/// <para>
/// Seven ecosystems caught it anyway on an independent <c>PathSafeValidator</c> call, whose literal
/// <c>char.IsControl</c> scan does not depend on anchoring. npm's publish path and OCI had no such
/// backstop: for npm the control character reached the hosted blob key as a real on-disk directory
/// segment and the <c>packages.name</c>/<c>purl_name</c> rows; for OCI the manifest, tag, catalogue
/// row, ownership record and audit event all committed before the crafted name was written into a
/// <c>Location</c> header, which Kestrel then rejected — a 500 after the corrupted identifier was
/// already permanent, where the Distribution Spec promises a 201.
/// </para>
///
/// <para>
/// These assert the validators themselves; <c>RegexAnchorComplianceTests</c> is what stops a new
/// <c>$</c>-anchored pattern from landing, and
/// <c>PackagePublishServiceTests.ControlCharacterInName_RejectedWith422</c> covers the
/// anchoring-independent service-level guard.
/// </para>
/// </summary>
public class RegexAnchorTrailingNewlineTests
{
    private const string Lf = "\n";

    [Theory]
    [InlineData("lodash")]
    [InlineData("react")]
    public void NpmPlainName_TrailingNewline_Rejected(string name)
    {
        Assert.True(NpmNameValidator.IsValidPlainName(name), "control: the bare name must be valid");
        Assert.False(NpmNameValidator.IsValidPlainName(name + Lf));
    }

    [Fact]
    public void NpmFullName_TrailingNewline_Rejected()
    {
        Assert.True(NpmNameValidator.IsValidFullName("@scope/pkg"));
        Assert.False(NpmNameValidator.IsValidFullName("@scope/pkg" + Lf));
        Assert.False(NpmNameValidator.IsValidFullName("@scope" + Lf + "/pkg"));
    }

    [Fact]
    public void OciRepositoryName_TrailingNewline_Rejected()
    {
        Assert.True(OciCoordinatesParser.IsValidRepositoryName("library/nginx"));
        Assert.False(OciCoordinatesParser.IsValidRepositoryName("library/nginx" + Lf));
    }

    [Fact]
    public void OciTag_TrailingNewline_Rejected()
    {
        Assert.True(OciCoordinatesParser.IsValidTag("1.0"));
        Assert.False(OciCoordinatesParser.IsValidTag("1.0" + Lf));
    }

    [Fact]
    public void OciParse_TrailingNewlineInEitherComponent_ReturnsNull()
    {
        Assert.NotNull(OciCoordinatesParser.Parse("repo", "latest"));
        Assert.Null(OciCoordinatesParser.Parse("repo" + Lf, "latest"));
        Assert.Null(OciCoordinatesParser.Parse("repo", "latest" + Lf));
    }

    [Fact]
    public void RpmName_TrailingNewline_Rejected()
    {
        Assert.Matches(RpmArtifactValidator.NameRegex, "bash");
        Assert.DoesNotMatch(RpmArtifactValidator.NameRegex, "bash" + Lf);
    }

    // The digest regex accepted any hex run ([a-f0-9]+), so 'sha256:a' and a 200-char digest both
    // passed. Not exploitable today — every consumer compares for exact equality against a digest
    // the server computed itself — but a prefix-matching optimisation would reopen it, and a
    // malformed digest should be refused at the DIGEST_INVALID gate, not saved by a downstream
    // equality check that happens to miss.
    [Theory]
    [InlineData("sha256:a")]
    [InlineData("sha256:abc123")]
    [InlineData("sha512:abc123")]
    public void OciDigest_WrongHexLength_Rejected(string digest) =>
        Assert.False(OciCoordinatesParser.IsValidDigest(digest));

    [Fact]
    public void OciDigest_CorrectHexLength_Accepted()
    {
        Assert.True(OciCoordinatesParser.IsValidDigest("sha256:" + new string('a', 64)));
        Assert.True(OciCoordinatesParser.IsValidDigest("sha512:" + new string('a', 128)));
        Assert.False(OciCoordinatesParser.IsValidDigest("sha256:" + new string('a', 64) + Lf));
        Assert.False(OciCoordinatesParser.IsValidDigest("sha384:" + new string('a', 96)));
    }

    // BlobKeys' own sha256 guard had the same anchor. Not reachable in production — every call site
    // passes a server-computed ChecksumVerifier hash, never a client-declared one — so this pins the
    // guard rather than closing a live hole.
    [Fact]
    public void BlobKeys_Sha256WithTrailingNewline_Rejected()
    {
        string good = new('a', 64);
        Assert.False(string.IsNullOrEmpty(BlobKeys.Proxy(good)));
        Assert.Throws<ArgumentException>(() => BlobKeys.Proxy(good + Lf));
    }
}
