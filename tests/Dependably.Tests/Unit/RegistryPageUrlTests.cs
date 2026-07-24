using Dependably.Protocol;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class RegistryPageUrlTests
{
    // Each ecosystem's public download host reconstructs the correct human-readable page URL.
    [Theory]
    [InlineData("npm", "pkg:npm/lodash@4.17.21", "lodash", "4.17.21",
        "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
        "https://www.npmjs.com/package/lodash/v/4.17.21")]
    // Scoped npm name keeps its @scope/pkg form literal (that is how npmjs.com routes it).
    [InlineData("npm", "pkg:npm/@babel/core@7.24.0", "@babel/core", "7.24.0",
        "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
        "https://www.npmjs.com/package/@babel/core/v/7.24.0")]
    // PyPI: display name is PEP 503-normalized for the project page.
    [InlineData("pypi", "pkg:pypi/flask@3.0.0", "Flask", "3.0.0",
        "https://files.pythonhosted.org/packages/ab/cd/Flask-3.0.0-py3-none-any.whl",
        "https://pypi.org/project/flask/3.0.0/")]
    // NuGet: original casing preserved (the nuget.org page is case-insensitive but tidy casing helps).
    [InlineData("nuget", "pkg:nuget/newtonsoft.json@13.0.3", "Newtonsoft.Json", "13.0.3",
        "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg",
        "https://www.nuget.org/packages/Newtonsoft.Json/13.0.3")]
    // Cargo: static.crates.io is the crates.io download host.
    [InlineData("cargo", "pkg:cargo/serde@1.0.197", "serde", "1.0.197",
        "https://static.crates.io/crates/serde/serde-1.0.197.crate",
        "https://crates.io/crates/serde/1.0.197")]
    // Maven: group/artifact recovered from the PURL, not the display name.
    [InlineData("maven", "pkg:maven/org.apache.commons/commons-lang3@3.14.0", "org.apache.commons:commons-lang3", "3.14.0",
        "https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar",
        "https://central.sonatype.com/artifact/org.apache.commons/commons-lang3/3.14.0")]
    [InlineData("maven", "pkg:maven/com.google.guava/guava@33.0.0-jre", "com.google.guava:guava", "33.0.0-jre",
        "https://repo.maven.apache.org/maven2/com/google/guava/guava/33.0.0-jre/guava-33.0.0-jre.jar",
        "https://central.sonatype.com/artifact/com.google.guava/guava/33.0.0-jre")]
    public void ForVersion_PublicHost_BuildsRegistryPage(
        string ecosystem, string purl, string displayName, string version, string upstreamUrl, string expected)
        => Assert.Equal(expected, RegistryPageUrl.ForVersion(ecosystem, purl, displayName, version, upstreamUrl));

    // Adversarial twin: a private/unrecognized upstream host must NEVER be turned into a public
    // page — reconstructing npmjs.com/pypi.org/… for a privately-mirrored package would be a lie.
    [Theory]
    [InlineData("npm", "pkg:npm/internal-lib@1.0.0", "internal-lib", "1.0.0",
        "https://npm.corp.example.com/internal-lib/-/internal-lib-1.0.0.tgz")]
    [InlineData("pypi", "pkg:pypi/internal-lib@1.0.0", "internal-lib", "1.0.0",
        "https://pypi.corp.example.com/packages/internal-lib-1.0.0-py3-none-any.whl")]
    [InlineData("nuget", "pkg:nuget/Internal.Lib@1.0.0", "Internal.Lib", "1.0.0",
        "https://nuget.corp.example.com/v3-flatcontainer/internal.lib/1.0.0/internal.lib.1.0.0.nupkg")]
    [InlineData("cargo", "pkg:cargo/internal-crate@1.0.0", "internal-crate", "1.0.0",
        "https://crates.corp.example.com/crates/internal-crate/internal-crate-1.0.0.crate")]
    [InlineData("maven", "pkg:maven/com.corp/internal@1.0.0", "com.corp:internal", "1.0.0",
        "https://artifactory.corp.example.com/maven2/com/corp/internal/1.0.0/internal-1.0.0.jar")]
    public void ForVersion_PrivateHost_ReturnsNull(
        string ecosystem, string purl, string displayName, string version, string upstreamUrl)
        => Assert.Null(RegistryPageUrl.ForVersion(ecosystem, purl, displayName, version, upstreamUrl));

    // Adversarial twin: no upstream URL recorded (uploaded/hosted version, or a repair-path proxy
    // row) has no origin to gate on — never fabricate a page.
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-url")]
    public void ForVersion_MissingOrUnparseableUpstream_ReturnsNull(string? upstreamUrl)
        => Assert.Null(RegistryPageUrl.ForVersion("npm", "pkg:npm/lodash@4.17.21", "lodash", "4.17.21", upstreamUrl));

    // A host that merely contains the public registry name as a substring must not match
    // (host equality, not a substring check) — a look-alike host is still a private lie.
    [Fact]
    public void ForVersion_LookAlikeHost_ReturnsNull()
        => Assert.Null(RegistryPageUrl.ForVersion(
            "npm", "pkg:npm/lodash@4.17.21", "lodash", "4.17.21",
            "https://registry.npmjs.org.evil.example.com/lodash/-/lodash-4.17.21.tgz"));

    // An ecosystem with no public-page mapping (e.g. rpm) returns null even from a plausible host.
    [Fact]
    public void ForVersion_UnmappedEcosystem_ReturnsNull()
        => Assert.Null(RegistryPageUrl.ForVersion(
            "rpm", "pkg:rpm/bash@5.2.15", "bash", "5.2.15",
            "https://mirror.example.org/packages/bash-5.2.15.rpm"));

    // Malformed Maven PURL (no group/artifact split) must not produce a broken Central URL.
    [Fact]
    public void ForVersion_MavenPurlWithoutGroupArtifact_ReturnsNull()
        => Assert.Null(RegistryPageUrl.ForVersion(
            "maven", "pkg:maven/justartifact@1.0.0", "justartifact", "1.0.0",
            "https://repo1.maven.org/maven2/justartifact/1.0.0/justartifact-1.0.0.jar"));
}
