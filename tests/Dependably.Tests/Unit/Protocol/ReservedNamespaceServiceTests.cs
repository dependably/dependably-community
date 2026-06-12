using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Table tests for <see cref="ReservedNamespaceService.Matches"/> — the pure per-ecosystem
/// pattern semantics: trailing-glob and case rules for npm/pypi/nuget, PEP 503 normalization
/// for pypi, and the dot-boundary groupId prefix for maven.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ReservedNamespaceServiceTests
{
    [Theory]
    // npm — ordinal on lowercase; scope globs
    [InlineData("npm", "@acme/*", "@acme/http-client", true)]
    [InlineData("npm", "@acme/*", "@acmecorp/http-client", false)]
    [InlineData("npm", "@acme/*", "@ACME/http-client", true)]   // npm names are lowercase-canonical
    [InlineData("npm", "acme-utils", "acme-utils", true)]
    [InlineData("npm", "acme-utils", "acme-utils-extra", false)] // exact pattern ≠ prefix
    [InlineData("npm", "acme-*", "acme-utils-extra", true)]
    // pypi — PEP 503 normalization on both sides
    [InlineData("pypi", "acme_tools", "acme-tools", true)]
    [InlineData("pypi", "Acme.Tools", "acme-tools", true)]
    [InlineData("pypi", "acme-*", "acme_internal_lib", true)]
    [InlineData("pypi", "acme-*", "acmeinternal", false)]
    // nuget — ids are case-insensitive
    [InlineData("nuget", "Acme.*", "acme.core", true)]
    [InlineData("nuget", "Acme.*", "ACME.Internal.Auth", true)]
    [InlineData("nuget", "Acme.Core", "acme.core", true)]
    [InlineData("nuget", "Acme.*", "Acme2.Core", false)]
    // maven — dot-boundary groupId prefix; never mid-segment
    [InlineData("maven", "com.acme", "com.acme", true)]
    [InlineData("maven", "com.acme", "com.acme.internal", true)]
    [InlineData("maven", "com.acme", "com.acmecorp", false)]
    [InlineData("maven", "com.acme.*", "com.acme.internal", true)] // tolerated spelling, same semantics
    [InlineData("maven", "com.acme*", "com.acmecorp", false)]      // '*' folds to the dot boundary
    // degenerate inputs
    [InlineData("npm", "", "anything", false)]
    [InlineData("npm", "*", "", false)]
    public void Matches_PerEcosystemSemantics(string ecosystem, string pattern, string name, bool expected)
    {
        Assert.Equal(expected, ReservedNamespaceService.Matches(ecosystem, pattern, name));
    }
}
