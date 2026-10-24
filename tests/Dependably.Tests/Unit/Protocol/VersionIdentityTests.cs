using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

[Trait("Category", "Unit")]
public sealed class VersionIdentityTests
{
    [Theory]
    [InlineData("nuget", true)]
    [InlineData("pypi", true)]
    [InlineData("npm", false)]
    [InlineData("golang", false)]
    [InlineData("cargo", false)]
    [InlineData("maven", false)]
    [InlineData("hex", false)]
    [InlineData("terraform", false)]
    [InlineData("rpm", false)]
    public void CaseFolding_AppliesOnlyToNuGetAndPyPi(string ecosystem, bool folds)
    {
        Assert.Equal(folds, VersionIdentity.IsCaseInsensitive(ecosystem));
        Assert.Equal(folds, VersionIdentity.Equal(ecosystem, "1.0.0-RC1", "1.0.0-rc1"));
        Assert.Equal(folds, VersionIdentity.Comparer(ecosystem).Equals("1.0.0-RC1", "1.0.0-rc1"));
        Assert.True(VersionIdentity.Equal(ecosystem, "1.0.0", "1.0.0"));
    }

    [Theory]
    [InlineData("1.0.0-rc1", "1.0.0rc1")]
    [InlineData("1.0.0.rc1", "1.0.0rc1")]
    [InlineData("1.0.0_rc1", "1.0.0rc1")]
    [InlineData("v1.0", "1.0")]
    [InlineData("1.0alpha1", "1.0a1")]
    [InlineData("1.0beta2", "1.0b2")]
    [InlineData("1.0c1", "1.0rc1")]
    [InlineData("1.0preview1", "1.0rc1")]
    [InlineData("1.0-post1", "1.0.post1")]
    [InlineData("1.0rev1", "1.0.post1")]
    [InlineData("1.0-1", "1.0.post1")]
    [InlineData("1.0.post", "1.0.post0")]
    [InlineData("1.0.dev", "1.0.dev0")]
    [InlineData("1.0a", "1.0a0")]
    [InlineData("01.002", "1.2")]
    [InlineData("0!1.0", "1.0")]
    [InlineData("1.0+Ubuntu-1", "1.0+ubuntu.1")]
    public void PyPi_FoldsPep440Spellings(string left, string right)
    {
        Assert.True(VersionIdentity.Equal("pypi", left, right));
        Assert.True(VersionIdentity.Comparer("pypi").Equals(left, right));
        Assert.Equal(VersionIdentity.Comparer("pypi").GetHashCode(left), VersionIdentity.Comparer("pypi").GetHashCode(right));
        Assert.Equal(Pep440Canonical.Canonicalize(right), Pep440Canonical.Canonicalize(left));
    }

    [Theory]
    [InlineData("1.0rc1", "1.0rc2")]
    [InlineData("1.0", "1.0.0")]
    [InlineData("1.0a1", "1.0b1")]
    [InlineData("1.0.post1", "1.0.dev1")]
    [InlineData("1!1.0", "1.0")]
    [InlineData("not a version", "not-a-version")]
    public void PyPi_KeepsDistinctVersionsDistinct(string left, string right)
    {
        Assert.False(VersionIdentity.Equal("pypi", left, right));
        Assert.False(VersionIdentity.Comparer("pypi").Equals(left, right));
    }

    [Theory]
    [InlineData("npm")]
    [InlineData("nuget")]
    [InlineData("cargo")]
    [InlineData("maven")]
    public void OtherEcosystems_DoNotFoldPep440Spellings(string ecosystem)
    {
        Assert.False(VersionIdentity.Equal(ecosystem, "1.0.0-rc1", "1.0.0rc1"));
        Assert.False(VersionIdentity.Equal(ecosystem, "v1.0", "1.0"));
    }

    [Theory]
    [InlineData("1.0.0-RC1", "1.0.0rc1")]
    [InlineData("v1.0", "1.0")]
    [InlineData(" 1.0alpha1 ", "1.0a1")]
    [InlineData("1.0-post1", "1.0.post1")]
    [InlineData("2!1.0.0_DEV", "2!1.0.0.dev0")]
    public void Canonicalize_ProducesPep440Form(string raw, string expected) =>
        Assert.Equal(expected, Pep440Canonical.Canonicalize(raw));

    [Fact]
    public void Canonicalize_NonPep440_FallsBackToTrimmedLowerCase() =>
        Assert.Equal("junk!!", Pep440Canonical.Canonicalize(" JUNK!! "));

    [Theory]
    [InlineData("npm")]
    [InlineData("pypi")]
    [InlineData("nuget")]
    [InlineData("maven")]
    public void Equal_TwoNullVersions_AreTheSame_ButNullNeverEqualsAValue(string ecosystem)
    {
        Assert.True(VersionIdentity.Equal(ecosystem, null, null));
        Assert.False(VersionIdentity.Equal(ecosystem, null, "1.0.0"));
        Assert.False(VersionIdentity.Equal(ecosystem, "1.0.0", null));
        Assert.False(VersionIdentity.Equal(ecosystem, null, ""));
    }

    [Fact]
    public void Pep440Comparer_HandlesNullAndReferenceEqualInputs()
    {
        var comparer = VersionIdentity.Comparer("pypi");
        string version = "1.0.0rc1";

        Assert.True(comparer.Equals(null, null));
        Assert.True(comparer.Equals(version, version));
        Assert.False(comparer.Equals(null, version));
        Assert.False(comparer.Equals(version, null));
    }

    [Fact]
    public void Comparer_NuGetFoldsCase_AndOthersUseOrdinalIdentity()
    {
        Assert.Equal(
            VersionIdentity.Comparer("nuget").GetHashCode("1.0.0-RC1"),
            VersionIdentity.Comparer("nuget").GetHashCode("1.0.0-rc1"));
        Assert.Equal(
            VersionIdentity.Comparer("npm").GetHashCode("1.0.0-rc.1"),
            VersionIdentity.Comparer("npm").GetHashCode("1.0.0-rc.1"));
        Assert.False(VersionIdentity.Comparer("npm").Equals("1.0.0-RC.1", "1.0.0-rc.1"));
    }
}
