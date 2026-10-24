using Dependably.Protocol.Hex;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// The built in hex.pm signing key lookup (<see cref="HexWellKnownRepositories"/>): only a URL on
/// the <c>repo.hex.pm</c> host resolves to the bundled key and the <c>hexpm</c> repository name.
/// </summary>
[Trait("Category", "Unit")]
public sealed class HexWellKnownRepositoriesTests
{
    [Theory]
    [InlineData("https://repo.hex.pm")]
    [InlineData("https://repo.hex.pm/")]
    [InlineData("https://REPO.HEX.PM/repos/hexpm")]
    public void Repo_hex_pm_resolves_to_the_bundled_key_and_name(string url)
    {
        Assert.Equal(HexWellKnownRepositories.HexpmPublicKeyPem, HexWellKnownRepositories.PublicKeyPemFor(url));
        Assert.Equal(HexWellKnownRepositories.HexpmRepositoryName, HexWellKnownRepositories.RepositoryNameFor(url));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("repo.hex.pm")]
    [InlineData("https://hex.pm")]
    [InlineData("https://repo.hex.pm.attacker.test")]
    [InlineData("https://mirror.example/repo.hex.pm")]
    public void Any_other_url_has_no_well_known_key(string? url)
    {
        Assert.Null(HexWellKnownRepositories.PublicKeyPemFor(url));
        Assert.Null(HexWellKnownRepositories.RepositoryNameFor(url));
    }

    [Fact]
    public void Bundled_key_is_a_pem_public_key()
    {
        string pem = HexWellKnownRepositories.HexpmPublicKeyPem;
        Assert.StartsWith("-----BEGIN PUBLIC KEY-----", pem, StringComparison.Ordinal);
        Assert.Contains("-----END PUBLIC KEY-----", pem, StringComparison.Ordinal);
    }
}
