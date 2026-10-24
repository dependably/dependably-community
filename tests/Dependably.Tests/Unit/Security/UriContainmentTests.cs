using Dependably.Security;

namespace Dependably.Tests.Unit.Security;

/// <summary>
/// The base-URL containment check (<see cref="UriContainment"/>) that governs both a Terraform
/// mirror's published archive URL and every redirect hop after it. Containment is decided on parsed
/// scheme, host, port and path segments, never on a string prefix.
/// </summary>
[Trait("Category", "Unit")]
public sealed class UriContainmentTests
{
    private const string Base = "https://mirror.example/terraform";

    [Theory]
    [InlineData("https://mirror.example/terraform/hashicorp/aws/aws_5.0.0.zip", Base)]
    [InlineData("https://mirror.example/terraform/x.zip", Base + "/")]
    [InlineData("https://MIRROR.EXAMPLE/terraform/x.zip", Base)]
    [InlineData("HTTPS://mirror.example/terraform/x.zip", Base)]
    [InlineData("https://mirror.example:443/terraform/x.zip", Base)]
    [InlineData("https://mirror.example/x.zip", "https://mirror.example")]
    [InlineData("https://mirror.example/x.zip", "https://mirror.example/")]
    public void Url_under_the_base_path_on_the_same_origin_is_beneath(string candidate, string baseUrl) =>
        Assert.True(UriContainment.IsBeneath(new Uri(candidate), baseUrl));

    [Theory]
    [InlineData("https://mirror.example/terraform-evil/x.zip")]
    [InlineData("https://mirror.example/terraform")]
    [InlineData("https://mirror.example/Terraform/x.zip")]
    [InlineData("https://mirror.example/terraform/../evil/x.zip")]
    [InlineData("http://mirror.example/terraform/x.zip")]
    [InlineData("https://mirror.example:8443/terraform/x.zip")]
    [InlineData("https://other.example/terraform/x.zip")]
    [InlineData("https://mirror.example.attacker.test/terraform/x.zip")]
    public void Url_off_the_base_is_not_beneath(string candidate) =>
        Assert.False(UriContainment.IsBeneath(new Uri(candidate), Base));

    [Theory]
    [InlineData("")]
    [InlineData("terraform")]
    [InlineData("not a url")]
    public void Unparseable_base_contains_nothing(string baseUrl) =>
        Assert.False(UriContainment.IsBeneath(new Uri("https://mirror.example/terraform/x.zip"), baseUrl));
}
