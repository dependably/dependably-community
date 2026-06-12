using Dependably.Configuration;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class OciOptionsValidatorTests
{
    private static readonly OciOptionsValidator Validator = new();

    private static OciUpstreamRegistryOptions ValidUpstream() => new()
    {
        Name = "dockerhub",
        Host = "registry-1.docker.io",
        AuthType = OciAuthType.Anonymous,
        Prefixes = [""],
    };

    private static OciOptions ValidOptions() => new()
    {
        ManifestTagTtl = TimeSpan.FromMinutes(5),
        TokenCacheDuration = TimeSpan.FromMinutes(55),
        UpstreamHttpTimeout = TimeSpan.FromMinutes(30),
        Upstreams = [ValidUpstream()],
    };

    [Fact]
    public void Validate_DefaultValidConfig_Succeeds()
    {
        var result = Validator.Validate(null, ValidOptions());
        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_NoUpstreams_Succeeds()
    {
        // An empty upstream list is legal — the proxy simply has nowhere to route, which the
        // resolver handles by returning null. Only malformed entries are rejected here.
        var opts = ValidOptions();
        opts.Upstreams = [];
        Assert.True(Validator.Validate(null, opts).Succeeded);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_NonPositiveTimeSpans_Fail(int seconds)
    {
        var span = TimeSpan.FromSeconds(seconds);
        var opts = ValidOptions();
        opts.ManifestTagTtl = span;
        opts.TokenCacheDuration = span;
        opts.UpstreamHttpTimeout = span;

        var result = Validator.Validate(null, opts);

        Assert.True(result.Failed);
        Assert.Contains("Oci:ManifestTagTtl must be positive.", result.Failures!);
        Assert.Contains("Oci:TokenCacheDuration must be positive.", result.Failures!);
        Assert.Contains("Oci:UpstreamHttpTimeout must be positive.", result.Failures!);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_MissingNameOrHost_Fail(string blank)
    {
        var opts = ValidOptions();
        opts.Upstreams[0].Name = blank;
        opts.Upstreams[0].Host = blank;

        var result = Validator.Validate(null, opts);

        Assert.True(result.Failed);
        Assert.Contains("Oci:Upstreams[0].Name is required.", result.Failures!);
        Assert.Contains("Oci:Upstreams[0].Host is required.", result.Failures!);
    }

    [Fact]
    public void Validate_BasicAuthWithoutCredentials_Fails()
    {
        var opts = ValidOptions();
        opts.Upstreams[0].AuthType = OciAuthType.Basic;
        opts.Upstreams[0].Username = null;
        opts.Upstreams[0].Password = null;

        var result = Validator.Validate(null, opts);

        Assert.True(result.Failed);
        Assert.Contains("Oci:Upstreams[0] AuthType=Basic requires Username.", result.Failures!);
        Assert.Contains("Oci:Upstreams[0] AuthType=Basic requires Password.", result.Failures!);
    }

    [Fact]
    public void Validate_BasicAuthWithCredentials_Succeeds()
    {
        var opts = ValidOptions();
        opts.Upstreams[0].AuthType = OciAuthType.Basic;
        opts.Upstreams[0].Username = "robot";
        opts.Upstreams[0].Password = "s3cret";

        Assert.True(Validator.Validate(null, opts).Succeeded);
    }

    [Fact]
    public void Validate_AwsEcrWithoutRegion_Fails()
    {
        var opts = ValidOptions();
        opts.Upstreams[0].AuthType = OciAuthType.AwsEcr;
        opts.Upstreams[0].AwsRegion = null;

        var result = Validator.Validate(null, opts);

        Assert.True(result.Failed);
        Assert.Contains("Oci:Upstreams[0] AuthType=AwsEcr requires AwsRegion.", result.Failures!);
    }

    [Fact]
    public void Validate_AwsEcrWithRegion_Succeeds()
    {
        var opts = ValidOptions();
        opts.Upstreams[0].AuthType = OciAuthType.AwsEcr;
        opts.Upstreams[0].AwsRegion = "us-east-1";

        Assert.True(Validator.Validate(null, opts).Succeeded);
    }

    [Fact]
    public void Validate_ReportsIndexOfOffendingUpstream()
    {
        var opts = ValidOptions();
        opts.Upstreams = [ValidUpstream(), new OciUpstreamRegistryOptions { Name = "", Host = "" }];

        var result = Validator.Validate(null, opts);

        Assert.True(result.Failed);
        Assert.Contains("Oci:Upstreams[1].Name is required.", result.Failures!);
        Assert.Contains("Oci:Upstreams[1].Host is required.", result.Failures!);
    }
}
