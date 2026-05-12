using System.Net;
using Dependably.Security;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Security")]
public class PathSafeValidatorTests
{
    [Theory]
    [InlineData("../etc/passwd")]
    [InlineData("foo/../bar")]
    [InlineData("../../etc")]
    public void Validate_PathTraversal_Fails(string input)
    {
        var result = PathSafeValidator.Validate(input, "field");
        Assert.False(result.IsValid);
    }

    [Theory]
    [InlineData("foo/bar")]
    [InlineData("foo\\bar")]
    public void Validate_PathSeparator_Fails(string input)
    {
        var result = PathSafeValidator.Validate(input, "field");
        Assert.False(result.IsValid);
    }

    [Fact]
    public void Validate_NullByte_Fails()
    {
        var result = PathSafeValidator.Validate("foo\0bar", "field");
        Assert.False(result.IsValid);
    }

    [Fact]
    public void Validate_Empty_Fails()
    {
        var result = PathSafeValidator.Validate("", "field");
        Assert.False(result.IsValid);
    }

    [Fact]
    public void Validate_TooLong_Fails()
    {
        var result = PathSafeValidator.Validate(new string('a', 201), "field");
        Assert.False(result.IsValid);
    }

    [Theory]
    [InlineData("requests")]
    [InlineData("my-package")]
    [InlineData("lodash")]
    [InlineData("Newtonsoft.Json")]
    [InlineData("1.0.0")]
    [InlineData("2.1.0-beta.1")]
    public void Validate_ValidInputs_Passes(string input)
    {
        var result = PathSafeValidator.Validate(input, "field");
        Assert.True(result.IsValid);
    }
}

[Trait("Category", "Security")]
public class HeaderInjectionTests
{
    [Fact]
    public void SanitizeHeader_StripsCRLF()
    {
        const string purl = "pkg:pypi/requests@2.28.0\r\nX-Injected: evil";
        var sanitized = SanitizeHeader(purl);
        // CRLF stripped — injection cannot create a separate HTTP header
        Assert.DoesNotContain('\r', sanitized);
        Assert.DoesNotContain('\n', sanitized);
    }

    [Fact]
    public void SanitizeHeader_StripsNullByte()
    {
        const string purl = "pkg:pypi/requests@2.28.0\0extra";
        var sanitized = SanitizeHeader(purl);
        Assert.DoesNotContain('\0', sanitized);
    }

    [Fact]
    public void SanitizeHeader_LeavesValidPurlUnchanged()
    {
        const string purl = "pkg:npm/%40angular/core@15.0.0";
        Assert.Equal(purl, SanitizeHeader(purl));
    }

    // Replicates the SanitizeHeader method from controllers
    private static string SanitizeHeader(string value)
        => value.Replace("\r", "").Replace("\n", "").Replace("\0", "");
}

[Trait("Category", "Security")]
public class UpstreamUrlValidatorTests
{
    [Theory]
    [InlineData("http://127.0.0.1/packages")]
    [InlineData("http://127.0.0.100/packages")]
    [InlineData("http://10.0.0.1/packages")]
    [InlineData("http://172.16.0.1/packages")]
    [InlineData("http://172.31.255.255/packages")]
    [InlineData("http://192.168.1.1/packages")]
    [InlineData("http://169.254.169.254/metadata")]  // AWS metadata endpoint
    [InlineData("http://100.64.0.1/packages")]
    public void ValidateUrl_BlockedIp_ReturnsError(string url)
    {
        var error = UpstreamUrlValidator.ValidateUrl(url);
        Assert.NotNull(error);
    }

    [Theory]
    [InlineData("ftp://pypi.org/packages")]
    [InlineData("file:///etc/passwd")]
    [InlineData("not-a-url")]
    public void ValidateUrl_InvalidSchemeOrFormat_ReturnsError(string url)
    {
        var error = UpstreamUrlValidator.ValidateUrl(url);
        Assert.NotNull(error);
    }

    [Theory]
    [InlineData("https://pypi.org")]
    [InlineData("https://registry.npmjs.org")]
    [InlineData("https://api.nuget.org/v3")]
    [InlineData("http://my-private-registry.example.com")]
    public void ValidateUrl_PublicUrl_ReturnsNull(string url)
    {
        var error = UpstreamUrlValidator.ValidateUrl(url);
        Assert.Null(error);
    }
}
