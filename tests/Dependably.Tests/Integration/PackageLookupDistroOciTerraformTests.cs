using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// <c>GET /api/v1/lookup</c> over the wire for the ecosystems that have no PURL-keyed OSV answer:
/// the <c>advisorySource</c> wire shape (camelCase), the explicit terraform "not applicable", an
/// apk lookup with no determinable release, and the input problems for the new parameters.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PackageLookupDistroOciTerraformTests : IClassFixture<DependablyFactory>
{
    private const string Digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    private readonly DependablyFactory _factory;

    public PackageLookupDistroOciTerraformTests(DependablyFactory factory) => _factory = factory;

    private async Task<HttpClient> MemberClientAsync()
    {
        string userId = await _factory.CreateUser($"lookup-{Guid.NewGuid():N}@example.com", "Password12345");
        return _factory.CreateClientWithBearer(await _factory.CreateUserJwt(userId, "member"));
    }

    [Fact]
    public async Task Terraform_ReportsNotApplicable_OnTheWire()
    {
        using var client = await MemberClientAsync();

        var resp = await client.GetAsync("/api/v1/lookup?ecosystem=terraform&name=hashicorp/aws&version=5.31.0");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        var source = body.GetProperty("advisorySource");
        Assert.Equal("not_applicable", source.GetProperty("status").GetString());
        Assert.Equal("no_advisory_source", source.GetProperty("reason").GetString());
        Assert.False(body.GetProperty("vulnerabilities").GetProperty("available").GetBoolean());
    }

    [Fact]
    public async Task Apk_WithoutARelease_AndNoDerivableUpstream_SaysDistroRequired_NotClean()
    {
        using var client = await MemberClientAsync();

        var resp = await client.GetAsync("/api/v1/lookup?ecosystem=apk&name=curl&version=8.5.0-r0");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        var source = body.GetProperty("advisorySource");
        Assert.Equal("unavailable", source.GetProperty("status").GetString());
        Assert.Equal("distro_required", source.GetProperty("reason").GetString());
        Assert.False(body.GetProperty("vulnerabilities").GetProperty("available").GetBoolean());
        Assert.Equal("warn", body.GetProperty("verdict").GetString());
    }

    [Fact]
    public async Task Oci_ImageNobodyScanned_IsUnavailable_NeverClean()
    {
        using var client = await MemberClientAsync();

        var resp = await client.GetAsync($"/api/v1/lookup?ecosystem=oci&name=team/app&version={Uri.EscapeDataString(Digest)}");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("no_scan_result", body.GetProperty("advisorySource").GetProperty("reason").GetString());
        Assert.False(body.GetProperty("vulnerabilities").GetProperty("available").GetBoolean());
    }

    [Theory]
    [InlineData("ecosystem=apk&name=curl&version=8.5.0-r0&distro=edge", "distro")]
    [InlineData("ecosystem=rpm&name=openssl&version=3.0.7-24.el9&distro=Debian%3A12", "distro")]
    [InlineData("ecosystem=oci&name=team/app&version=latest", "version")]
    [InlineData("ecosystem=apk&name=curl&version=8.5.0&distro=v3.20", "version")]
    [InlineData("ecosystem=rpm&name=openssl&version=3.0.7&distro=Rocky%20Linux%3A9", "version")]
    public async Task InvalidNewInputs_Return422_WithTheFieldNamed(string query, string field)
    {
        using var client = await MemberClientAsync();

        var resp = await client.GetAsync($"/api/v1/lookup?{query}");

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        var problem = await resp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(field, problem.GetProperty("field").GetString());
    }

    [Fact]
    public async Task OpenApiDescription_StatesTheNotApplicableVerdict()
    {
        using var client = await MemberClientAsync();

        string spec = await client.GetStringAsync("/openapi/management.json");

        Assert.Contains("not_applicable", spec, StringComparison.Ordinal);
        Assert.Contains("verdict allowed", spec, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("apk")]
    [InlineData("rpm")]
    [InlineData("oci")]
    [InlineData("terraform")]
    public async Task EcosystemsEndpoint_AdvertisesTheLookupPlane(string ecosystem)
    {
        using var client = await MemberClientAsync();

        var resp = await client.GetAsync("/api/v1/ecosystems");

        var body = await resp.Content.ReadFromJsonAsync<JsonElement>();
        var lookup = body.GetProperty("planes").GetProperty("lookup").EnumerateArray().Select(e => e.GetString());
        Assert.Contains(ecosystem, lookup);
    }
}
