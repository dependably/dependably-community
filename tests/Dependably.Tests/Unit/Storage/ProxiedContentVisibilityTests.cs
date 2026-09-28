using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit.Storage;

/// <summary>
/// The upstream-backed visibility rule: a proxied blob is public only when the org's upstreams
/// for its ecosystem are all credential-free, with the serve path's ecosystem name mapped onto
/// the upstream table's (Go serves as <c>go</c>, configures as <c>golang</c>), and never on an
/// edge node, whose upstream is its master.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ProxiedContentVisibilityTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public ProxiedContentVisibilityTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private UpstreamRegistryRepository Repo() => new(_fixture.Store, TimeProvider.System, TestEnvelope.Configured());

    private UpstreamProxiedContentVisibility Sut(bool edge = false)
        => new(Repo(), new EdgeMode(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["DEPLOYMENT_MODE"] = edge ? "edge" : "single",
            ["EDGE_MASTER_URL"] = edge ? "https://master.example" : null,
        }).Build()));

    [Fact]
    public async Task GoServePath_ReadsTheGolangUpstreams()
    {
        string org = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await Repo().AddAsync(org, new NewUpstreamRegistry("golang", "https://proxy.golang.org"));

        Assert.True(await Sut().IsPublicAsync(org, "go"));

        await Repo().AddAsync(org, new NewUpstreamRegistry("golang", "https://goproxy.private.example", AuthType: "basic", Username: "u", Secret: "p"));

        Assert.False(await Sut().IsPublicAsync(org, "go"));
    }

    [Fact]
    public async Task EdgeNode_IsNeverPublic_EvenWithAnonymousUpstreams()
    {
        string org = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await Repo().AddAsync(org, new NewUpstreamRegistry("npm", "https://registry.npmjs.org"));

        Assert.True(await Sut().IsPublicAsync(org, "npm"));
        Assert.False(await Sut(edge: true).IsPublicAsync(org, "npm"));
    }

    [Theory]
    [InlineData("go", "golang")]
    [InlineData("npm", "npm")]
    [InlineData("oci", "oci")]
    [InlineData("terraform", "terraform")]
    [InlineData("hex", "hex")]
    [InlineData("golang", "golang")]
    [InlineData("gem", null)]
    [InlineData("", null)]
    public void UpstreamEcosystem_MapsServeNamesOntoUpstreamRows(string serve, string? expected)
        => Assert.Equal(expected, UpstreamProxiedContentVisibility.UpstreamEcosystem(serve));
}
