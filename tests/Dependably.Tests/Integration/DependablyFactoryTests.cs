using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

[Trait("Category", "Integration")]
public sealed class DependablyFactoryTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public DependablyFactoryTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task HealthEndpoint_Returns200()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/health");
        Assert.Equal(System.Net.HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task ReadyEndpoint_Returns200_WhenDbReady()
    {
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/ready");
        Assert.Equal(System.Net.HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task CreateToken_ReturnsBearerThatAuthenticates()
    {
        string token = await _factory.CreateToken("pull");
        using var client = _factory.CreateClientWithBearer(token);
        // A pull token should authenticate against the PyPI simple index (anonymous_pull = 0 by default)
        var resp = await client.GetAsync("/simple/");
        Assert.NotEqual(System.Net.HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task CreateAdminToken_ReturnsValidToken()
    {
        string token = await _factory.CreateAdminToken();
        Assert.False(string.IsNullOrEmpty(token));
    }

    [Fact]
    public async Task PushPyPiPackage_StoresPackageInBlobStore()
    {
        await _factory.PushPyPiPackage("test-pkg", "1.0.0");
        Assert.True(await _factory.BlobStore.GetTotalSizeAsync() > 0);
    }

    [Fact]
    public async Task PushNpmPackage_StoresPackageInBlobStore()
    {
        long sizeBefore = await _factory.BlobStore.GetTotalSizeAsync();
        await _factory.PushNpmPackage("test-npm-pkg", "1.0.0");
        Assert.True(await _factory.BlobStore.GetTotalSizeAsync() > sizeBefore);
    }

    [Fact]
    public async Task PushNuGetPackage_StoresPackageInBlobStore()
    {
        long sizeBefore = await _factory.BlobStore.GetTotalSizeAsync();
        await _factory.PushNuGetPackage("TestPkg", "1.0.0");
        Assert.True(await _factory.BlobStore.GetTotalSizeAsync() > sizeBefore);
    }

    [Fact]
    public async Task FixtureFiles_ExistAndMatchManifestHashes()
    {
        Assert.Equal(
            FixtureManifest.MypyExtensionsWheelSha256,
            Sha256OfFixture("pypi", "mypy_extensions-1.0.0-py3-none-any.whl"));

        Assert.Equal(
            FixtureManifest.MypyExtensionsSdistSha256,
            Sha256OfFixture("pypi", "mypy_extensions-1.0.0.tar.gz"));

        Assert.Equal(
            FixtureManifest.IsOddTarballSha256,
            Sha256OfFixture("npm", "is-odd-3.0.1.tgz"));

        Assert.Equal(
            FixtureManifest.NewtonsoftJsonNupkgSha256,
            Sha256OfFixture("nuget", "Newtonsoft.Json.13.0.3.nupkg"));
    }

    private static string Sha256OfFixture(string ecosystem, string filename)
    {
        string path = Path.Combine(FixtureManifest.FixturesRoot, ecosystem, filename);
        byte[] bytes = File.ReadAllBytes(path);
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
    }
}
