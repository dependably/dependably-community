using System.Net;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Runtime regression coverage for the SPA + Swagger static assets after the management-plane
/// extraction. The Svelte SPA and the vendored Swagger UI live under <c>wwwroot</c> in the
/// <c>Dependably.Management</c> project (they moved there with the management plane). The
/// composition root serves them from a physical <c>wwwroot</c> directory copied into its own build
/// and publish output via a <c>Content</c> link over <c>../Dependably.Management/wwwroot/**</c> —
/// <c>Program.ConfigureApp</c>'s <c>ManifestEmbeddedFileProvider</c> falls through to a
/// <see cref="Microsoft.Extensions.FileProviders.PhysicalFileProvider"/> rooted at
/// <c>AppContext.BaseDirectory/wwwroot</c>, which is exactly this copied tree.
///
/// If that Content link were dropped or mis-pathed when wwwroot moved to the class library, the
/// host would build and publish with an empty <c>wwwroot</c> and silently serve a blank SPA — the
/// top runtime-only regression risk of the split. These tests pin that the tracked
/// <c>wwwroot/swagger</c> assets reach the host output and that the running app serves them, so a
/// broken retarget fails here rather than shipping a blank UI. They assert against the committed
/// swagger assets rather than the Vite-built top-level <c>index.html</c>, so they hold in the test
/// environment where the frontend is not built.
/// </summary>
[Trait("Category", "Integration")]
public sealed class EmbeddedSpaAssetsTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;

    public EmbeddedSpaAssetsTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void ManagementWwwroot_IsCopiedIntoHostOutput()
    {
        // The composition root's Content link copies Dependably.Management/wwwroot into its own
        // output tree (bin/.../wwwroot). The tracked swagger assets are always present (the SPA's
        // top-level index.html is Vite-built and absent in the test environment), so assert on
        // those: their presence proves the referenced library's wwwroot reaches the host.
        string wwwroot = Path.Combine(AppContext.BaseDirectory, "wwwroot");
        string swaggerShell = Path.Combine(wwwroot, "swagger", "index.html");
        string swaggerCss = Path.Combine(wwwroot, "swagger", "swagger-ui.css");

        Assert.True(File.Exists(swaggerShell),
            $"swagger/index.html must be copied from the Management wwwroot into the host output ({swaggerShell})");
        Assert.True(File.Exists(swaggerCss),
            $"swagger/swagger-ui.css must be copied from the Management wwwroot into the host output ({swaggerCss})");
        Assert.True(new FileInfo(swaggerShell).Length > 0);
    }

    [Fact]
    public async Task ProtocolSwaggerAsset_IsServedFromHostWwwroot()
    {
        // End-to-end: the running app serves a swagger static asset from the physical wwwroot
        // through the protocol Swagger UI mount (/docs/, public — not IP-gated). A 200 with real
        // CSS bytes proves the static-file middleware resolves the copied Management wwwroot.
        using var client = _factory.CreateClient();
        var resp = await client.GetAsync("/docs/swagger-ui.css");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        string css = await resp.Content.ReadAsStringAsync();
        Assert.NotEmpty(css);
    }
}
