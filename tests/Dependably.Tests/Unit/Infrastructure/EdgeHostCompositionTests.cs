extern alias edge;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using EdgeProgram = edge::Program;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The edge composition root (<c>Dependably.Edge</c>'s <c>Program.ConfigureBuilder</c>) must build
/// with <c>ValidateOnBuild</c> and <c>ValidateScopes</c> on. The edge root turns both on only in
/// Development, and every edge test host runs as Production, so without this test a captive
/// dependency in the protocol-only graph would first surface on a developer's machine. The graph
/// is built and its hosted services resolved, never started.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EdgeHostCompositionTests : IDisposable
{
    private readonly string _dataDir =
        Path.Combine(Path.GetTempPath(), "dependably-edge-composition-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task EdgeHost_BuildsWithScopeValidation_AndResolvesEveryHostedService()
    {
        var builder = WebApplication.CreateBuilder();
        TestHostEnv.PinAmbient(builder, deploymentMode: "edge");
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["EDGE_MASTER_URL"] = "https://master.invalid",
            ["EDGE_MASTER_TOKEN"] = "edge-composition-token",
            ["REDIS_CONNECTION_STRING"] = "",
            ["DB_PATH"] = Path.Combine(_dataDir, "dependably.db"),
            ["LOCAL_STORAGE_PATH"] = Path.Combine(_dataDir, "blobs"),
        });

        EdgeProgram.ConfigureBuilder(builder);

        // Applied after ConfigureBuilder so it holds whatever environment the test runs under.
        builder.Host.UseDefaultServiceProvider(o =>
        {
            o.ValidateOnBuild = true;
            o.ValidateScopes = true;
        });

        await using var app = builder.Build();

        var hosted = app.Services.GetServices<IHostedService>().ToList();
        Assert.NotEmpty(hosted);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dataDir, recursive: true);
        }
        catch (DirectoryNotFoundException)
        {
            // Nothing was written.
        }
    }
}
