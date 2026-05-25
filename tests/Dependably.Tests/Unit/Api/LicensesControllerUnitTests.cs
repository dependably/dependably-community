using Dependably.Api;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Unit coverage for <see cref="LicensesController"/>. The controller reads a notices.json
/// file from <see cref="AppContext.BaseDirectory"/>; the integration suite only exercises the
/// "file missing → dev-mode stub" branch because Docker writes that file, not `dotnet run`.
/// These tests cover both branches by writing/removing the file at test time and asserting
/// that concurrent test runs do not race (each test serializes around the shared path).
/// </summary>
[Trait("Category", "Unit")]
[Collection("LicensesController file IO")]
public sealed class LicensesControllerUnitTests
{
    private static readonly string NoticesPath =
        Path.Combine(AppContext.BaseDirectory, "notices.json");

    [Fact]
    public async Task Get_ReturnsDevModeStub_WhenNoticesFileMissing()
    {
        EnsureNoNoticesFile();

        var controller = new LicensesController();
        var result = await controller.Get(CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.NotNull(ok.Value);
        var payload = ok.Value!;
        var type = payload.GetType();
        Assert.True((bool)type.GetProperty("devModeStub")!.GetValue(payload)!);
        Assert.Equal(0, (int)type.GetProperty("count")!.GetValue(payload)!);
        Assert.Null(type.GetProperty("generatedAt")!.GetValue(payload));
        var components = type.GetProperty("components")!.GetValue(payload);
        Assert.NotNull(components);
        Assert.Empty((System.Collections.IEnumerable)components!);
    }

    [Fact]
    public async Task Get_ReturnsFileContents_WhenNoticesFilePresent()
    {
        const string json = """{"generatedAt":"2026-05-21T00:00:00Z","count":1,"components":[{"name":"x"}]}""";
        try
        {
            await File.WriteAllTextAsync(NoticesPath, json);

            var controller = new LicensesController();
            var result = await controller.Get(CancellationToken.None);

            var content = Assert.IsType<ContentResult>(result);
            Assert.Equal(json, content.Content);
            Assert.Equal("application/json; charset=utf-8", content.ContentType);
        }
        finally
        {
            EnsureNoNoticesFile();
        }
    }

    [Fact]
    public async Task Get_HonoursCancellationToken_WhenFilePresent()
    {
        const string json = """{"generatedAt":null,"count":0,"components":[]}""";
        try
        {
            await File.WriteAllTextAsync(NoticesPath, json);
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            var controller = new LicensesController();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => controller.Get(cts.Token));
        }
        finally
        {
            EnsureNoNoticesFile();
        }
    }

    private static void EnsureNoNoticesFile()
    {
        if (File.Exists(NoticesPath))
        {
            File.Delete(NoticesPath);
        }
    }
}

[CollectionDefinition("LicensesController file IO", DisableParallelization = true)]
public sealed class LicensesControllerFileIoCollection
{
}
