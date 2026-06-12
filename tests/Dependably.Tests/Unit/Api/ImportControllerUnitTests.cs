using System.Text;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// ImportController has two endpoints (admin/upload, admin/import/manifest) over the
/// IPackagePublishService pipeline. Tests focus on the auth + content-type + form
/// validation branches; the storage pipeline is NSubstituted via ControllerScenario so
/// the SUT is just the controller.
///
/// Multipart-form happy-path tests stay in the integration suite — round-tripping a
/// real wheel/tgz through the publish service is the integration concern.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ImportControllerUnitTests
{
    // ── Auth + content-type branches (Upload) ───────────────────────────────

    [Fact]
    public async Task Upload_Anonymous_RejectedByGuard()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.ImportController.Upload(dryRun: false, CancellationToken.None);
        Assert.False(result is OkObjectResult);
    }

    [Fact]
    public async Task Upload_Member_Forbidden_NoTenantConfigure()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        var b = await s.BuildAsync();

        var result = await b.ImportController.Upload(dryRun: false, CancellationToken.None);
        Assert.False(result is OkObjectResult);
    }

    [Fact]
    public async Task Upload_NonMultipartContentType_Returns400()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        b.ImportController.Request.ContentType = "application/json";

        var result = await b.ImportController.Upload(dryRun: false, CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Upload_MultipartButNoFiles_Returns400()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Pre-bake an empty form so ReadFormAsync returns 0 files.
        SetForm(b.ImportController.HttpContext, new FormCollection(
            new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>(), new FormFileCollection()));
        b.ImportController.Request.ContentType = "multipart/form-data; boundary=stub";

        var result = await b.ImportController.Upload(dryRun: false, CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Upload_GarbageFile_RecordsAsRejected_NotAccepted()
    {
        // The publish service mock returns Accepted, but the controller's per-file
        // EcosystemDetector runs BEFORE the publish call — garbage bytes return a Rejected
        // outcome at the detector stage. Pin that behaviour.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var files = new FormFileCollection
        {
            BuildFile("notapackage.tgz", "not gzipped data here"),
        };
        SetForm(b.ImportController.HttpContext, new FormCollection(
            new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>(), files));
        b.ImportController.Request.ContentType = "multipart/form-data; boundary=stub";

        var result = await b.ImportController.Upload(dryRun: false, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        int rejected = (int)ok.Value!.GetType().GetProperty("rejected")!.GetValue(ok.Value)!;
        int accepted = (int)ok.Value!.GetType().GetProperty("accepted")!.GetValue(ok.Value)!;
        Assert.Equal(1, rejected);
        Assert.Equal(0, accepted);
    }

    [Fact]
    public async Task Upload_DryRunFlag_ReflectedInResponseMode()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        SetForm(b.ImportController.HttpContext, new FormCollection(
            new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>(),
            new FormFileCollection { BuildFile("x.tgz", "garbage") }));
        b.ImportController.Request.ContentType = "multipart/form-data; boundary=stub";

        var result = await b.ImportController.Upload(dryRun: true, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        string mode = (string)ok.Value!.GetType().GetProperty("mode")!.GetValue(ok.Value)!;
        Assert.Equal("upload-bulk-dryrun", mode);
        bool dryRun = (bool)ok.Value!.GetType().GetProperty("dry_run")!.GetValue(ok.Value)!;
        Assert.True(dryRun);
    }

    // ── Manifest endpoint ────────────────────────────────────────────────────

    [Fact]
    public async Task ImportManifest_NonMultipart_Returns400()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        b.ImportController.Request.ContentType = "application/json";

        var result = await b.ImportController.ImportManifest(dryRun: false, CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task ImportManifest_MissingManifestPart_Returns400()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        // Multipart form but with only "files" — no "manifest" part.
        var files = new FormFileCollection
        {
            BuildFile("acme-1.0.0.tgz", "fake", name: "files"),
        };
        SetForm(b.ImportController.HttpContext, new FormCollection(
            new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>(), files));
        b.ImportController.Request.ContentType = "multipart/form-data; boundary=stub";

        var result = await b.ImportController.ImportManifest(dryRun: false, CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task ImportManifest_UnknownManifestType_Returns400()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        var files = new FormFileCollection
        {
            BuildFile("strange-manifest.yaml", "yaml: not-an-osv-manifest", name: "manifest"),
        };
        SetForm(b.ImportController.HttpContext, new FormCollection(
            new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>(), files));
        b.ImportController.Request.ContentType = "multipart/form-data; boundary=stub";

        var result = await b.ImportController.ImportManifest(dryRun: false, CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task ImportManifest_EmptyManifestEntries_Returns400()
    {
        // Valid manifest type (requirements.txt extension) but the content has no parseable
        // entries — the controller rejects with "Manifest contains no package entries."
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        var files = new FormFileCollection
        {
            BuildFile("requirements.txt", "# comment only\n# nothing pinned\n", name: "manifest"),
        };
        SetForm(b.ImportController.HttpContext, new FormCollection(
            new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>(), files));
        b.ImportController.Request.ContentType = "multipart/form-data; boundary=stub";

        var result = await b.ImportController.ImportManifest(dryRun: false, CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task ImportManifest_Anonymous_Rejected()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); s.WithNoUser();
        var b = await s.BuildAsync();

        var result = await b.ImportController.ImportManifest(dryRun: false, CancellationToken.None);
        Assert.False(result is OkObjectResult);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static void SetForm(HttpContext ctx, IFormCollection form)
    {
        ctx.Features.Set<IFormFeature>(new FormFeature(form));
    }

    private static FormFile BuildFile(string filename, string content, string name = "files")
    {
        byte[] bytes = Encoding.UTF8.GetBytes(content);
        return new FormFile(
            new MemoryStream(bytes), 0, bytes.Length, name, filename)
        {
            Headers = new HeaderDictionary(),
            ContentType = "application/octet-stream",
        };
    }
}
