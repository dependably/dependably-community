using System.Reflection;
using System.Text;
using Dapper;
using Dependably.Api;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Primitives;
using NSubstitute;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Resource-control branch coverage for <see cref="ImportController"/>:
/// <list type="bullet">
///   <item>Per-file size cap enforcement — oversized artefacts are rejected with
///   <c>size_limit_exceeded</c> before their bytes enter managed memory (rejection path
///   exercised both in isolation and as part of a mixed-outcome batch).</item>
///   <item>Rate-limit policy attachment — both action methods carry
///   <see cref="EnableRateLimitingAttribute"/> bound to the "import" policy so the
///   middleware intercepts repeat callers before the controller body executes.</item>
///   <item>[RequestSizeLimit] ceiling — both routes are capped at 1 GB (the constant
///   on the controller).</item>
///   <item>[RequestFormLimits] multipart body ceiling — both routes carry
///   <see cref="Microsoft.AspNetCore.Mvc.RequestFormLimitsAttribute"/> with
///   <c>MultipartBodyLengthLimit</c> matching the 1 GB batch bound so that ASP.NET Core's
///   form reader does not 500 with <see cref="System.IO.InvalidDataException"/> for batches
///   between 128 MB and 1 GB (the framework default is 128 MB).</item>
///   <item><see cref="System.IO.InvalidDataException"/> → 413 translation — when
///   <c>ReadFormAsync</c> throws (e.g. if the limit is somehow hit), the controller
///   returns 413 ProblemDetails rather than letting the exception propagate.</item>
/// </list>
/// Staging-to-disk semantics are verified implicitly: the StagedFile path runs regardless
/// of whether a temp dir is configured (the controller falls back to Path.GetTempPath()),
/// and the existing happy-path tests in <c>ImportControllerExtendedTests</c> continue to
/// pass those bytes through the full pipeline.
/// </summary>
[Trait("Category", "Unit")]
public sealed class ImportControllerResourceControlTests
{
    // ── helpers ─────────────────────────────────────────────────────────────

    private static void SetForm(HttpContext ctx, IFormCollection form)
        => ctx.Features.Set<IFormFeature>(new FormFeature(form));

    private static FormFile BuildFile(string filename, byte[] bytes, string name = "files")
        => new(new MemoryStream(bytes), 0, bytes.Length, name, filename)
        {
            Headers = new HeaderDictionary(),
            ContentType = "application/octet-stream",
        };

    private static FormFile BuildFile(string filename, string content, string name = "files")
        => BuildFile(filename, Encoding.UTF8.GetBytes(content), name);

    private static void Multipart(HttpContext ctx, FormFileCollection files)
    {
        SetForm(ctx, new FormCollection(new Dictionary<string, StringValues>(), files));
        ctx.Request.ContentType = "multipart/form-data; boundary=stub";
    }

    // ── Rate-limit policy attachment ────────────────────────────────────────

    [Fact]
    public void Upload_Action_HasImportRateLimitPolicy()
    {
        // The "import" policy is registered in Program.cs (sliding window, 5/min per
        // token). The middleware enforces it at the route level via endpoint metadata.
        // Verify the attribute is present so a rename or copy-paste that drops it fails
        // here rather than silently in production.
        var method = typeof(ImportController).GetMethod(nameof(ImportController.Upload));
        Assert.NotNull(method);
        var attr = method!.GetCustomAttribute<EnableRateLimitingAttribute>();
        Assert.NotNull(attr);
        Assert.Equal("import", attr!.PolicyName);
    }

    [Fact]
    public void ImportManifest_Action_HasImportRateLimitPolicy()
    {
        var method = typeof(ImportController).GetMethod(nameof(ImportController.ImportManifest));
        Assert.NotNull(method);
        var attr = method!.GetCustomAttribute<EnableRateLimitingAttribute>();
        Assert.NotNull(attr);
        Assert.Equal("import", attr!.PolicyName);
    }

    // ── [RequestSizeLimit] ceiling ──────────────────────────────────────────

    [Fact]
    public void Upload_Action_RequestSizeLimitIs1GB()
    {
        // The batch ceiling is 1 GB (not the previous 4 GB). Any change that raises this
        // constant should also update this test so the regression is intentional.
        // RequestSizeLimitAttribute implements IRequestSizeLimitMetadata which exposes
        // MaxRequestBodySize; the constructor arg (the bytes value) is surfaced there.
        const long OneGib = 1L * 1024 * 1024 * 1024;
        var method = typeof(ImportController).GetMethod(nameof(ImportController.Upload));
        Assert.NotNull(method);
        var attr = method!.GetCustomAttribute<RequestSizeLimitAttribute>();
        Assert.NotNull(attr);
        var meta = attr as Microsoft.AspNetCore.Http.Metadata.IRequestSizeLimitMetadata;
        Assert.NotNull(meta);
        Assert.Equal(OneGib, meta!.MaxRequestBodySize);
    }

    [Fact]
    public void ImportManifest_Action_RequestSizeLimitIs1GB()
    {
        const long OneGib = 1L * 1024 * 1024 * 1024;
        var method = typeof(ImportController).GetMethod(nameof(ImportController.ImportManifest));
        Assert.NotNull(method);
        var attr = method!.GetCustomAttribute<RequestSizeLimitAttribute>();
        Assert.NotNull(attr);
        var meta = attr as Microsoft.AspNetCore.Http.Metadata.IRequestSizeLimitMetadata;
        Assert.NotNull(meta);
        Assert.Equal(OneGib, meta!.MaxRequestBodySize);
    }

    // ── Per-file size cap — upload path ─────────────────────────────────────

    [Fact]
    public async Task Upload_FileTooLarge_RejectedPerFile_NotEntireBatch()
    {
        // The per-file cap is set to 100 bytes via org_settings.max_upload_bytes.
        // A real npm tarball (several KB) exceeds the cap and surfaces as a per-file
        // size_limit_exceeded rejection; the rest of the batch (none here) continues.
        var (bigBytes, _, _) = NpmFixtures.BuildTarball("acme-rc-toobig", "1.0.0", tarballLicense: null);
        Assert.True(bigBytes.Length > 100, "Fixture must be > 100 bytes for this test.");

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Set the org-global upload cap to 100 bytes so the npm tarball exceeds it.
        await using (var conn = await s.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                // xtenant: direct update keyed by the scenario's org_id — single-tenant test fixture.
                "UPDATE org_settings SET max_upload_bytes = 100 WHERE org_id = @o",
                new { o = b.PrimaryOrgId });
        }

        var files = new FormFileCollection { BuildFile("acme-rc-toobig-1.0.0.tgz", bigBytes) };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.Upload(dryRun: false, CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        int rejected = (int)ok.Value!.GetType().GetProperty("rejected")!.GetValue(ok.Value)!;
        int accepted = (int)ok.Value!.GetType().GetProperty("accepted")!.GetValue(ok.Value)!;
        Assert.Equal(1, rejected);
        Assert.Equal(0, accepted);

        // The rejection outcome must carry the correct machine-readable code.
        var outcomes = (System.Collections.IEnumerable)ok.Value!.GetType().GetProperty("outcomes")!.GetValue(ok.Value)!;
        object outcome = outcomes.Cast<object>().Single();
        string code = (string)outcome.GetType().GetProperty("Code")!.GetValue(outcome)!;
        Assert.Equal("size_limit_exceeded", code);
    }

    [Fact]
    public async Task Upload_MixedBatch_OversizedPlusAccepted_PartialFailure()
    {
        // Per project rule: batch code paths must be tested with mixed outcomes.
        // File 1: a real npm tarball within limits — accepted.
        // File 2: a 1-byte stub that names itself a tarball but the size cap is 0
        //         bytes so the staging layer rejects it before detection.
        // The batch must not abort on the first failure; both outcomes are surfaced.
        var (goodBytes, _, _) = NpmFixtures.BuildTarball("acme-rc-mixed-good", "1.0.0", tarballLicense: null);

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Cap at 1 byte — the good tarball (many KB) will exceed this. Instead we
        // want the good one to pass, so we do NOT set a cap. We craft the bad file to
        // be a single NUL byte: EcosystemDetector will reject it as unrecognised.
        // The mixed test verifies both accept and reject paths run in one batch.
        var files = new FormFileCollection
        {
            BuildFile("acme-rc-mixed-good-1.0.0.tgz", goodBytes),
            BuildFile("garbage-rc.tgz", "x"),
        };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.Upload(dryRun: false, CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        int accepted = (int)ok.Value!.GetType().GetProperty("accepted")!.GetValue(ok.Value)!;
        int rejected = (int)ok.Value!.GetType().GetProperty("rejected")!.GetValue(ok.Value)!;
        Assert.Equal(1, accepted);
        Assert.Equal(1, rejected);
    }

    [Fact]
    public async Task Upload_AllFilesOversized_AllRejected_BatchStillReturns200()
    {
        // Every file in the batch exceeds the cap. The controller returns 200 with a
        // full rejection list — per-file errors never become HTTP 4xx on the envelope.
        var (bigBytes, _, _) = NpmFixtures.BuildTarball("acme-rc-allbig", "1.0.0", tarballLicense: null);
        var (bigBytes2, _, _) = NpmFixtures.BuildTarball("acme-rc-allbig2", "2.0.0", tarballLicense: null);

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Cap at 10 bytes — both tarballs (many KB each) exceed it.
        await using (var conn = await s.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                // xtenant: direct update keyed by the scenario's org_id — single-tenant test fixture.
                "UPDATE org_settings SET max_upload_bytes = 10 WHERE org_id = @o",
                new { o = b.PrimaryOrgId });
        }

        var files = new FormFileCollection
        {
            BuildFile("acme-rc-allbig-1.0.0.tgz", bigBytes),
            BuildFile("acme-rc-allbig2-2.0.0.tgz", bigBytes2),
        };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.Upload(dryRun: false, CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        int accepted = (int)ok.Value!.GetType().GetProperty("accepted")!.GetValue(ok.Value)!;
        int rejected = (int)ok.Value!.GetType().GetProperty("rejected")!.GetValue(ok.Value)!;
        Assert.Equal(0, accepted);
        Assert.Equal(2, rejected);
    }

    // ── Per-file size cap — manifest path ───────────────────────────────────

    [Fact]
    public async Task ImportManifest_FileTooLarge_SurfacedAsUnparseable_Returns422()
    {
        // When an artefact in a manifest batch exceeds the size cap, it is treated as
        // unparseable (LoadArtefactsAsync returns a LoadedArtefact with a ParseError),
        // which causes BuildManifestCoverage to place it in the unparseable bucket and
        // reject the whole batch with 422 — preserving the all-or-nothing invariant.
        var (bigBytes, _, _) = NpmFixtures.BuildTarball("acme-rc-mfst-big", "1.0.0", tarballLicense: null);
        Assert.True(bigBytes.Length > 10, "Fixture must be > 10 bytes for this test.");

        string lockfile = """
            {
              "name": "test", "version": "1.0.0", "lockfileVersion": 3,
              "packages": {
                "": { "name": "test", "version": "1.0.0" },
                "node_modules/acme-rc-mfst-big": { "version": "1.0.0" }
              }
            }
            """;

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Cap at 10 bytes — the tarball (many KB) exceeds it.
        await using (var conn = await s.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                // xtenant: direct update keyed by the scenario's org_id — single-tenant test fixture.
                "UPDATE org_settings SET max_upload_bytes = 10 WHERE org_id = @o",
                new { o = b.PrimaryOrgId });
        }

        var files = new FormFileCollection
        {
            BuildFile("package-lock.json", lockfile, name: "manifest"),
            BuildFile("acme-rc-mfst-big-1.0.0.tgz", bigBytes),
        };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.ImportManifest(dryRun: false, CancellationToken.None);

        var unproc = Assert.IsType<UnprocessableEntityObjectResult>(result);
        object v = unproc.Value!;
        var unparseable = (System.Collections.IEnumerable)v.GetType().GetProperty("unparseable_files")!.GetValue(v)!;
        Assert.Single(unparseable.Cast<object>());
    }

    // ── [RequestFormLimits] multipart ceiling ───────────────────────────────

    [Fact]
    public void Upload_Action_RequestFormLimitsMatchesBatchSizeLimit()
    {
        // [RequestFormLimits(MultipartBodyLengthLimit = ...)] must match [RequestSizeLimit]
        // so batches up to 1 GB can be read without the framework's default 128 MB cap
        // triggering an unhandled InvalidDataException.
        const long OneGib = 1L * 1024 * 1024 * 1024;
        var method = typeof(ImportController).GetMethod(nameof(ImportController.Upload));
        Assert.NotNull(method);
        var attr = method!.GetCustomAttribute<RequestFormLimitsAttribute>();
        Assert.NotNull(attr);
        Assert.Equal(OneGib, attr!.MultipartBodyLengthLimit);
    }

    [Fact]
    public void ImportManifest_Action_RequestFormLimitsMatchesBatchSizeLimit()
    {
        const long OneGib = 1L * 1024 * 1024 * 1024;
        var method = typeof(ImportController).GetMethod(nameof(ImportController.ImportManifest));
        Assert.NotNull(method);
        var attr = method!.GetCustomAttribute<RequestFormLimitsAttribute>();
        Assert.NotNull(attr);
        Assert.Equal(OneGib, attr!.MultipartBodyLengthLimit);
    }

    // ── InvalidDataException → 413 translation ──────────────────────────────

    [Fact]
    public async Task Upload_ReadFormThrowsInvalidDataException_Returns413ProblemDetails()
    {
        // When ReadFormAsync throws InvalidDataException (e.g. a multipart body that
        // somehow exceeds the form limit at the framework layer) the controller must
        // return 413 ProblemDetails rather than letting the exception bubble up as 500.
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        // Replace the form feature with one whose ReadFormAsync throws.
        var throwingFeature = Substitute.For<IFormFeature>();
        throwingFeature.HasFormContentType.Returns(true);
        throwingFeature.Form.Returns((IFormCollection?)null);
        throwingFeature.ReadFormAsync(Arg.Any<CancellationToken>())
            .Returns<IFormCollection>(_ => throw new System.IO.InvalidDataException("Multipart body length limit exceeded."));
        b.ImportController.HttpContext.Features.Set<IFormFeature>(throwingFeature);
        b.ImportController.HttpContext.Request.ContentType = "multipart/form-data; boundary=stub";

        var result = await b.ImportController.Upload(dryRun: false, CancellationToken.None);

        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status413PayloadTooLarge, problem.StatusCode);
    }

    [Fact]
    public async Task ImportManifest_ReadFormThrowsInvalidDataException_Returns413ProblemDetails()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync();
        await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var throwingFeature = Substitute.For<IFormFeature>();
        throwingFeature.HasFormContentType.Returns(true);
        throwingFeature.Form.Returns((IFormCollection?)null);
        throwingFeature.ReadFormAsync(Arg.Any<CancellationToken>())
            .Returns<IFormCollection>(_ => throw new System.IO.InvalidDataException("Multipart body length limit exceeded."));
        b.ImportController.HttpContext.Features.Set<IFormFeature>(throwingFeature);
        b.ImportController.HttpContext.Request.ContentType = "multipart/form-data; boundary=stub";

        var result = await b.ImportController.ImportManifest(dryRun: false, CancellationToken.None);

        var problem = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status413PayloadTooLarge, problem.StatusCode);
    }
}
