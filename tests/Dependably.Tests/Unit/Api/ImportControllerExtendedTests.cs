using System.Security.Cryptography;
using System.Text;
using Dependably.Infrastructure.Publish;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using NSubstitute;
using Xunit;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// Branch coverage for <c>ImportController</c> beyond the auth/content-type slice covered by
/// <c>ImportControllerUnitTests</c>. Focuses on the body of <c>Upload</c> / <c>ImportManifest</c>:
/// sha256sums sidecar paths, per-ecosystem dispatch, claim-required vs generic rejection,
/// partial-failure batches (per project rule — batch code must be tested with mixed outcomes),
/// license-emission post-accept, and the manifest coverage-report variants (hash mismatch,
/// unparseable file, orphan, missing entry).
/// </summary>
[Trait("Category", "Unit")]
public sealed class ImportControllerExtendedTests
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

    private static string Sha256Hex(byte[] bytes)
        => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static void Multipart(HttpContext ctx, FormFileCollection files)
    {
        SetForm(ctx, new FormCollection(new Dictionary<string, StringValues>(), files));
        ctx.Request.ContentType = "multipart/form-data; boundary=stub";
    }

    // ── Upload — sha256sums sidecar ─────────────────────────────────────────

    [Fact]
    public async Task Upload_Sha256Sums_Valid_AcceptsBatch()
    {
        // tarballLicense: null so the post-accept SetLicensesAsync path is skipped — this
        // is a unit test over the controller, not the LicenseRepository. The license
        // extraction branch is exercised separately below.
        var (npmBytes, _, _) = NpmFixtures.BuildTarball("acme-ext-sums-ok", "1.0.0", tarballLicense: null);
        var sidecar = $"{Sha256Hex(npmBytes)}  acme-ext-sums-ok-1.0.0.tgz\n";

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var files = new FormFileCollection
        {
            BuildFile("acme-ext-sums-ok-1.0.0.tgz", npmBytes),
            BuildFile("sha256sums", sidecar, name: "sha256sums"),
        };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.Upload(dryRun: false, CancellationToken.None);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.Equal(1, (int)ok.Value!.GetType().GetProperty("accepted")!.GetValue(ok.Value)!);
    }

    [Fact]
    public async Task Upload_Sha256Sums_Malformed_Returns422()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var files = new FormFileCollection
        {
            BuildFile("x.tgz", "garbage"),
            // Digest is non-hex / wrong length — parser throws InvalidDataException.
            BuildFile("sha256sums", "not-a-digest x.tgz\n", name: "sha256sums"),
        };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.Upload(dryRun: false, CancellationToken.None);
        var unproc = Assert.IsType<UnprocessableEntityObjectResult>(result);
        Assert.Contains("malformed", unproc.Value!.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Upload_Sha256Sums_DigestMismatch_Returns422()
    {
        var (npmBytes, _, _) = NpmFixtures.BuildTarball("acme-ext-mismatch", "1.0.0");
        // Different bytes → different digest.
        var wrong = Sha256Hex(Encoding.UTF8.GetBytes("not-the-right-bytes"));
        var sidecar = $"{wrong}  acme-ext-mismatch-1.0.0.tgz\n";

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var files = new FormFileCollection
        {
            BuildFile("acme-ext-mismatch-1.0.0.tgz", npmBytes),
            BuildFile("sha256sums", sidecar, name: "sha256sums"),
        };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.Upload(dryRun: false, CancellationToken.None);
        Assert.IsType<UnprocessableEntityObjectResult>(result);
    }

    [Fact]
    public async Task Upload_Sha256Sums_UnlistedArtefact_Returns422()
    {
        // Sidecar mentions file A; we upload file B. Unlisted-files rejects the batch.
        var (aBytes, _, _) = NpmFixtures.BuildTarball("acme-ext-listed", "1.0.0");
        var (bBytes, _, _) = NpmFixtures.BuildTarball("acme-ext-unlisted", "1.0.0");
        var sidecar = $"{Sha256Hex(aBytes)}  acme-ext-listed-1.0.0.tgz\n";

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var files = new FormFileCollection
        {
            BuildFile("acme-ext-unlisted-1.0.0.tgz", bBytes),
            BuildFile("sha256sums", sidecar, name: "sha256sums"),
        };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.Upload(dryRun: false, CancellationToken.None);
        Assert.IsType<UnprocessableEntityObjectResult>(result);
    }

    // ── Upload — per-ecosystem happy paths ──────────────────────────────────

    [Fact]
    public async Task Upload_NpmTarball_DispatchesAsNpm_AndAccepts()
    {
        var (npmBytes, _, _) = NpmFixtures.BuildTarball("acme-ext-npm-happy", "2.3.4", tarballLicense: null);

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var files = new FormFileCollection { BuildFile("acme-ext-npm-happy-2.3.4.tgz", npmBytes) };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.Upload(dryRun: false, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.Equal(1, (int)ok.Value!.GetType().GetProperty("accepted")!.GetValue(ok.Value)!);
        await s.PublishService!.Received(1).StoreAndRecordAsync(
            Arg.Is<PublishRequest>(r => r.Ecosystem == "npm"), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Upload_PyPiWheel_DispatchesAsPyPi_AndAccepts()
    {
        var (whlBytes, _) = PyPiFixtures.BuildWheel("acme_ext_pypi_happy", "1.2.3");

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var files = new FormFileCollection { BuildFile("acme_ext_pypi_happy-1.2.3-py3-none-any.whl", whlBytes) };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.Upload(dryRun: false, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.Equal(1, (int)ok.Value!.GetType().GetProperty("accepted")!.GetValue(ok.Value)!);
        await s.PublishService!.Received(1).StoreAndRecordAsync(
            Arg.Is<PublishRequest>(r => r.Ecosystem == "pypi"), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Upload_NuGetNupkg_DispatchesAsNuGet_AndAccepts()
    {
        var (nupkgBytes, _) = NuGetFixtures.BuildNupkg("Acme.Ext.NuGet.Happy", "4.5.6");

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var files = new FormFileCollection { BuildFile("Acme.Ext.NuGet.Happy.4.5.6.nupkg", nupkgBytes) };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.Upload(dryRun: false, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.Equal(1, (int)ok.Value!.GetType().GetProperty("accepted")!.GetValue(ok.Value)!);
        await s.PublishService!.Received(1).StoreAndRecordAsync(
            Arg.Is<PublishRequest>(r => r.Ecosystem == "nuget"), Arg.Any<CancellationToken>());
    }

    // ── Upload — partial-failure batch (mandated by project memory) ─────────

    [Fact]
    public async Task Upload_MixedBatch_ValidPlusGarbage_PartialFailure()
    {
        // One real npm tarball + one garbage file in the same call. Per project rule the
        // batch code path must be tested with mixed outcomes; pure all-pass / all-fail is
        // insufficient. Detector accepts the first, rejects the second; controller keeps
        // going on per-file errors.
        var (npmBytes, _, _) = NpmFixtures.BuildTarball("acme-ext-mixed", "1.0.0", tarballLicense: null);

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var files = new FormFileCollection
        {
            BuildFile("acme-ext-mixed-1.0.0.tgz", npmBytes),
            BuildFile("garbage.tgz", "not a tarball at all"),
        };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.Upload(dryRun: false, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        var accepted = (int)ok.Value!.GetType().GetProperty("accepted")!.GetValue(ok.Value)!;
        var rejected = (int)ok.Value!.GetType().GetProperty("rejected")!.GetValue(ok.Value)!;
        Assert.Equal(1, accepted);
        Assert.Equal(1, rejected);
    }

    // ── Upload — publish-pipeline rejection variants ────────────────────────

    [Fact]
    public async Task Upload_ClaimRequired_SurfacesEcosystemAndName()
    {
        // Override the mock so the publish service yields claim_required. The controller
        // is supposed to attach BOTH ecosystem and name to that outcome so the UI's
        // "claim & upload" flow has the bits it needs.
        var (npmBytes, _, _) = NpmFixtures.BuildTarball("acme-ext-claimreq", "1.0.0");

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        s.PublishService!.StoreAndRecordAsync(Arg.Any<PublishRequest>(), Arg.Any<CancellationToken>())
            .Returns(new PublishResult.Rejected(409, "claim_required", "name not claimed"));

        var files = new FormFileCollection { BuildFile("acme-ext-claimreq-1.0.0.tgz", npmBytes) };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.Upload(dryRun: false, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        var outcomes = (System.Collections.IEnumerable)ok.Value!.GetType().GetProperty("outcomes")!.GetValue(ok.Value)!;
        var rejected = outcomes.Cast<object>().Single();
        var t = rejected.GetType();
        Assert.Equal("claim_required", (string)t.GetProperty("Code")!.GetValue(rejected)!);
        Assert.Equal("npm", (string)t.GetProperty("Ecosystem")!.GetValue(rejected)!);
        Assert.Equal("acme-ext-claimreq", (string)t.GetProperty("Name")!.GetValue(rejected)!);
    }

    [Fact]
    public async Task Upload_GenericRejection_SurfacesEcosystem_NotName()
    {
        // For non-claim rejections (e.g. size_limit_exceeded, license_blocked) the controller
        // attaches ecosystem but leaves Name null so the UI can label the failure without
        // implying a claim-and-retry workflow.
        var (npmBytes, _, _) = NpmFixtures.BuildTarball("acme-ext-generic-reject", "1.0.0");

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();
        s.PublishService!.StoreAndRecordAsync(Arg.Any<PublishRequest>(), Arg.Any<CancellationToken>())
            .Returns(new PublishResult.Rejected(413, "size_limit_exceeded", "too big"));

        var files = new FormFileCollection { BuildFile("acme-ext-generic-reject-1.0.0.tgz", npmBytes) };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.Upload(dryRun: false, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        var outcomes = (System.Collections.IEnumerable)ok.Value!.GetType().GetProperty("outcomes")!.GetValue(ok.Value)!;
        var rejected = outcomes.Cast<object>().Single();
        var t = rejected.GetType();
        Assert.Equal("size_limit_exceeded", (string)t.GetProperty("Code")!.GetValue(rejected)!);
        Assert.Equal("npm", (string)t.GetProperty("Ecosystem")!.GetValue(rejected)!);
        Assert.Null(t.GetProperty("Name")!.GetValue(rejected));
    }

    [Fact]
    public async Task Upload_DryRun_AcceptedReportsWouldAccept_AndStoreNotCalled()
    {
        // Dry-run path must dispatch ValidateAsync (not StoreAndRecord) and surface the
        // status as "would_accept" so the operator can tell at a glance nothing landed.
        var (npmBytes, _, _) = NpmFixtures.BuildTarball("acme-ext-dryrun", "1.0.0", tarballLicense: null);

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var files = new FormFileCollection { BuildFile("acme-ext-dryrun-1.0.0.tgz", npmBytes) };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.Upload(dryRun: true, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        var outcomes = (System.Collections.IEnumerable)ok.Value!.GetType().GetProperty("outcomes")!.GetValue(ok.Value)!;
        var first = outcomes.Cast<object>().Single();
        Assert.Equal("would_accept", (string)first.GetType().GetProperty("Status")!.GetValue(first)!);

        await s.PublishService!.Received(1).ValidateAsync(Arg.Any<PublishRequest>(), Arg.Any<CancellationToken>());
        await s.PublishService!.DidNotReceive().StoreAndRecordAsync(Arg.Any<PublishRequest>(), Arg.Any<CancellationToken>());
    }

    // ── ImportManifest — coverage-report variants ───────────────────────────

    [Fact]
    public async Task ImportManifest_HappyPath_AllAccepted()
    {
        var (npmBytes, _, _) = NpmFixtures.BuildTarball("acme-ext-mfst-happy", "1.0.0", tarballLicense: null);
        var lockfile = """
            {
              "name": "test", "version": "1.0.0", "lockfileVersion": 3,
              "packages": {
                "": { "name": "test", "version": "1.0.0" },
                "node_modules/acme-ext-mfst-happy": { "version": "1.0.0" }
              }
            }
            """;

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var files = new FormFileCollection
        {
            BuildFile("package-lock.json", lockfile, name: "manifest"),
            BuildFile("acme-ext-mfst-happy-1.0.0.tgz", npmBytes),
        };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.ImportManifest(dryRun: false, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.Equal(1, (int)ok.Value!.GetType().GetProperty("accepted")!.GetValue(ok.Value)!);
        Assert.Equal("manifest-bulk", (string)ok.Value!.GetType().GetProperty("mode")!.GetValue(ok.Value)!);
        Assert.Equal("NpmPackageLock", (string)ok.Value!.GetType().GetProperty("manifest_type")!.GetValue(ok.Value)!);
        Assert.False(string.IsNullOrEmpty((string)ok.Value!.GetType().GetProperty("manifest_digest")!.GetValue(ok.Value)!));
    }

    [Fact]
    public async Task ImportManifest_DryRun_ReportsManifestBulkDryRun()
    {
        var (npmBytes, _, _) = NpmFixtures.BuildTarball("acme-ext-mfst-dry", "1.0.0", tarballLicense: null);
        var lockfile = """
            {
              "name": "test", "version": "1.0.0", "lockfileVersion": 3,
              "packages": {
                "": { "name": "test", "version": "1.0.0" },
                "node_modules/acme-ext-mfst-dry": { "version": "1.0.0" }
              }
            }
            """;

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var files = new FormFileCollection
        {
            BuildFile("package-lock.json", lockfile, name: "manifest"),
            BuildFile("acme-ext-mfst-dry-1.0.0.tgz", npmBytes),
        };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.ImportManifest(dryRun: true, CancellationToken.None);
        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.Equal("manifest-bulk-dryrun", (string)ok.Value!.GetType().GetProperty("mode")!.GetValue(ok.Value)!);
        Assert.True((bool)ok.Value!.GetType().GetProperty("dry_run")!.GetValue(ok.Value)!);
    }

    [Fact]
    public async Task ImportManifest_HashMismatch_Returns422WithMismatchList()
    {
        // requirements.txt declares a sha256 that won't match the wheel's actual hash.
        var (whlBytes, _) = PyPiFixtures.BuildWheel("acme_ext_mfst_hash", "1.0.0");
        var bogus = new string('a', 64);
        var requirements = $"acme-ext-mfst-hash==1.0.0 --hash=sha256:{bogus}\n";

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var files = new FormFileCollection
        {
            BuildFile("requirements.txt", requirements, name: "manifest"),
            BuildFile("acme_ext_mfst_hash-1.0.0-py3-none-any.whl", whlBytes),
        };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.ImportManifest(dryRun: false, CancellationToken.None);
        var unproc = Assert.IsType<UnprocessableEntityObjectResult>(result);
        var v = unproc.Value!;
        var mismatches = (System.Collections.IEnumerable)v.GetType().GetProperty("hash_mismatches")!.GetValue(v)!;
        Assert.Single(mismatches.Cast<object>());
    }

    [Fact]
    public async Task ImportManifest_MissingArtifact_Returns422_NoSideEffects()
    {
        // Manifest declares two packages, only one artefact uploaded. Pre-validation rejects
        // and StoreAndRecordAsync is NOT called for the one that did upload.
        var (presentBytes, _, _) = NpmFixtures.BuildTarball("acme-ext-mfst-pres", "1.0.0", tarballLicense: null);
        var lockfile = """
            {
              "name": "test", "version": "1.0.0", "lockfileVersion": 3,
              "packages": {
                "": { "name": "test", "version": "1.0.0" },
                "node_modules/acme-ext-mfst-pres":    { "version": "1.0.0" },
                "node_modules/acme-ext-mfst-missing": { "version": "2.0.0" }
              }
            }
            """;

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var files = new FormFileCollection
        {
            BuildFile("package-lock.json", lockfile, name: "manifest"),
            BuildFile("acme-ext-mfst-pres-1.0.0.tgz", presentBytes),
        };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.ImportManifest(dryRun: false, CancellationToken.None);
        var unproc = Assert.IsType<UnprocessableEntityObjectResult>(result);
        var v = unproc.Value!;
        var missing = (System.Collections.IEnumerable)v.GetType().GetProperty("manifest_entries_without_files")!.GetValue(v)!;
        Assert.Single(missing.Cast<object>());

        await s.PublishService!.DidNotReceive().StoreAndRecordAsync(Arg.Any<PublishRequest>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ImportManifest_OrphanArtifact_Returns422()
    {
        // Manifest declares one package, two artefacts uploaded. The orphan surfaces as a
        // coverage error rather than being silently imported.
        var (declBytes, _, _) = NpmFixtures.BuildTarball("acme-ext-mfst-decl", "1.0.0");
        var (orphBytes, _, _) = NpmFixtures.BuildTarball("acme-ext-mfst-orph", "1.0.0");
        var lockfile = """
            {
              "name": "test", "version": "1.0.0", "lockfileVersion": 3,
              "packages": {
                "": { "name": "test", "version": "1.0.0" },
                "node_modules/acme-ext-mfst-decl": { "version": "1.0.0" }
              }
            }
            """;

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var files = new FormFileCollection
        {
            BuildFile("package-lock.json", lockfile, name: "manifest"),
            BuildFile("acme-ext-mfst-decl-1.0.0.tgz", declBytes),
            BuildFile("acme-ext-mfst-orph-1.0.0.tgz", orphBytes),
        };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.ImportManifest(dryRun: false, CancellationToken.None);
        var unproc = Assert.IsType<UnprocessableEntityObjectResult>(result);
        var v = unproc.Value!;
        var orphans = (System.Collections.IEnumerable)v.GetType().GetProperty("files_without_manifest_entries")!.GetValue(v)!;
        Assert.Single(orphans.Cast<object>());
    }

    [Fact]
    public async Task ImportManifest_UnparseableArtifact_Returns422()
    {
        // Manifest declares the package; uploaded "artefact" is garbage bytes that the
        // EcosystemDetector can't classify, so it lands in the Unparseable bucket and the
        // batch is rejected.
        var lockfile = """
            {
              "name": "test", "version": "1.0.0", "lockfileVersion": 3,
              "packages": {
                "": { "name": "test", "version": "1.0.0" },
                "node_modules/acme-ext-mfst-unparse": { "version": "1.0.0" }
              }
            }
            """;

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var files = new FormFileCollection
        {
            BuildFile("package-lock.json", lockfile, name: "manifest"),
            BuildFile("acme-ext-mfst-unparse-1.0.0.tgz", "this is not a tarball"),
        };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.ImportManifest(dryRun: false, CancellationToken.None);
        var unproc = Assert.IsType<UnprocessableEntityObjectResult>(result);
        var v = unproc.Value!;
        var unparseable = (System.Collections.IEnumerable)v.GetType().GetProperty("unparseable_files")!.GetValue(v)!;
        Assert.Single(unparseable.Cast<object>());
    }

    [Fact]
    public async Task ImportManifest_MalformedJson_Returns400()
    {
        // package-lock.json filename is recognised, but contents fail JsonDocument.Parse —
        // the controller's ParseManifestPartAsync catches the exception and returns 400.
        var bogusLock = "{ this is not valid json";

        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "owner");
        var b = await s.BuildAsync();

        var files = new FormFileCollection
        {
            BuildFile("package-lock.json", bogusLock, name: "manifest"),
            BuildFile("x.tgz", "garbage"),
        };
        Multipart(b.ImportController.HttpContext, files);

        var result = await b.ImportController.ImportManifest(dryRun: false, CancellationToken.None);
        Assert.IsType<BadRequestObjectResult>(result);
    }
}
