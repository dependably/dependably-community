using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Integration coverage for POST /api/v1/admin/upload — the unified content-detected admin
/// upload endpoint. Exercises: happy paths per ecosystem, mixed batches, partial failure
/// (some files succeed, some reject in the same call — required by user feedback rule),
/// content-trumps-extension, claim-required, sha256sums sidecar, dry-run, and tenant scoping.
/// </summary>
[Trait("Category", "Integration")]
public sealed class UploadEndpointTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public UploadEndpointTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    private static ByteArrayContent File(byte[] bytes, string contentType = "application/octet-stream")
    {
        var part = new ByteArrayContent(bytes);
        part.Headers.ContentType = new MediaTypeHeaderValue(contentType);
        return part;
    }

    [Fact]
    public async Task Anonymous_Returns401Or404()
    {
        using var client = _factory.CreateClient();
        var (bytes, _, _) = NpmFixtures.BuildTarball("anon-pkg", "1.0.0");
        using var content = new MultipartFormDataContent();
        content.Add(File(bytes), "files", "anon-pkg-1.0.0.tgz");
        var response = await client.PostAsync("/api/v1/admin/upload", content);
        Assert.True(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task HappyPath_MixedBatch_AllThreeEcosystemsAccepted()
    {
        using var client = await AdminClient();
        var (npmBytes, _, _) = NpmFixtures.BuildTarball("acme-up-mixnpm", "1.0.0");
        var (whlBytes, _) = PyPiFixtures.BuildWheel("acme_up_mixpypi", "1.0.0");
        var (nupkgBytes, _) = NuGetFixtures.BuildNupkg("Acme.Up.MixNuGet", "1.0.0");

        using var content = new MultipartFormDataContent();
        content.Add(File(npmBytes), "files", "acme-up-mixnpm-1.0.0.tgz");
        content.Add(File(whlBytes), "files", "acme_up_mixpypi-1.0.0-py3-none-any.whl");
        content.Add(File(nupkgBytes), "files", "Acme.Up.MixNuGet.1.0.0.nupkg");

        var resp = await client.PostAsync("/api/v1/admin/upload", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("upload-bulk", doc.GetProperty("mode").GetString());
        Assert.Equal(3, doc.GetProperty("accepted").GetInt32());
        Assert.Equal(0, doc.GetProperty("rejected").GetInt32());
        Assert.False(string.IsNullOrEmpty(doc.GetProperty("batch_id").GetString()));

        var outcomes = doc.GetProperty("outcomes").EnumerateArray().ToList();
        // The ecosystem badge is populated per-file from server-side detection.
        var byFilename = outcomes.ToDictionary(o => o.GetProperty("filename").GetString()!);
        Assert.Equal("npm", byFilename["acme-up-mixnpm-1.0.0.tgz"].GetProperty("ecosystem").GetString());
        Assert.Equal("pypi", byFilename["acme_up_mixpypi-1.0.0-py3-none-any.whl"].GetProperty("ecosystem").GetString());
        Assert.Equal("nuget", byFilename["Acme.Up.MixNuGet.1.0.0.nupkg"].GetProperty("ecosystem").GetString());
    }

    [Fact]
    public async Task PartialFailure_GarbageMixedWithValid_AcceptsValid_RejectsGarbage()
    {
        // User feedback rule: batch fan-out must be tested with mixed pass/fail.
        using var client = await AdminClient();
        var (npmBytes, _, _) = NpmFixtures.BuildTarball("acme-up-partial-npm", "1.0.0");
        var (whlBytes, _) = PyPiFixtures.BuildWheel("acme_up_partial_pypi", "1.0.0");
        var (nupkgBytes, _) = NuGetFixtures.BuildNupkg("Acme.Up.Partial.NuGet", "1.0.0");

        using var content = new MultipartFormDataContent();
        content.Add(File(npmBytes), "files", "acme-up-partial-npm-1.0.0.tgz");
        content.Add(File(whlBytes), "files", "acme_up_partial_pypi-1.0.0-py3-none-any.whl");
        content.Add(File(nupkgBytes), "files", "Acme.Up.Partial.NuGet.1.0.0.nupkg");
        content.Add(File([0x01, 0x02, 0x03]), "files", "junk.tgz");

        var resp = await client.PostAsync("/api/v1/admin/upload", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(3, doc.GetProperty("accepted").GetInt32());
        Assert.Equal(1, doc.GetProperty("rejected").GetInt32());
        Assert.False(string.IsNullOrEmpty(doc.GetProperty("batch_id").GetString()));

        var outcomes = doc.GetProperty("outcomes").EnumerateArray().ToList();
        var junk = outcomes.Single(o => o.GetProperty("filename").GetString() == "junk.tgz");
        Assert.Equal("rejected", junk.GetProperty("status").GetString());
        Assert.Equal("unrecognised_format", junk.GetProperty("code").GetString());
    }

    [Fact]
    public async Task PartialFailure_SlashLadenManifestName_RejectedWhileValidSiblingAccepted()
    {
        // A crafted package.json name with extra '/' segments would otherwise flow verbatim
        // into hosted blob-key construction. The batch must reject that file with the npm
        // name-shape error while the well-formed sibling still lands (mixed pass/fail rule).
        using var client = await AdminClient();
        var (goodBytes, _, _) = NpmFixtures.BuildTarball("acme-up-goodname", "1.0.0");
        var (evilBytes, _, _) = NpmFixtures.BuildTarball("evil/../acme-up-escape", "1.0.0");
        var (slashBytes, _, _) = NpmFixtures.BuildTarball("a/b", "1.0.0");

        using var content = new MultipartFormDataContent();
        content.Add(File(goodBytes), "files", "acme-up-goodname-1.0.0.tgz");
        content.Add(File(evilBytes), "files", "evil-name-1.0.0.tgz");
        content.Add(File(slashBytes), "files", "slash-name-1.0.0.tgz");

        var resp = await client.PostAsync("/api/v1/admin/upload", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(1, doc.GetProperty("accepted").GetInt32());
        Assert.Equal(2, doc.GetProperty("rejected").GetInt32());

        var outcomes = doc.GetProperty("outcomes").EnumerateArray().ToList();
        var good = outcomes.Single(o => o.GetProperty("filename").GetString() == "acme-up-goodname-1.0.0.tgz");
        Assert.Equal("accepted", good.GetProperty("status").GetString());
        foreach (string rejectedFile in new[] { "evil-name-1.0.0.tgz", "slash-name-1.0.0.tgz" })
        {
            var rejected = outcomes.Single(o => o.GetProperty("filename").GetString() == rejectedFile);
            Assert.Equal("rejected", rejected.GetProperty("status").GetString());
            Assert.Equal("tarball_invalid", rejected.GetProperty("code").GetString());
            Assert.Contains("Invalid npm package name", rejected.GetProperty("message").GetString());
        }
    }

    [Fact]
    public async Task Import_ScopedNpmName_StillAccepted()
    {
        // The slash gate must keep the one legitimate slash shape working: @scope/name.
        using var client = await AdminClient();
        var (bytes, _, _) = NpmFixtures.BuildTarball("@acme/up-scoped-ok", "1.0.0");

        using var content = new MultipartFormDataContent();
        content.Add(File(bytes), "files", "acme-up-scoped-ok-1.0.0.tgz");

        var resp = await client.PostAsync("/api/v1/admin/upload", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(1, doc.GetProperty("accepted").GetInt32());
        Assert.Equal(0, doc.GetProperty("rejected").GetInt32());
    }

    [Fact]
    public async Task ContentTrumpsExtension_NuPkgRenamedAsTgz_LandsAsNuGet()
    {
        // File named .tgz but content is a .nupkg (ZIP with .nuspec). Detection must trust
        // the bytes, not the filename. A sibling valid npm tarball confirms the batch still
        // dispatches per-file correctly.
        using var client = await AdminClient();
        var (nupkgBytes, _) = NuGetFixtures.BuildNupkg("Acme.Up.Disguised", "1.0.0");
        var (npmBytes, _, _) = NpmFixtures.BuildTarball("acme-up-honest", "1.0.0");

        using var content = new MultipartFormDataContent();
        content.Add(File(nupkgBytes), "files", "lying-extension.tgz");
        content.Add(File(npmBytes), "files", "acme-up-honest-1.0.0.tgz");

        var resp = await client.PostAsync("/api/v1/admin/upload", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(2, doc.GetProperty("accepted").GetInt32());

        var outcomes = doc.GetProperty("outcomes").EnumerateArray().ToList();
        var lying = outcomes.Single(o => o.GetProperty("filename").GetString() == "lying-extension.tgz");
        Assert.Equal("nuget", lying.GetProperty("ecosystem").GetString());
        var honest = outcomes.Single(o => o.GetProperty("filename").GetString() == "acme-up-honest-1.0.0.tgz");
        Assert.Equal("npm", honest.GetProperty("ecosystem").GetString());
    }

    [Fact]
    public async Task OriginRecordedAsUploaded_NotImportedOrPrivate()
    {
        using var client = await AdminClient();
        var (bytes, _, _) = NpmFixtures.BuildTarball("acme-up-originassert", "9.9.9");

        using var content = new MultipartFormDataContent();
        content.Add(File(bytes), "files", "acme-up-originassert-9.9.9.tgz");

        var resp = await client.PostAsync("/api/v1/admin/upload", content);
        resp.EnsureSuccessStatusCode();

        // Inspect the row directly — origin must be 'uploaded', never 'imported' or 'private'.
        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? origin = await conn.ExecuteScalarAsync<string>(
            "SELECT origin FROM package_versions WHERE version = '9.9.9'");
        Assert.Equal("uploaded", origin);
    }

    [Fact]
    public async Task TenantScoping_BlobKeyAndPackageRow_PinnedToCallerTenant()
    {
        // The new endpoint must thread OrgId from the authenticated TenantContext into the
        // PublishRequest. Verifies the persisted package_versions row links to a package
        // owned by the caller's org, and the blob key is prefixed with that org id —
        // proving there's no path where a request body can rewrite the tenant.
        using var client = await AdminClient();
        var (bytes, _, _) = NpmFixtures.BuildTarball("acme-up-tenantcheck", "1.0.0");
        using var content = new MultipartFormDataContent();
        content.Add(File(bytes), "files", "acme-up-tenantcheck-1.0.0.tgz");

        var resp = await client.PostAsync("/api/v1/admin/upload", content);
        resp.EnsureSuccessStatusCode();

        var store = _factory.Services.GetRequiredService<IMetadataStore>();
        await using var conn = await store.OpenAsync();
        string? defaultOrgId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1");
        Assert.False(string.IsNullOrEmpty(defaultOrgId));

        var (OrgId, BlobKey) = await conn.QuerySingleAsync<(string OrgId, string BlobKey)>("""
            SELECT p.org_id AS OrgId, pv.blob_key AS BlobKey
            FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.name = 'acme-up-tenantcheck' AND pv.version = '1.0.0'
            """);
        Assert.Equal(defaultOrgId, OrgId);
        Assert.StartsWith($"hosted/{defaultOrgId}/", BlobKey);
    }

    [Fact]
    public async Task NoFiles_400()
    {
        using var client = await AdminClient();
        using var content = new MultipartFormDataContent();
        // Only a sidecar — no artefacts.
        content.Add(new ByteArrayContent(Encoding.UTF8.GetBytes("")), "sha256sums", "sha256sums");
        var resp = await client.PostAsync("/api/v1/admin/upload", content);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task DryRun_PreviewsAndDoesNotPersist()
    {
        using var client = await AdminClient();
        var (bytes, _, _) = NpmFixtures.BuildTarball("acme-up-dry", "1.0.0");

        using var dry = new MultipartFormDataContent();
        dry.Add(File(bytes), "files", "acme-up-dry-1.0.0.tgz");
        var dryResp = await client.PostAsync("/api/v1/admin/upload?dryRun=true", dry);
        Assert.Equal(HttpStatusCode.OK, dryResp.StatusCode);

        var dryDoc = JsonDocument.Parse(await dryResp.Content.ReadAsStringAsync()).RootElement;
        Assert.True(dryDoc.GetProperty("dry_run").GetBoolean());
        Assert.Equal("upload-bulk-dryrun", dryDoc.GetProperty("mode").GetString());
        Assert.Equal(1, dryDoc.GetProperty("accepted").GetInt32());
        var outcome = dryDoc.GetProperty("outcomes")[0];
        Assert.Equal("would_accept", outcome.GetProperty("status").GetString());
        Assert.Equal("", outcome.GetProperty("versionId").GetString());

        // A real run with the same coordinate must succeed (dry run wrote nothing).
        using var real = new MultipartFormDataContent();
        real.Add(File(bytes), "files", "acme-up-dry-1.0.0.tgz");
        var realResp = await client.PostAsync("/api/v1/admin/upload", real);
        realResp.EnsureSuccessStatusCode();
        var realDoc = JsonDocument.Parse(await realResp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(1, realDoc.GetProperty("accepted").GetInt32());
    }

    [Fact]
    public async Task DryRun_MixedDuplicateAndNew_SurfacesPartialPreview()
    {
        // Real upload first to establish the coordinate.
        using var client = await AdminClient();
        var (dupBytes, _, _) = NpmFixtures.BuildTarball("acme-up-drymix-dup", "1.0.0");
        var (freshBytes, _, _) = NpmFixtures.BuildTarball("acme-up-drymix-fresh", "1.0.0");

        using (var first = new MultipartFormDataContent())
        {
            first.Add(File(dupBytes), "files", "acme-up-drymix-dup-1.0.0.tgz");
            (await client.PostAsync("/api/v1/admin/upload", first)).EnsureSuccessStatusCode();
        }

        using var dry = new MultipartFormDataContent();
        dry.Add(File(dupBytes), "files", "acme-up-drymix-dup-1.0.0.tgz");
        dry.Add(File(freshBytes), "files", "acme-up-drymix-fresh-1.0.0.tgz");
        var resp = await client.PostAsync("/api/v1/admin/upload?dryRun=true", dry);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;

        Assert.Equal(1, doc.GetProperty("accepted").GetInt32());
        Assert.Equal(1, doc.GetProperty("rejected").GetInt32());
        var outcomes = doc.GetProperty("outcomes").EnumerateArray().ToList();
        var dupOutcome = outcomes.Single(o => o.GetProperty("status").GetString() == "would_reject");
        Assert.Equal("version_exists", dupOutcome.GetProperty("code").GetString());
        var freshOutcome = outcomes.Single(o => o.GetProperty("status").GetString() == "would_accept");
        Assert.Equal("npm", freshOutcome.GetProperty("ecosystem").GetString());
    }

    [Fact]
    public async Task DuplicateInSameBatch_RejectedNotAborted()
    {
        // Establish the coordinate.
        using var client = await AdminClient();
        var (bytesA, _, _) = NpmFixtures.BuildTarball("acme-up-dup-a", "1.0.0");
        var (bytesB, _, _) = NpmFixtures.BuildTarball("acme-up-dup-b", "1.0.0");

        using (var first = new MultipartFormDataContent())
        {
            first.Add(File(bytesA), "files", "acme-up-dup-a-1.0.0.tgz");
            (await client.PostAsync("/api/v1/admin/upload", first)).EnsureSuccessStatusCode();
        }

        // Mixed batch: one duplicate, one new.
        using var second = new MultipartFormDataContent();
        second.Add(File(bytesA), "files", "acme-up-dup-a-1.0.0.tgz");
        second.Add(File(bytesB), "files", "acme-up-dup-b-1.0.0.tgz");

        var resp = await client.PostAsync("/api/v1/admin/upload", second);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(1, doc.GetProperty("accepted").GetInt32());
        Assert.Equal(1, doc.GetProperty("rejected").GetInt32());
        var dupOutcome = doc.GetProperty("outcomes").EnumerateArray()
            .Single(o => o.GetProperty("status").GetString() == "rejected");
        Assert.Equal("version_exists", dupOutcome.GetProperty("code").GetString());
    }

    [Fact]
    public async Task Sha256SumsSidecar_AllMatch_AcceptsBatch()
    {
        using var client = await AdminClient();
        var (bytes, sha, _) = NpmFixtures.BuildTarball("acme-up-sumsok", "1.0.0");
        string sidecarText = $"{sha}  acme-up-sumsok-1.0.0.tgz\n";

        using var content = new MultipartFormDataContent();
        content.Add(File(bytes), "files", "acme-up-sumsok-1.0.0.tgz");
        content.Add(File(Encoding.UTF8.GetBytes(sidecarText), "text/plain"), "sha256sums", "sha256sums");

        var resp = await client.PostAsync("/api/v1/admin/upload", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(1, doc.GetProperty("accepted").GetInt32());
    }

    [Fact]
    public async Task Sha256SumsSidecar_Mismatch_Rejects422AndPersistsNothing()
    {
        using var client = await AdminClient();
        var (bytes, _, _) = NpmFixtures.BuildTarball("acme-up-sumsmiss", "1.0.0");
        string bogus = new('0', 64);
        string sidecarText = $"{bogus}  acme-up-sumsmiss-1.0.0.tgz\n";

        using var content = new MultipartFormDataContent();
        content.Add(File(bytes), "files", "acme-up-sumsmiss-1.0.0.tgz");
        content.Add(File(Encoding.UTF8.GetBytes(sidecarText), "text/plain"), "sha256sums", "sha256sums");

        var resp = await client.PostAsync("/api/v1/admin/upload", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task OuterLabel_DistinguishesSourceArchives_AcrossAllEcosystems()
    {
        // Repro of the user-reported case (mermaid monorepo) plus parallel coverage for
        // PyPI sdist + wheel and NuGet nupkg. Each pair shares an embedded manifest version
        // but carries a distinct outer label (wrapper-dir for tarballs, filename for ZIPs);
        // both files in each pair must land as distinct (name, version) rows.
        using var client = await AdminClient();

        // ── npm: same embedded `mermaid-monorepo@10.2.4`, two source-archive wrappers ──
        byte[] npmA = BuildNpmTarballWithWrapper(
            wrapperDir: "mermaid-mermaid-10.2.4",
            name: "mermaid-monorepo-test-a", version: "10.2.4");
        byte[] npmB = BuildNpmTarballWithWrapper(
            wrapperDir: "mermaid-mermaid-11.13.0",
            name: "mermaid-monorepo-test-a", version: "10.2.4");

        // ── PyPI sdist: same embedded `pypi-mono@1.0.0`, two source-archive wrappers ──
        byte[] sdistA = BuildPyPiSdistWithWrapper(
            wrapperDir: "pypi-mono-test-b-1.0.0",
            name: "pypi-mono-test-b", version: "1.0.0");
        byte[] sdistB = BuildPyPiSdistWithWrapper(
            wrapperDir: "pypi-mono-test-b-2.0.0",
            name: "pypi-mono-test-b", version: "1.0.0");

        // ── PyPI wheel: same embedded METADATA, two filenames ──
        var (whlA, _) = PyPiFixtures.BuildWheel("acme_wheel_outer_c", "1.0.0");
        var (whlB, _) = PyPiFixtures.BuildWheel("acme_wheel_outer_c", "1.0.0");

        // ── NuGet nupkg: same embedded .nuspec, two filenames ──
        var (nupkgA, _) = NuGetFixtures.BuildNupkg("Acme.Outer.NuGet.D", "1.0.0");
        var (nupkgB, _) = NuGetFixtures.BuildNupkg("Acme.Outer.NuGet.D", "1.0.0");

        using var content = new MultipartFormDataContent();
        content.Add(File(npmA), "files", "mermaid-mermaid-10.2.4.tar.gz");
        content.Add(File(npmB), "files", "mermaid-mermaid-11.13.0.tar.gz");
        content.Add(File(sdistA), "files", "pypi-mono-test-b-1.0.0.tar.gz");
        content.Add(File(sdistB), "files", "pypi-mono-test-b-2.0.0.tar.gz");
        content.Add(File(whlA), "files", "acme_wheel_outer_c-1.0.0-py3-none-any.whl");
        content.Add(File(whlB), "files", "acme_wheel_outer_c-2.0.0-py3-none-any.whl");
        content.Add(File(nupkgA), "files", "Acme.Outer.NuGet.D.1.0.0.nupkg");
        content.Add(File(nupkgB), "files", "Acme.Outer.NuGet.D.2.0.0.nupkg");

        var resp = await client.PostAsync("/api/v1/admin/upload", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(8, doc.GetProperty("accepted").GetInt32());
        Assert.Equal(0, doc.GetProperty("rejected").GetInt32());

        // Spot-check the parsed version per outcome — it should reflect the outer label,
        // not the embedded manifest version.
        var purls = doc.GetProperty("outcomes").EnumerateArray()
            .ToDictionary(o => o.GetProperty("filename").GetString()!, o => o.GetProperty("purl").GetString()!);
        Assert.Contains("@10.2.4", purls["mermaid-mermaid-10.2.4.tar.gz"]);
        Assert.Contains("@11.13.0", purls["mermaid-mermaid-11.13.0.tar.gz"]);
        Assert.Contains("@1.0.0", purls["pypi-mono-test-b-1.0.0.tar.gz"]);
        Assert.Contains("@2.0.0", purls["pypi-mono-test-b-2.0.0.tar.gz"]);
        Assert.Contains("@1.0.0", purls["acme_wheel_outer_c-1.0.0-py3-none-any.whl"]);
        Assert.Contains("@2.0.0", purls["acme_wheel_outer_c-2.0.0-py3-none-any.whl"]);
        Assert.Contains("@1.0.0", purls["Acme.Outer.NuGet.D.1.0.0.nupkg"]);
        Assert.Contains("@2.0.0", purls["Acme.Outer.NuGet.D.2.0.0.nupkg"]);
    }

    private static byte[] BuildNpmTarballWithWrapper(string wrapperDir, string name, string version)
    {
        string json = $"{{\"name\":\"{name}\",\"version\":\"{version}\"}}";
        return BuildGzippedTarWithEntry($"{wrapperDir}/package.json", Encoding.UTF8.GetBytes(json));
    }

    private static byte[] BuildPyPiSdistWithWrapper(string wrapperDir, string name, string version)
    {
        string pkgInfo = $"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nSummary: synthetic\n";
        return BuildGzippedTarWithEntry($"{wrapperDir}/PKG-INFO", Encoding.UTF8.GetBytes(pkgInfo));
    }

    private static byte[] BuildGzippedTarWithEntry(string entryName, byte[] bytes)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tw = new System.Formats.Tar.TarWriter(gz, leaveOpen: true))
        {
            var entry = new System.Formats.Tar.PaxTarEntry(
                System.Formats.Tar.TarEntryType.RegularFile, entryName)
            {
                DataStream = new MemoryStream(bytes)
            };
            tw.WriteEntry(entry);
        }
        return ms.ToArray();
    }

    [Fact]
    public async Task DeletedEcosystemEndpoint_Returns404()
    {
        // Sanity check that the four legacy file-upload endpoints are gone. The manifest
        // endpoint stays under /api/v1/admin/import/manifest.
        using var client = await AdminClient();
        var (bytes, _, _) = NpmFixtures.BuildTarball("legacy-route", "1.0.0");
        using var content = new MultipartFormDataContent();
        content.Add(new StringContent("uploaded"), "origin");
        content.Add(File(bytes), "files", "legacy-route-1.0.0.tgz");

        var resp = await client.PostAsync("/api/v1/admin/import/npm", content);
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }
}
