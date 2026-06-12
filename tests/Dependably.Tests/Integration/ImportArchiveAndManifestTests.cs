using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Manifest-driven import covers POST /api/v1/admin/import/manifest. Archive-style import is
/// no longer a dedicated endpoint — operators send mixed-ecosystem batches through the
/// unified <c>/api/v1/admin/upload</c> path (see <see cref="UploadEndpointTests"/>).
/// </summary>
[Trait("Category", "Integration")]
public sealed class ImportArchiveAndManifestTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private readonly DependablyFactory _factory;
    public ImportArchiveAndManifestTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    [Fact]
    public async Task ImportManifest_NpmPackageLockV3_HappyPath()
    {
        var (lodashBytes, _, _) = NpmFixtures.BuildTarball("acme-mfst-lodash", "1.0.0");
        var (reactBytes, _, _) = NpmFixtures.BuildTarball("acme-mfst-react", "2.0.0");

        string lockfile = """
            {
              "name": "test",
              "version": "1.0.0",
              "lockfileVersion": 3,
              "requires": true,
              "packages": {
                "": { "name": "test", "version": "1.0.0" },
                "node_modules/acme-mfst-lodash": { "version": "1.0.0" },
                "node_modules/acme-mfst-react":  { "version": "2.0.0" }
              }
            }
            """;

        using var client = await AdminClient();
        using var content = new MultipartFormDataContent();
        var manifestPart = new ByteArrayContent(Encoding.UTF8.GetBytes(lockfile));
        manifestPart.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        content.Add(manifestPart, "manifest", "package-lock.json");
        var p1 = new ByteArrayContent(lodashBytes); content.Add(p1, "files", "acme-mfst-lodash-1.0.0.tgz");
        var p2 = new ByteArrayContent(reactBytes); content.Add(p2, "files", "acme-mfst-react-2.0.0.tgz");

        var resp = await client.PostAsync("/api/v1/admin/import/manifest", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("manifest-bulk", doc.GetProperty("mode").GetString());
        Assert.Equal("NpmPackageLock", doc.GetProperty("manifest_type").GetString());
        Assert.Equal(2, doc.GetProperty("accepted").GetInt32());
        Assert.Equal(0, doc.GetProperty("rejected").GetInt32());
    }

    [Fact]
    public async Task ImportManifest_MissingArtifact_RejectsEntireBatchAtomically()
    {
        var (lodashBytes, _, _) = NpmFixtures.BuildTarball("acme-mfst-atomic-a", "1.0.0");
        // react manifest entry is declared but no artefact uploaded — the entire batch
        // must be rejected with a 422 and zero side effects.
        string lockfile = """
            {
              "name": "test", "version": "1.0.0", "lockfileVersion": 3,
              "packages": {
                "": { "name": "test", "version": "1.0.0" },
                "node_modules/acme-mfst-atomic-a": { "version": "1.0.0" },
                "node_modules/acme-mfst-atomic-b": { "version": "2.0.0" }
              }
            }
            """;

        using var client = await AdminClient();
        using var content = new MultipartFormDataContent();
        content.Add(new ByteArrayContent(Encoding.UTF8.GetBytes(lockfile)), "manifest", "package-lock.json");
        content.Add(new ByteArrayContent(lodashBytes), "files", "acme-mfst-atomic-a-1.0.0.tgz");

        var resp = await client.PostAsync("/api/v1/admin/import/manifest", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        var missing = doc.GetProperty("manifest_entries_without_files").EnumerateArray().ToList();
        Assert.Single(missing);
        Assert.Equal("acme-mfst-atomic-b", missing[0].GetProperty("name").GetString());

        // Pre-validation rejection: zero side effects. Re-uploading just the matching file
        // through the unified endpoint confirms it's still importable (not already written).
        using var content2 = new MultipartFormDataContent();
        var part = new ByteArrayContent(lodashBytes);
        content2.Add(part, "files", "acme-mfst-atomic-a-1.0.0.tgz");
        var resp2 = await client.PostAsync("/api/v1/admin/upload", content2);
        var doc2 = JsonDocument.Parse(await resp2.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(1, doc2.GetProperty("accepted").GetInt32());
    }

    [Fact]
    public async Task ImportManifest_RequirementsTxtWithHashes_VerifiesHashes()
    {
        var (whlBytes, sha256) = PyPiFixtures.BuildWheel("acme_mfst_pip", "3.0.0");
        string requirements = $"""
            # comment
            acme-mfst-pip==3.0.0 \
                --hash=sha256:{sha256}
            """;

        using var client = await AdminClient();
        using var content = new MultipartFormDataContent();
        content.Add(new ByteArrayContent(Encoding.UTF8.GetBytes(requirements)), "manifest", "requirements.txt");
        var part = new ByteArrayContent(whlBytes);
        content.Add(part, "files", "acme_mfst_pip-3.0.0-py3-none-any.whl");

        var resp = await client.PostAsync("/api/v1/admin/import/manifest", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("PipRequirements", doc.GetProperty("manifest_type").GetString());
        Assert.Equal(1, doc.GetProperty("accepted").GetInt32());
    }

    [Fact]
    public async Task ImportManifest_PipfileLockWithHashes_VerifiesHashes()
    {
        var (whlBytes, sha256) = PyPiFixtures.BuildWheel("acme_mfst_pipenv", "4.0.0");
        string lockfile = $$"""
            {
              "_meta": { "hash": { "sha256": "deadbeef" } },
              "default": {
                "acme-mfst-pipenv": {
                  "version": "==4.0.0",
                  "hashes": ["sha256:{{sha256}}"]
                }
              },
              "develop": {}
            }
            """;

        using var client = await AdminClient();
        using var content = new MultipartFormDataContent();
        var manifestPart = new ByteArrayContent(Encoding.UTF8.GetBytes(lockfile));
        manifestPart.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        content.Add(manifestPart, "manifest", "Pipfile.lock");
        content.Add(new ByteArrayContent(whlBytes), "files", "acme_mfst_pipenv-4.0.0-py3-none-any.whl");

        var resp = await client.PostAsync("/api/v1/admin/import/manifest", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("PipfileLock", doc.GetProperty("manifest_type").GetString());
        Assert.Equal(1, doc.GetProperty("accepted").GetInt32());
    }

    [Fact]
    public async Task ImportManifest_PipfileLock_OneGoodOneBadHash_RejectsEntireBatch()
    {
        // Mixed batch: one entry's hash matches its artefact, the other's does not. The bad
        // hash must surface and reject the whole batch atomically (no partial import).
        var (goodBytes, goodSha) = PyPiFixtures.BuildWheel("acme_mfst_pipgood", "1.0.0");
        var (badBytes, _) = PyPiFixtures.BuildWheel("acme_mfst_pipbad", "2.0.0");
        string bogusSha = new('a', 64);
        string lockfile = $$"""
            {
              "_meta": { "hash": { "sha256": "deadbeef" } },
              "default": {
                "acme-mfst-pipgood": { "version": "==1.0.0", "hashes": ["sha256:{{goodSha}}"] },
                "acme-mfst-pipbad":  { "version": "==2.0.0", "hashes": ["sha256:{{bogusSha}}"] }
              }
            }
            """;

        using var client = await AdminClient();
        using var content = new MultipartFormDataContent();
        var manifestPart = new ByteArrayContent(Encoding.UTF8.GetBytes(lockfile));
        manifestPart.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        content.Add(manifestPart, "manifest", "Pipfile.lock");
        content.Add(new ByteArrayContent(goodBytes), "files", "acme_mfst_pipgood-1.0.0-py3-none-any.whl");
        content.Add(new ByteArrayContent(badBytes), "files", "acme_mfst_pipbad-2.0.0-py3-none-any.whl");

        var resp = await client.PostAsync("/api/v1/admin/import/manifest", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        var mismatches = doc.GetProperty("hash_mismatches").EnumerateArray().ToList();
        Assert.Single(mismatches);
        Assert.Equal("acme_mfst_pipbad-2.0.0-py3-none-any.whl", mismatches[0].GetProperty("filename").GetString());

        // Atomic: the good package was NOT written — re-uploading it standalone still imports.
        using var content2 = new MultipartFormDataContent();
        content2.Add(new ByteArrayContent(goodBytes), "files", "acme_mfst_pipgood-1.0.0-py3-none-any.whl");
        var resp2 = await client.PostAsync("/api/v1/admin/upload", content2);
        var doc2 = JsonDocument.Parse(await resp2.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(1, doc2.GetProperty("accepted").GetInt32());
    }

    [Fact]
    public async Task ImportManifest_PoetryLock_MatchesOnNameAndVersion()
    {
        // poetry.lock carries per-file hashes only, so the manifest entry has a null hash and
        // matches purely on name+version.
        var (whlBytes, _) = PyPiFixtures.BuildWheel("acme_mfst_poetry", "5.0.0");
        string lockfile = """
            # This file is automatically generated by Poetry and should not be changed by hand.

            [[package]]
            name = "acme-mfst-poetry"
            version = "5.0.0"
            description = "test"
            optional = false

            [metadata]
            lock-version = "2.0"
            """;

        using var client = await AdminClient();
        using var content = new MultipartFormDataContent();
        content.Add(new ByteArrayContent(Encoding.UTF8.GetBytes(lockfile)), "manifest", "poetry.lock");
        content.Add(new ByteArrayContent(whlBytes), "files", "acme_mfst_poetry-5.0.0-py3-none-any.whl");

        var resp = await client.PostAsync("/api/v1/admin/import/manifest", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("PoetryLock", doc.GetProperty("manifest_type").GetString());
        Assert.Equal(1, doc.GetProperty("accepted").GetInt32());
    }

    [Fact]
    public async Task Upload_LegacyEgg_DetectedAsPyPi()
    {
        var (eggBytes, _) = PyPiFixtures.BuildEgg("acme_mfst_egg", "0.9.0");

        using var client = await AdminClient();
        using var content = new MultipartFormDataContent();
        content.Add(new ByteArrayContent(eggBytes), "files", "acme_mfst_egg-0.9.0-py3.11.egg");

        var resp = await client.PostAsync("/api/v1/admin/upload", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(1, doc.GetProperty("accepted").GetInt32());
    }

    [Fact]
    public async Task ImportManifest_HashMismatch_Rejects422()
    {
        var (whlBytes, _) = PyPiFixtures.BuildWheel("acme_mfst_hash", "1.0.0");
        string bogusHash = new('a', 64);
        string requirements = $"acme-mfst-hash==1.0.0 --hash=sha256:{bogusHash}\n";

        using var client = await AdminClient();
        using var content = new MultipartFormDataContent();
        content.Add(new ByteArrayContent(Encoding.UTF8.GetBytes(requirements)), "manifest", "requirements.txt");
        var part = new ByteArrayContent(whlBytes);
        content.Add(part, "files", "acme_mfst_hash-1.0.0-py3-none-any.whl");

        var resp = await client.PostAsync("/api/v1/admin/import/manifest", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        var mismatches = doc.GetProperty("hash_mismatches").EnumerateArray().ToList();
        Assert.Single(mismatches);
    }

    [Fact]
    public async Task ImportManifest_OrphanArtifact_Rejects422()
    {
        // Manifest declares one package; operator uploads two. The orphan file must surface
        // as a coverage error rather than being silently imported.
        var (decBytes, _, _) = NpmFixtures.BuildTarball("acme-mfst-decl", "1.0.0");
        var (orpBytes, _, _) = NpmFixtures.BuildTarball("acme-mfst-orph", "1.0.0");
        string lockfile = """
            {
              "name": "test", "version": "1.0.0", "lockfileVersion": 3,
              "packages": {
                "": { "name": "test", "version": "1.0.0" },
                "node_modules/acme-mfst-decl": { "version": "1.0.0" }
              }
            }
            """;

        using var client = await AdminClient();
        using var content = new MultipartFormDataContent();
        content.Add(new ByteArrayContent(Encoding.UTF8.GetBytes(lockfile)), "manifest", "package-lock.json");
        content.Add(new ByteArrayContent(decBytes), "files", "acme-mfst-decl-1.0.0.tgz");
        content.Add(new ByteArrayContent(orpBytes), "files", "acme-mfst-orph-1.0.0.tgz");

        var resp = await client.PostAsync("/api/v1/admin/import/manifest", content);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        var orphans = doc.GetProperty("files_without_manifest_entries").EnumerateArray().ToList();
        Assert.Single(orphans);
        Assert.Equal("acme-mfst-orph", orphans[0].GetProperty("name").GetString());
    }

    [Fact]
    public async Task ImportManifest_ApiTokenWithImportAndConfigureCaps_Accepted()
    {
        // An API token (PAT) carrying import:* + tenant:configure must drive the admin
        // manifest-import route — it authenticates via the ApiToken scheme, not JWT-only.
        var (whlBytes, sha256) = PyPiFixtures.BuildWheel("acme_mfst_pat", "1.2.3");
        string requirements = $"acme-mfst-pat==1.2.3 --hash=sha256:{sha256}\n";

        string pat = await _factory.CreateAdminUserToken(
            """["import:*","tenant:configure","read:metadata","read:artifact"]""");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", pat);

        using var content = new MultipartFormDataContent();
        content.Add(new ByteArrayContent(Encoding.UTF8.GetBytes(requirements)), "manifest", "requirements.txt");
        content.Add(new ByteArrayContent(whlBytes), "files", "acme_mfst_pat-1.2.3-py3-none-any.whl");

        var resp = await client.PostAsync("/api/v1/admin/import/manifest", content);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(1, doc.GetProperty("accepted").GetInt32());
    }

    [Fact]
    public async Task ImportManifest_ApiTokenLackingImportCap_Forbidden()
    {
        // A publish-only PAT authenticates under the ApiToken scheme but lacks import:* —
        // it must be rejected at the capability gate (403), NOT bounced at authentication (401).
        string pat = await _factory.CreateAdminUserToken(
            """["publish:*","read:metadata","read:artifact"]""");
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", pat);

        using var content = new MultipartFormDataContent();
        content.Add(new ByteArrayContent(Encoding.UTF8.GetBytes("acme==1.0.0\n")), "manifest", "requirements.txt");
        content.Add(new ByteArrayContent([0x00]), "files", "x.whl");

        var resp = await client.PostAsync("/api/v1/admin/import/manifest", content);
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task ImportManifest_UnrecognisedManifest_400()
    {
        using var client = await AdminClient();
        using var content = new MultipartFormDataContent();
        content.Add(new ByteArrayContent(Encoding.UTF8.GetBytes("garbage")), "manifest", "weird.lock");
        var part = new ByteArrayContent([0x00]);
        content.Add(part, "files", "x.tgz");

        var resp = await client.PostAsync("/api/v1/admin/import/manifest", content);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }
}
