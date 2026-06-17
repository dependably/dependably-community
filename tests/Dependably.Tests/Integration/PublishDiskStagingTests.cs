using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Verifies that the three publish handlers (npm, PyPI, NuGet) stage uploads to disk
/// rather than buffering in RAM, and that staging files are always cleaned up — both on
/// success and on every failure path.
///
/// Uses a dedicated factory instance that pins PROXY_STAGING_PATH to a unique per-run
/// temp directory so staging-file count assertions are isolated from the shared singleton.
///
/// Mixed partial-failure coverage (house rule): sequential calls to the same endpoint
/// where some succeed, some fail with 413 (oversized), and some fail with 422
/// (bad checksum / corrupt body) — all with staging cleanup asserted after each call.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PublishDiskStagingTests : IAsyncLifetime
{
    private readonly string _stagingDir =
        System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"dep-staging-test-{Guid.NewGuid():N}");

    private readonly DependablyFactory _factory;

    public PublishDiskStagingTests()
    {
        Directory.CreateDirectory(_stagingDir);
        _factory = new DependablyFactory { StagingPath = _stagingDir };
    }

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();

    public async Task DisposeAsync()
    {
        await ((IAsyncLifetime)_factory).DisposeAsync();
        if (Directory.Exists(_stagingDir))
        {
            Directory.Delete(_stagingDir, recursive: true);
        }
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns the count of staging temp files still present in the pinned staging directory.
    /// A well-behaved handler leaves 0 after every request completes.
    /// </summary>
    private int StagingFileCount()
        => Directory.GetFiles(_stagingDir, "publish-stage-*.tmp").Length;

    private async Task<string> PushToken() => await _factory.CreateToken("push");

    private static MultipartFormDataContent BuildPyPiUploadForm(
        string name, string version, byte[] bytes, string sha256, string filename)
    {
        var content = new MultipartFormDataContent
        {
            { new StringContent("file_upload"), ":action" },
            { new StringContent("2.1"), "metadata_version" },
            { new StringContent(name), "name" },
            { new StringContent(version), "version" },
            { new StringContent(sha256), "sha256_digest" },
            { new StringContent("bdist_wheel"), "filetype" },
        };
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "content", filename);
        return content;
    }

    private static string BasicAuthHeader(string token)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes($"user:{token}"));

    // ── PyPI ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task PyPi_SuccessfulUpload_LeavesNoStagingFiles()
    {
        string token = await PushToken();
        var (bytes, sha256) = PyPiFixtures.BuildWheel("staging-happy-pypi", "1.0.0");
        string filename = "staging_happy_pypi-1.0.0-py3-none-any.whl";

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Basic", BasicAuthHeader(token));

        using var form = BuildPyPiUploadForm("staging-happy-pypi", "1.0.0", bytes, sha256, filename);
        var resp = await client.PostAsync("/pypi/legacy/", form);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(0, StagingFileCount());
    }

    [Fact]
    public async Task PyPi_BadChecksum_Returns422_LeavesNoStagingFiles()
    {
        string token = await PushToken();
        var (bytes, _) = PyPiFixtures.BuildWheel("staging-bad-hash-pypi", "1.0.0");
        string filename = "staging_bad_hash_pypi-1.0.0-py3-none-any.whl";

        // Supply a wrong SHA-256 digest — the handler stages first, then rejects, then cleans up.
        string wrongSha256 = new('a', 64);

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Basic", BasicAuthHeader(token));

        using var form = BuildPyPiUploadForm("staging-bad-hash-pypi", "1.0.0", bytes, wrongSha256, filename);
        var resp = await client.PostAsync("/pypi/legacy/", form);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        Assert.Equal(0, StagingFileCount());
    }

    /// <summary>
    /// Mixed partial-failure: three sequential PyPI calls — good, oversized (413),
    /// bad checksum (422). Each call must leave 0 staging files.
    ///
    /// The 413 case specifically pins the "stage first, size-check second, clean up"
    /// path in PyPiController.Upload: staging happens before CheckPyPiUploadSizeAsync,
    /// so the cleanup in the finally block is the only guard against leaking the file.
    /// </summary>
    [Fact]
    public async Task PyPi_MixedPartialFailure_AllCallsCleanUpStagingFiles()
    {
        string token = await PushToken();

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Basic", BasicAuthHeader(token));

        // Call 1 — good wheel: must succeed and leave no staging files.
        var (goodBytes, goodSha256) = PyPiFixtures.BuildWheel("staging-mix-pypi", "1.0.0");
        string goodFilename = "staging_mix_pypi-1.0.0-py3-none-any.whl";
        using (var form = BuildPyPiUploadForm("staging-mix-pypi", "1.0.0", goodBytes, goodSha256, goodFilename))
        {
            var r1 = await client.PostAsync("/pypi/legacy/", form);
            Assert.Equal(HttpStatusCode.OK, r1.StatusCode);
        }

        Assert.Equal(0, StagingFileCount());

        // Call 2 — oversized: 1-byte org limit fires after staging.
        await _factory.SetOrgLimit("default", "pypi", 1L);
        try
        {
            var (oversizedBytes, oversizedSha256) = PyPiFixtures.BuildWheel("staging-mix-big-pypi", "1.0.0");
            string oversizedFilename = "staging_mix_big_pypi-1.0.0-py3-none-any.whl";
            using var oversizedForm = BuildPyPiUploadForm(
                "staging-mix-big-pypi", "1.0.0", oversizedBytes, oversizedSha256, oversizedFilename);
            var r2 = await client.PostAsync("/pypi/legacy/", oversizedForm);
            Assert.Equal(HttpStatusCode.RequestEntityTooLarge, r2.StatusCode);
        }
        finally
        {
            await _factory.SetOrgLimit("default", "pypi", null);
        }

        Assert.Equal(0, StagingFileCount());

        // Call 3 — bad checksum: correct bytes but wrong digest string.
        var (corruptBytes, _) = PyPiFixtures.BuildWheel("staging-mix-corrupt-pypi", "2.0.0");
        string corruptFilename = "staging_mix_corrupt_pypi-2.0.0-py3-none-any.whl";
        using (var form = BuildPyPiUploadForm(
            "staging-mix-corrupt-pypi", "2.0.0", corruptBytes, new('b', 64), corruptFilename))
        {
            var r3 = await client.PostAsync("/pypi/legacy/", form);
            Assert.Equal(HttpStatusCode.UnprocessableEntity, r3.StatusCode);
        }

        Assert.Equal(0, StagingFileCount());
    }

    // ── NuGet ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task NuGet_SuccessfulPush_LeavesNoStagingFiles()
    {
        string token = await PushToken();
        var (bytes, _) = NuGetFixtures.BuildNupkg("Staging.Happy.NuGet", "1.0.0");
        string filename = "Staging.Happy.NuGet.1.0.0.nupkg";

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        using var content = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "package", filename);

        var resp = await client.PutAsync("/nuget/publish", content);

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        Assert.Equal(0, StagingFileCount());
    }

    /// <summary>
    /// Mixed partial-failure: valid push, then oversized (413), then corrupt nupkg (422/400).
    /// The staging file for both failures must be cleaned up by the finally block in PushPackage.
    /// </summary>
    [Fact]
    public async Task NuGet_MixedPartialFailure_AllCallsCleanUpStagingFiles()
    {
        string token = await PushToken();

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-NuGet-ApiKey", token);

        // Call 1 — valid push.
        var (goodBytes, _) = NuGetFixtures.BuildNupkg("Staging.Mix.NuGet", "1.0.0");
        using (var content = new MultipartFormDataContent())
        {
            var f = new ByteArrayContent(goodBytes);
            f.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            content.Add(f, "package", "Staging.Mix.NuGet.1.0.0.nupkg");
            var r1 = await client.PutAsync("/nuget/publish", content);
            Assert.Equal(HttpStatusCode.Created, r1.StatusCode);
        }

        Assert.Equal(0, StagingFileCount());

        // Call 2 — oversized: 1-byte limit fires after staging.
        await _factory.SetOrgLimit("default", "nuget", 1L);
        try
        {
            var (bigBytes, _) = NuGetFixtures.BuildNupkg("Staging.Mix.Big.NuGet", "1.0.0");
            using var content = new MultipartFormDataContent();
            var f = new ByteArrayContent(bigBytes);
            f.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            content.Add(f, "package", "Staging.Mix.Big.NuGet.1.0.0.nupkg");
            var r2 = await client.PutAsync("/nuget/publish", content);
            Assert.Equal(HttpStatusCode.RequestEntityTooLarge, r2.StatusCode);
        }
        finally
        {
            await _factory.SetOrgLimit("default", "nuget", null);
        }

        Assert.Equal(0, StagingFileCount());

        // Call 3 — not a valid nupkg (corrupt ZIP): rejected after staging.
        byte[] corruptBytes = "this is not a zip file"u8.ToArray();
        using (var content = new MultipartFormDataContent())
        {
            var f = new ByteArrayContent(corruptBytes);
            f.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            content.Add(f, "package", "Staging.Mix.Corrupt.NuGet.1.0.0.nupkg");
            var r3 = await client.PutAsync("/nuget/publish", content);
            Assert.True(
                r3.StatusCode is HttpStatusCode.UnprocessableEntity or HttpStatusCode.BadRequest,
                $"Expected 422 or 400 for corrupt nupkg, got {(int)r3.StatusCode}");
        }

        Assert.Equal(0, StagingFileCount());
    }

    // ── npm ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Npm_SuccessfulPublish_LeavesNoStagingFiles()
    {
        string token = await PushToken();
        string body = NpmFixtures.BuildPublishBody("staging-happy-npm", "1.0.0");

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/npm/staging-happy-npm", content);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(0, StagingFileCount());
    }

    /// <summary>
    /// Mixed partial-failure: valid publish, then oversized declared attachment (413),
    /// then invalid base64 (422). The 413 case pins that after decoding, writing to the
    /// staging file, and checking the org size limit, the finally block deletes the file.
    /// The invalid-base64 case never creates a file (failure is pre-write), but the
    /// staging count must remain 0.
    /// </summary>
    [Fact]
    public async Task Npm_MixedPartialFailure_AllCallsCleanUpStagingFiles()
    {
        string token = await PushToken();

        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // Call 1 — valid publish.
        string body1 = NpmFixtures.BuildPublishBody("staging-mix-npm", "1.0.0");
        using (var content = new StringContent(body1, Encoding.UTF8, "application/json"))
        {
            var r1 = await client.PutAsync("/npm/staging-mix-npm", content);
            Assert.Equal(HttpStatusCode.OK, r1.StatusCode);
        }

        Assert.Equal(0, StagingFileCount());

        // Call 2 — oversized declared attachment length so CheckUploadSizeFromFileAsync fires.
        await _factory.SetOrgLimit("default", "npm", 1L);
        try
        {
            var (tarball, _, integrity) = NpmFixtures.BuildTarball("staging-mix-big-npm", "1.0.0");
            string filename = "staging-mix-big-npm-1.0.0.tgz";
            string bigBody = System.Text.Json.JsonSerializer.Serialize(new
            {
                name = "staging-mix-big-npm",
                versions = new Dictionary<string, object>
                {
                    ["1.0.0"] = new
                    {
                        name = "staging-mix-big-npm",
                        version = "1.0.0",
                        description = "test",
                        dist = new { tarball = $"https://x/{filename}", integrity }
                    }
                },
                _attachments = new Dictionary<string, object>
                {
                    [filename] = new
                    {
                        content_type = "application/octet-stream",
                        data = Convert.ToBase64String(tarball),
                        length = tarball.Length
                    }
                }
            });
            using var content = new StringContent(bigBody, Encoding.UTF8, "application/json");
            var r2 = await client.PutAsync("/npm/staging-mix-big-npm", content);
            Assert.Equal(HttpStatusCode.RequestEntityTooLarge, r2.StatusCode);
        }
        finally
        {
            await _factory.SetOrgLimit("default", "npm", null);
        }

        Assert.Equal(0, StagingFileCount());

        // Call 3 — invalid base64 in _attachments.data: ExtractAttachmentToStagingAsync
        // must reject before the write step, so no staging file is created and the count stays 0.
        string body3 = System.Text.Json.JsonSerializer.Serialize(new
        {
            name = "staging-mix-corrupt-npm",
            versions = new Dictionary<string, object>
            {
                ["1.0.0"] = new
                {
                    name = "staging-mix-corrupt-npm",
                    version = "1.0.0",
                    description = "test",
                    dist = new { tarball = "https://x/f.tgz", integrity = "sha512-x" }
                }
            },
            _attachments = new Dictionary<string, object>
            {
                ["staging-mix-corrupt-npm-1.0.0.tgz"] = new
                {
                    content_type = "application/octet-stream",
                    data = "!!!not-valid-base64!!!",
                    length = 10
                }
            }
        });
        using (var content = new StringContent(body3, Encoding.UTF8, "application/json"))
        {
            var r3 = await client.PutAsync("/npm/staging-mix-corrupt-npm", content);
            Assert.Equal(HttpStatusCode.UnprocessableEntity, r3.StatusCode);
        }

        Assert.Equal(0, StagingFileCount());
    }
}
