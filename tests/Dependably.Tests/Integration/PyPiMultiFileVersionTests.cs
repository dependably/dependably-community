using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Multi-file-per-version PyPI storage: a release stores its wheel AND its sdist as distinct
/// blobs with their own filename/size/checksum records (the model pypi.org exposes), the
/// simple index lists every stored file, and /packages/{file} serves exactly the blob whose
/// filename was requested. Adding a new file to an existing release bypasses the same-version
/// overwrite policy (nothing is overwritten); re-uploading an existing filename stays
/// policy-gated. Version delete removes every file's blob.
/// </summary>
[Trait("Category", "Integration")]
public sealed class PyPiMultiFileVersionTests : IClassFixture<DependablyFactory>
{
    private readonly DependablyFactory _factory;
    public PyPiMultiFileVersionTests(DependablyFactory factory) => _factory = factory;

    private async Task<string> PushToken() => await _factory.CreateToken("push");
    private async Task<string> PullToken() => await _factory.CreateToken("pull");

    private static MultipartFormDataContent BuildUploadForm(
        string name, string version, byte[] bytes, string sha256, string filename, string filetype)
    {
        var content = new MultipartFormDataContent
        {
            { new StringContent("file_upload"), ":action" },
            { new StringContent("2.1"), "metadata_version" },
            { new StringContent(name), "name" },
            { new StringContent(version), "version" },
            { new StringContent(sha256), "sha256_digest" },
            { new StringContent(filetype), "filetype" },
        };
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "content", filename);
        return content;
    }

    private async Task<HttpResponseMessage> UploadAsync(
        string token, string name, string version, byte[] bytes, string sha256, string filename, string filetype)
    {
        using var client = _factory.CreateClientWithBasic(token);
        using var form = BuildUploadForm(name, version, bytes, sha256, filename, filetype);
        return await client.PostAsync("/pypi/legacy/", form);
    }

    private static string Sha256Hex(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    [Fact]
    public async Task WheelThenSdist_SameVersion_BothListedAndEachServesItsOwnBytes()
    {
        // The default org overwrite policy is 'block' — the sdist joining the wheel must
        // still be accepted, because it adds a file rather than overwriting one.
        string name = $"mfv-both-{Guid.NewGuid():N}"[..24];
        string underscored = name.Replace('-', '_');
        const string version = "1.2.3";
        string pushToken = await PushToken();

        var (wheel, wheelSha) = PyPiFixtures.BuildWheel(name, version);
        string wheelFile = $"{underscored}-{version}-py3-none-any.whl";
        var wheelResp = await UploadAsync(pushToken, name, version, wheel, wheelSha, wheelFile, "bdist_wheel");
        Assert.Equal(HttpStatusCode.OK, wheelResp.StatusCode);

        var (sdist, sdistSha) = PyPiFixtures.BuildSdist(name, version);
        string sdistFile = $"{underscored}-{version}.tar.gz";
        var sdistResp = await UploadAsync(pushToken, name, version, sdist, sdistSha, sdistFile, "sdist");
        Assert.Equal(HttpStatusCode.OK, sdistResp.StatusCode);

        string pullToken = await PullToken();
        using var client = _factory.CreateClientWithBasic(pullToken);

        // The simple index lists BOTH files of the release, each with its own sha256 fragment.
        var index = await client.GetAsync($"/simple/{name}/");
        Assert.Equal(HttpStatusCode.OK, index.StatusCode);
        string html = await index.Content.ReadAsStringAsync();
        Assert.Contains(wheelFile, html);
        Assert.Contains(sdistFile, html);
        Assert.Contains($"#sha256={wheelSha}", html);
        Assert.Contains($"#sha256={sdistSha}", html);

        // Each filename serves exactly its own bytes — the wheel URL must never stream the
        // sdist's gzip (the "Wheel is invalid" corruption this model replaces).
        byte[] servedWheel = await client.GetByteArrayAsync($"/packages/{wheelFile}");
        Assert.Equal(wheelSha, Sha256Hex(servedWheel));
        byte[] servedSdist = await client.GetByteArrayAsync($"/packages/{sdistFile}");
        Assert.Equal(sdistSha, Sha256Hex(servedSdist));

        // HEAD reports the per-file size and checksum, not the version row's primary.
        using var headReq = new HttpRequestMessage(HttpMethod.Head, $"/packages/{sdistFile}");
        var head = await client.SendAsync(headReq);
        Assert.Equal(HttpStatusCode.OK, head.StatusCode);
        Assert.Equal(sdist.LongLength.ToString(), head.Content.Headers.GetValues("Content-Length").Single());
        Assert.Equal($"\"sha256:{sdistSha}\"", head.Headers.ETag!.ToString());
    }

    [Fact]
    public async Task SameFilenameReupload_DefaultBlockPolicy_Rejected409_NewFileStillAccepted()
    {
        // Mixed outcome within one release: re-uploading the existing wheel filename is a
        // true overwrite (blocked by the default policy), while the sdist — a new file —
        // is accepted in the same state.
        string name = $"mfv-mixed-{Guid.NewGuid():N}"[..24];
        string underscored = name.Replace('-', '_');
        const string version = "2.0.0";
        string pushToken = await PushToken();

        var (wheel, wheelSha) = PyPiFixtures.BuildWheel(name, version);
        string wheelFile = $"{underscored}-{version}-py3-none-any.whl";
        var first = await UploadAsync(pushToken, name, version, wheel, wheelSha, wheelFile, "bdist_wheel");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        var again = await UploadAsync(pushToken, name, version, wheel, wheelSha, wheelFile, "bdist_wheel");
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
        Assert.Contains("already exists", await again.Content.ReadAsStringAsync());

        var (sdist, sdistSha) = PyPiFixtures.BuildSdist(name, version);
        string sdistFile = $"{underscored}-{version}.tar.gz";
        var sdistResp = await UploadAsync(pushToken, name, version, sdist, sdistSha, sdistFile, "sdist");
        Assert.Equal(HttpStatusCode.OK, sdistResp.StatusCode);
    }

    [Fact]
    public async Task DeleteVersion_RemovesEveryFileOfTheRelease()
    {
        string name = $"mfv-del-{Guid.NewGuid():N}"[..24];
        string underscored = name.Replace('-', '_');
        const string version = "3.0.0";
        string pushToken = await PushToken();

        var (wheel, wheelSha) = PyPiFixtures.BuildWheel(name, version);
        string wheelFile = $"{underscored}-{version}-py3-none-any.whl";
        (await UploadAsync(pushToken, name, version, wheel, wheelSha, wheelFile, "bdist_wheel")).EnsureSuccessStatusCode();
        var (sdist, sdistSha) = PyPiFixtures.BuildSdist(name, version);
        string sdistFile = $"{underscored}-{version}.tar.gz";
        (await UploadAsync(pushToken, name, version, sdist, sdistSha, sdistFile, "sdist")).EnsureSuccessStatusCode();

        string jwt = await _factory.CreateAdminJwt();
        using var admin = _factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        var del = await admin.DeleteAsync($"/api/v1/packages/pypi/{name}/{version}");
        Assert.Equal(HttpStatusCode.NoContent, del.StatusCode);

        // Both files are gone: not listed, not downloadable (no proxy upstream is configured
        // for these synthetic names, so the miss path cannot resurrect them).
        string pullToken = await PullToken();
        using var client = _factory.CreateClientWithBasic(pullToken);
        var wheelGet = await client.GetAsync($"/packages/{wheelFile}");
        Assert.Equal(HttpStatusCode.NotFound, wheelGet.StatusCode);
        var sdistGet = await client.GetAsync($"/packages/{sdistFile}");
        Assert.Equal(HttpStatusCode.NotFound, sdistGet.StatusCode);
    }

}
