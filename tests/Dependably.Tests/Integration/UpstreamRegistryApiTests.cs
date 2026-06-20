using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Management-API surface for per-org upstream proxy registries: CRUD + reorder, the
/// tenant:configure gate, SSRF rejection (reusing UpstreamUrlValidator), and ecosystem
/// validation. The fetch-side "empty list = disabled" contract is covered separately in the
/// per-ecosystem proxy tests.
/// </summary>
[Trait("Category", "Integration")]
public sealed class UpstreamRegistryApiTests : IClassFixture<DependablyFactory>
{
    private readonly DependablyFactory _factory;
    public UpstreamRegistryApiTests(DependablyFactory factory) => _factory = factory;

    private async Task<HttpClient> AdminClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    private async Task<HttpClient> MemberClient()
    {
        string id = await _factory.CreateUser($"ur-{Guid.NewGuid():N}@example.com", "Password12345");
        string jwt = await _factory.CreateUserJwt(id, "member");
        return _factory.CreateClientWithBearer(jwt);
    }

    [Fact]
    public async Task AddListReorderDelete_RoundTrip()
    {
        using var c = await AdminClient();
        string urlA = $"https://mirror-a-{Guid.NewGuid():N}.example.com";
        string urlB = $"https://mirror-b-{Guid.NewGuid():N}.example.com";

        var addA = await c.PostAsJsonAsync("/api/v1/upstream-registries",
            new { ecosystem = "pypi", url = urlA, name = "A" });
        Assert.Equal(HttpStatusCode.Created, addA.StatusCode);
        string? idA = (await JsonDocument.ParseAsync(await addA.Content.ReadAsStreamAsync()))
            .RootElement.GetProperty("id").GetString();

        var addB = await c.PostAsJsonAsync("/api/v1/upstream-registries",
            new { ecosystem = "pypi", url = urlB });
        Assert.Equal(HttpStatusCode.Created, addB.StatusCode);
        string? idB = (await JsonDocument.ParseAsync(await addB.Content.ReadAsStreamAsync()))
            .RootElement.GetProperty("id").GetString();

        // Reorder so B precedes A.
        var reorder = await c.PutAsJsonAsync("/api/v1/upstream-registries/pypi/order",
            new { ids = new[] { idB, idA } });
        Assert.Equal(HttpStatusCode.NoContent, reorder.StatusCode);

        var list = await c.GetAsync("/api/v1/upstream-registries");
        list.EnsureSuccessStatusCode();
        var items = (await JsonDocument.ParseAsync(await list.Content.ReadAsStreamAsync())).RootElement;
        var pypi = items.EnumerateArray()
            .Where(e => e.GetProperty("ecosystem").GetString() == "pypi")
            .OrderBy(e => e.GetProperty("position").GetInt32())
            .Select(e => e.GetProperty("url").GetString())
            .ToList();
        Assert.Equal(urlB, pypi[0]);
        Assert.Equal(urlA, pypi[1]);

        Assert.Equal(HttpStatusCode.NoContent,
            (await c.DeleteAsync($"/api/v1/upstream-registries/{idA}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent,
            (await c.DeleteAsync($"/api/v1/upstream-registries/{idB}")).StatusCode);
    }

    [Fact]
    public async Task Add_PrivateRangeUrl_RejectedAsSsrf()
    {
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/upstream-registries",
            new { ecosystem = "npm", url = "http://169.254.169.254/latest/meta-data" });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Add_UnknownEcosystem_Rejected()
    {
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/upstream-registries",
            new { ecosystem = "conan", url = "https://conan.io/center" });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task Add_ByMember_Forbidden()
    {
        using var c = await MemberClient();
        var resp = await c.PostAsJsonAsync("/api/v1/upstream-registries",
            new { ecosystem = "pypi", url = "https://pypi.org" });
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    // ── OCI-specific tests ────────────────────────────────────────────────────

    [Fact]
    public async Task AddOci_Anonymous_ReturnsCreatedWithPrefixesAndAuthType()
    {
        using var c = await AdminClient();
        string host = $"ghcr-{Guid.NewGuid():N}.io";

        var resp = await c.PostAsJsonAsync("/api/v1/upstream-registries", new
        {
            ecosystem = "oci",
            url = host,
            authType = "anonymous",
            prefixes = new[] { "myorg/", "" },
            name = "GHCR Test",
        });

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        var root = doc.RootElement;

        Assert.Equal("oci", root.GetProperty("ecosystem").GetString());
        Assert.Equal(host, root.GetProperty("url").GetString());
        Assert.Equal("anonymous", root.GetProperty("authType").GetString());
        Assert.False(root.GetProperty("hasSecret").GetBoolean());
        var prefixes = root.GetProperty("prefixes").EnumerateArray()
            .Select(e => e.GetString()).ToList();
        Assert.Contains("myorg/", prefixes);
        Assert.Contains("", prefixes);
    }

    [Fact]
    public async Task AddOci_Basic_SecretIsWriteOnly_HasSecretTrue()
    {
        using var c = await AdminClient();
        string host = $"registry-{Guid.NewGuid():N}.example.com";

        var addResp = await c.PostAsJsonAsync("/api/v1/upstream-registries", new
        {
            ecosystem = "oci",
            url = host,
            authType = "basic",
            username = "robot",
            secret = "my-super-secret-password",
            prefixes = new[] { "myrepo/" },
        });
        Assert.Equal(HttpStatusCode.Created, addResp.StatusCode);

        string id = (await JsonDocument.ParseAsync(await addResp.Content.ReadAsStreamAsync()))
            .RootElement.GetProperty("id").GetString()!;

        // GET /api/v1/upstream-registries must return hasSecret=true but no secret field.
        var listResp = await c.GetAsync("/api/v1/upstream-registries");
        listResp.EnsureSuccessStatusCode();
        var items = (await JsonDocument.ParseAsync(await listResp.Content.ReadAsStreamAsync())).RootElement;
        var entry = items.EnumerateArray().FirstOrDefault(e => e.GetProperty("id").GetString() == id);
        Assert.NotEqual(default, entry);
        Assert.True(entry.GetProperty("hasSecret").GetBoolean());
        Assert.False(entry.TryGetProperty("secret", out _), "Secret field must not appear in GET response.");

        // Cleanup
        await c.DeleteAsync($"/api/v1/upstream-registries/{id}");
    }

    [Fact]
    public async Task AddOci_AwsEcr_Rejected()
    {
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/upstream-registries", new
        {
            ecosystem = "oci",
            url = "123456789.dkr.ecr.us-east-1.amazonaws.com",
            authType = "aws_ecr",
            prefixes = new[] { "" },
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task AddOci_BasicWithoutCredentials_Rejected()
    {
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/upstream-registries", new
        {
            ecosystem = "oci",
            url = "registry.example.com",
            authType = "basic",
            prefixes = new[] { "" },
            // username and secret deliberately omitted
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task AddOci_WithoutPrefixes_Rejected()
    {
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/upstream-registries", new
        {
            ecosystem = "oci",
            url = "registry.example.com",
            authType = "anonymous",
            // prefixes deliberately omitted
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task AddOci_SsrfHost_Rejected()
    {
        using var c = await AdminClient();
        var resp = await c.PostAsJsonAsync("/api/v1/upstream-registries", new
        {
            ecosystem = "oci",
            url = "169.254.169.254",
            authType = "anonymous",
            prefixes = new[] { "" },
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task AddOci_NonOciFieldsOnNonOciEcosystem_Rejected()
    {
        using var c = await AdminClient();
        // authType is an OCI-only field — should be rejected on pypi.
        var resp = await c.PostAsJsonAsync("/api/v1/upstream-registries", new
        {
            ecosystem = "pypi",
            url = "https://pypi.org",
            authType = "basic",
        });
        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
    }

    [Fact]
    public async Task ReorderOci_ReordersEntries()
    {
        using var c = await AdminClient();
        string hostA = $"oci-a-{Guid.NewGuid():N}.example.com";
        string hostB = $"oci-b-{Guid.NewGuid():N}.example.com";

        var addA = await c.PostAsJsonAsync("/api/v1/upstream-registries",
            new { ecosystem = "oci", url = hostA, authType = "anonymous", prefixes = new[] { "a/" } });
        var addB = await c.PostAsJsonAsync("/api/v1/upstream-registries",
            new { ecosystem = "oci", url = hostB, authType = "anonymous", prefixes = new[] { "b/" } });

        string idA = (await JsonDocument.ParseAsync(await addA.Content.ReadAsStreamAsync()))
            .RootElement.GetProperty("id").GetString()!;
        string idB = (await JsonDocument.ParseAsync(await addB.Content.ReadAsStreamAsync()))
            .RootElement.GetProperty("id").GetString()!;

        // Reorder: B before A.
        var reorderResp = await c.PutAsJsonAsync("/api/v1/upstream-registries/oci/order",
            new { ids = new[] { idB, idA } });
        Assert.Equal(HttpStatusCode.NoContent, reorderResp.StatusCode);

        var list = await c.GetAsync("/api/v1/upstream-registries");
        list.EnsureSuccessStatusCode();
        var items = (await JsonDocument.ParseAsync(await list.Content.ReadAsStreamAsync())).RootElement;
        var ociEntries = items.EnumerateArray()
            .Where(e => e.GetProperty("ecosystem").GetString() == "oci"
                     && (e.GetProperty("url").GetString() == hostA
                      || e.GetProperty("url").GetString() == hostB))
            .OrderBy(e => e.GetProperty("position").GetInt32())
            .Select(e => e.GetProperty("url").GetString())
            .ToList();

        Assert.Equal(hostB, ociEntries[0]);
        Assert.Equal(hostA, ociEntries[1]);

        // Cleanup
        await c.DeleteAsync($"/api/v1/upstream-registries/{idA}");
        await c.DeleteAsync($"/api/v1/upstream-registries/{idB}");
    }

    /// <summary>
    /// Mixed partial-failure: POST anonymous OCI succeeds; POST basic OCI without credentials
    /// fails. Both in the same test to confirm per-request validation is independent.
    /// </summary>
    [Fact]
    public async Task AddOci_MixedOutcome_AnonymousSucceedsBasicWithoutCredsFails()
    {
        using var c = await AdminClient();
        string hostGood = $"good-{Guid.NewGuid():N}.example.com";

        // Good: anonymous OCI — should succeed.
        var goodResp = await c.PostAsJsonAsync("/api/v1/upstream-registries", new
        {
            ecosystem = "oci",
            url = hostGood,
            authType = "anonymous",
            prefixes = new[] { "ok/" },
        });

        // Bad: basic OCI without credentials — should fail.
        var badResp = await c.PostAsJsonAsync("/api/v1/upstream-registries", new
        {
            ecosystem = "oci",
            url = $"bad-{Guid.NewGuid():N}.example.com",
            authType = "basic",
            prefixes = new[] { "bad/" },
            // username and secret missing
        });

        Assert.Equal(HttpStatusCode.Created, goodResp.StatusCode);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, badResp.StatusCode);

        // Cleanup the successful entry.
        string id = (await JsonDocument.ParseAsync(await goodResp.Content.ReadAsStreamAsync()))
            .RootElement.GetProperty("id").GetString()!;
        await c.DeleteAsync($"/api/v1/upstream-registries/{id}");
    }
}
