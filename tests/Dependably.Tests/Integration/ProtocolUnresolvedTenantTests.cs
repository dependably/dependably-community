using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// A protocol request that resolves no tenant — the multi-mode apex host, an unknown subdomain
/// slug, or a sub-subdomain of the apex — is refused with 404 (RFC 9457
/// problem+json, or the OCI error envelope on <c>/v2/</c>) at <c>TenantStatusEnforcementMiddleware</c>,
/// before any protocol controller runs with a null org id. Every refusal is paired with the same
/// request on a real tenant subdomain so a gate that refuses everything fails too, and the apex
/// system-admin plane is probed to show it is untouched.
///
/// <para>
/// Authenticated probes present a genuine service token of a real tenant on the unresolved host:
/// the request must still be refused, never served from the token's own org, because the host —
/// not the credential — names the tenant a request runs under.
/// </para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class ProtocolUnresolvedTenantTests : IClassFixture<DependablyMultiFactory>, IAsyncLifetime
{
    // A metadata route per ecosystem. Maven metadata is the reported 500; npm's packument and
    // PyPI's simple page share the same epoch-bound metadata cache; the NuGet service index and
    // the Cargo config need no package at all, so they prove the refusal is not metadata-specific.
    public static TheoryData<string> ProtocolPaths => new()
    {
        "/maven/org/apache/maven/plugins/maven-metadata.xml",
        "/npm/left-pad",
        "/simple/requests/",
        "/nuget/v3/index.json",
        "/cargo/config.json",
    };

    private readonly DependablyMultiFactory _factory;

    public ProtocolUnresolvedTenantTests(DependablyMultiFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private static string UnknownSlugHost() =>
        $"nosuch-{Guid.NewGuid().ToString("N")[..8]}.{DependablyMultiFactory.ApexHost}";

    [Theory]
    [MemberData(nameof(ProtocolPaths))]
    public async Task Anonymous_request_on_the_apex_host_is_a_404_problem(string path)
    {
        using var client = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        using var resp = await client.GetAsync(path);

        await AssertTenantNotFoundProblemAsync(resp);
    }

    [Theory]
    [MemberData(nameof(ProtocolPaths))]
    public async Task Anonymous_request_on_an_unknown_slug_is_a_404_problem(string path)
    {
        using var client = _factory.CreateClientForHost(UnknownSlugHost());
        using var resp = await client.GetAsync(path);

        await AssertTenantNotFoundProblemAsync(resp);
    }

    [Theory]
    [MemberData(nameof(ProtocolPaths))]
    public async Task Anonymous_request_on_a_sub_subdomain_is_a_404_problem(string path)
    {
        // Only single-label slugs name a tenant; a deeper host resolves to no tenant at all. (A
        // Host outside the apex domain never reaches the resolver: host filtering answers 400.)
        using var client = _factory.CreateClientForHost($"deep.{UnknownSlugHost()}");
        using var resp = await client.GetAsync(path);

        await AssertTenantNotFoundProblemAsync(resp);
    }

    [Theory]
    [MemberData(nameof(ProtocolPaths))]
    public async Task Tenant_token_on_the_apex_or_an_unknown_slug_is_refused_not_served_from_its_org(string path)
    {
        string slug = await CreateTenantAsync("unres");
        string token = await CreateServiceTokenAsync(slug);

        foreach (string host in new[] { DependablyMultiFactory.ApexHost, UnknownSlugHost() })
        {
            using var client = _factory.CreateClientForHost(host);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var resp = await client.GetAsync(path);

            await AssertTenantNotFoundProblemAsync(resp);
        }
    }

    [Theory]
    [MemberData(nameof(ProtocolPaths))]
    public async Task System_admin_session_on_the_apex_is_refused_on_the_protocol_plane(string path)
    {
        using var sys = await _factory.CreateSystemAdminClient();
        using var resp = await sys.GetAsync(path);

        await AssertTenantNotFoundProblemAsync(resp);
    }

    [Fact]
    public async Task Same_request_on_a_real_tenant_host_reaches_the_controller()
    {
        string slug = await CreateTenantAsync("res");
        using var client = _factory.CreateClientForHost($"{slug}.{DependablyMultiFactory.ApexHost}");

        // Anonymous pull is off for a new tenant, so the controller's own credential challenge
        // answers — the request got past the tenant gate and was not a 500.
        using var resp = await client.GetAsync("/maven/org/apache/maven/plugins/maven-metadata.xml");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);

        // The NuGet service index is anonymous-readable and needs no upstream, so the tenant
        // twin of the refused apex request is an outright 200.
        using var index = await client.GetAsync("/nuget/v3/index.json");
        Assert.Equal(HttpStatusCode.OK, index.StatusCode);
    }

    [Fact]
    public async Task Oci_on_an_unresolved_host_answers_with_the_oci_error_envelope()
    {
        string slug = await CreateTenantAsync("oci");
        string token = await CreateServiceTokenAsync(slug);

        foreach (string host in new[] { DependablyMultiFactory.ApexHost, UnknownSlugHost() })
        {
            foreach (string path in new[] { "/v2/", "/v2/team/app/manifests/latest" })
            {
                foreach (bool authenticated in new[] { false, true })
                {
                    using var client = _factory.CreateClientForHost(host);
                    if (authenticated)
                    {
                        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                    }

                    using var resp = await client.GetAsync(path);
                    string body = await resp.Content.ReadAsStringAsync();
                    Assert.True(resp.StatusCode == HttpStatusCode.NotFound,
                        $"{host}{path} (auth={authenticated}): expected 404, got {(int)resp.StatusCode}. Body: {body}");
                    Assert.Equal("application/json", resp.Content.Headers.ContentType?.MediaType);
                    using var doc = JsonDocument.Parse(body);
                    Assert.Equal("NAME_UNKNOWN", doc.RootElement.GetProperty("errors")[0].GetProperty("code").GetString());
                }
            }
        }

        // The tenant twin: the same token on its own subdomain passes the Distribution Spec ping.
        using var tenant = _factory.CreateClientForHost($"{slug}.{DependablyMultiFactory.ApexHost}");
        tenant.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var ping = await tenant.GetAsync("/v2/");
        Assert.Equal(HttpStatusCode.OK, ping.StatusCode);
    }

    [Fact]
    public async Task Apex_management_and_operator_routes_are_unaffected()
    {
        using var sys = await _factory.CreateSystemAdminClient();

        using var tenants = await sys.GetAsync("/api/v1/system/tenants?limit=200");
        Assert.Equal(HttpStatusCode.OK, tenants.StatusCode);

        using var anon = _factory.CreateClientForHost(DependablyMultiFactory.ApexHost);
        using var bootstrap = await anon.GetAsync("/api/v1/bootstrap");
        Assert.Equal(HttpStatusCode.OK, bootstrap.StatusCode);
        using (var doc = JsonDocument.Parse(await bootstrap.Content.ReadAsStringAsync()))
        {
            Assert.True(doc.RootElement.GetProperty("isApex").GetBoolean());
        }

        using var methods = await anon.GetAsync("/api/v1/auth/methods");
        Assert.Equal(HttpStatusCode.OK, methods.StatusCode);

        using var health = await anon.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
    }

    private static async Task AssertTenantNotFoundProblemAsync(HttpResponseMessage resp)
    {
        string body = await resp.Content.ReadAsStringAsync();
        string where = $"{resp.RequestMessage?.Headers.Host}{resp.RequestMessage?.RequestUri?.PathAndQuery}";
        Assert.True(resp.StatusCode == HttpStatusCode.NotFound,
            $"{where}: expected 404, got {(int)resp.StatusCode}. Body: {body}");
        Assert.Equal("application/problem+json", resp.Content.Headers.ContentType?.MediaType);

        using var doc = JsonDocument.Parse(body);
        Assert.Equal(404, doc.RootElement.GetProperty("status").GetInt32());
        Assert.Equal(nameof(TenantNotReadyReason.NotFound), doc.RootElement.GetProperty("reason").GetString());
    }

    private async Task<string> CreateTenantAsync(string prefix)
    {
        string slug = prefix + "-" + Guid.NewGuid().ToString("N")[..8];
        using var sys = await _factory.CreateSystemAdminClient();
        using var resp = await sys.PostAsJsonAsync("/api/v1/system/tenants", new
        {
            slug,
            ownerEmail = $"{slug}@example.com",
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        return slug;
    }

    private async Task<string> CreateServiceTokenAsync(string slug)
    {
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        var tokens = _factory.Services.GetRequiredService<TokenRepository>();
        var org = await orgs.GetBySlugAsync(slug)
            ?? throw new InvalidOperationException($"Org '{slug}' not found.");
        var (raw, _) = await tokens.CreateServiceTokenAsync(
            org.Id,
            $"tok-{Guid.NewGuid():N}"[..16],
            """["read:artifact","read:metadata"]""",
            expiresAt: null);
        return raw;
    }
}
