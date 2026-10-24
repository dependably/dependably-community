using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Tenant banner management and the member-facing read/dismiss endpoints, end to end: request
/// validation, capability denials, per-scope active cap, role targeting, and org isolation.
/// Banner windows are fixed instants decades either side of any run date so activity never
/// depends on the host clock.
/// </summary>
[Trait("Category", "Integration")]
public sealed class BannersApiTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string Starts = "2020-01-01T00:00:00Z";
    private const string Ends = "2099-01-01T00:00:00Z";

    private readonly DependablyFactory _factory;
    public BannersApiTests(DependablyFactory factory) => _factory = factory;
    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> AdminClient() =>
        _factory.CreateClientWithBearer(await _factory.CreateAdminJwt());

    private async Task<HttpClient> MemberClient()
    {
        string id = await _factory.CreateUser($"banner-member-{Guid.NewGuid():N}@example.com", "Password12345");
        return _factory.CreateClientWithBearer(await _factory.CreateUserJwt(id, "member"));
    }

    private async Task<HttpClient> ClientWithCaps(params string[] caps)
    {
        string id = await _factory.CreateUser($"banner-caps-{Guid.NewGuid():N}@example.com", "Password12345");
        return _factory.CreateClientWithBearer(await _factory.CreateUserJwtWithCaps(id, caps));
    }

    private static object Body(
        string body = "Scheduled maintenance on Saturday",
        string severity = "info",
        string targetRole = "all",
        string? linkUrl = null,
        string? linkLabel = null,
        string startsAt = Starts,
        string endsAt = Ends,
        bool enabled = true) =>
        new { severity, body, linkUrl, linkLabel, targetRole, startsAt, endsAt, enabled };

    private static async Task<string> CreateAsync(HttpClient c, object body)
    {
        var resp = await c.PostAsJsonAsync("/api/v1/banners", body);
        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        return (await ProblemBody.ReadAsync(resp)).GetProperty("id").GetString()!;
    }

    private static async Task<List<string>> ActiveIdsAsync(HttpClient c)
    {
        var resp = await c.GetAsync("/api/v1/banners/active");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        return (await ProblemBody.ReadAsync(resp)).EnumerateArray().Select(e => e.GetProperty("id").GetString()!).ToList();
    }

    [Fact]
    public async Task CreateUpdateDelete_RoundTrip_PersistsAndNormalizesTheWindow()
    {
        using var admin = await AdminClient();

        var create = await admin.PostAsJsonAsync("/api/v1/banners", Body(
            severity: "warn", linkUrl: "https://status.example.com/incident", linkLabel: "Status page",
            startsAt: "2020-01-01T02:00:00+02:00", endsAt: "2099-01-01T02:00:00+02:00"));
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        var created = await ProblemBody.ReadAsync(create);
        string id = created.GetProperty("id").GetString()!;
        Assert.Equal("warn", created.GetProperty("severity").GetString());
        Assert.Equal("Status page", created.GetProperty("linkLabel").GetString());
        // The +02:00 offsets are persisted as the UTC instants they denote.
        Assert.Equal("2020-01-01T00:00:00Z", created.GetProperty("startsAt").GetString());
        Assert.Equal("2099-01-01T00:00:00Z", created.GetProperty("endsAt").GetString());

        var update = await admin.PutAsJsonAsync($"/api/v1/banners/{id}", Body(
            body: "Maintenance moved to Sunday", severity: "alert", targetRole: "member", enabled: false));
        Assert.Equal(HttpStatusCode.NoContent, update.StatusCode);

        var list = await admin.GetFromJsonAsync<JsonElement>("/api/v1/banners");
        var row = Assert.Single(list.EnumerateArray(), e => e.GetProperty("id").GetString() == id);
        Assert.Equal("Maintenance moved to Sunday", row.GetProperty("body").GetString());
        Assert.Equal("alert", row.GetProperty("severity").GetString());
        Assert.Equal("member", row.GetProperty("targetRole").GetString());
        Assert.False(row.GetProperty("enabled").GetBoolean());

        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/api/v1/banners/{id}")).StatusCode);
        list = await admin.GetFromJsonAsync<JsonElement>("/api/v1/banners");
        Assert.DoesNotContain(list.EnumerateArray(), e => e.GetProperty("id").GetString() == id);
    }

    [Fact]
    public async Task Writes_WithoutTenantConfigure_AreForbiddenAndChangeNothing()
    {
        using var admin = await AdminClient();
        string id = await CreateAsync(admin, Body(body: "original text"));
        using var reader = await ClientWithCaps("read:tenant");
        using var member = await MemberClient();

        foreach (var c in new[] { reader, member })
        {
            await ProblemBody.AssertForbiddenAsync(await c.PostAsJsonAsync("/api/v1/banners", Body(body: "denied")));
            await ProblemBody.AssertForbiddenAsync(await c.PutAsJsonAsync($"/api/v1/banners/{id}", Body(body: "denied")));
            await ProblemBody.AssertForbiddenAsync(await c.DeleteAsync($"/api/v1/banners/{id}"));
        }

        // The management list needs read:tenant; the tenant reader sees it, the plain member does not.
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync("/api/v1/banners")).StatusCode);
        await ProblemBody.AssertForbiddenAsync(await member.GetAsync("/api/v1/banners"));

        var list = await admin.GetFromJsonAsync<JsonElement>("/api/v1/banners");
        var row = Assert.Single(list.EnumerateArray(), e => e.GetProperty("id").GetString() == id);
        Assert.Equal("original text", row.GetProperty("body").GetString());
        Assert.DoesNotContain(list.EnumerateArray(), e => e.GetProperty("body").GetString() == "denied");
        await admin.DeleteAsync($"/api/v1/banners/{id}");
    }

    [Theory]
    [InlineData("body", "", "body")]
    [InlineData("body", "   ", "body")]
    [InlineData("body", "TOO_LONG_BODY", "body")]
    [InlineData("linkUrl", "TOO_LONG_URL", "linkUrl")]
    [InlineData("linkUrl", "ftp://files.example.com/x", "linkUrl")]
    [InlineData("linkUrl", "not a url", "linkUrl")]
    [InlineData("linkLabel", "TOO_LONG_LABEL", "linkLabel")]
    [InlineData("startsAt", "yesterday", "startsAt")]
    [InlineData("endsAt", "tomorrow", "endsAt")]
    [InlineData("severity", "critical", "severity")]
    [InlineData("targetRole", "everyone", "targetRole")]
    public async Task CreateAndUpdate_InvalidField_ReturnsValidationProblemNamingTheField(
        string property, string value, string field)
    {
        using var admin = await AdminClient();
        string id = await CreateAsync(admin, Body(body: "valid original"));
        string sent = value switch
        {
            "TOO_LONG_BODY" => new string('b', 2001),
            "TOO_LONG_URL" => "https://example.com/" + new string('p', 2040),
            "TOO_LONG_LABEL" => new string('l', 201),
            _ => value,
        };
        var fields = new Dictionary<string, object?>
        {
            ["severity"] = "info",
            ["body"] = "Scheduled maintenance",
            ["linkUrl"] = null,
            ["linkLabel"] = null,
            ["targetRole"] = "all",
            ["startsAt"] = Starts,
            ["endsAt"] = Ends,
        };
        fields[property] = sent;

        await ProblemBody.AssertValidationAsync(await admin.PostAsJsonAsync("/api/v1/banners", fields), field);
        await ProblemBody.AssertValidationAsync(await admin.PutAsJsonAsync($"/api/v1/banners/{id}", fields), field);

        var list = await admin.GetFromJsonAsync<JsonElement>("/api/v1/banners");
        var row = Assert.Single(list.EnumerateArray(), e => e.GetProperty("id").GetString() == id);
        Assert.Equal("valid original", row.GetProperty("body").GetString());
        await admin.DeleteAsync($"/api/v1/banners/{id}");
    }

    [Fact]
    public async Task EndsAtNotAfterStartsAt_IsRejectedEvenAcrossDifferentOffsets()
    {
        using var admin = await AdminClient();

        // 03:00+02:00 is 01:00Z, which is before the 02:00Z start despite the larger wall-clock text.
        await ProblemBody.AssertValidationAsync(
            await admin.PostAsJsonAsync("/api/v1/banners",
                Body(startsAt: "2030-01-01T02:00:00Z", endsAt: "2030-01-01T03:00:00+02:00")),
            "endsAt");
        await ProblemBody.AssertValidationAsync(
            await admin.PostAsJsonAsync("/api/v1/banners", Body(startsAt: Starts, endsAt: Starts)),
            "endsAt");
    }

    [Fact]
    public async Task Create_PastTheActiveCap_ReturnsValidationProblem()
    {
        await using var factory = new DependablyFactory();
        await factory.InitializeAsync();
        using var admin = factory.CreateClientWithBearer(await factory.CreateAdminJwt());
        for (int i = 0; i < BannerRepository.MaxActiveBannersPerScope; i++)
        {
            await CreateAsync(admin, Body(body: $"banner {i}"));
        }

        await ProblemBody.AssertValidationAsync(
            await admin.PostAsJsonAsync("/api/v1/banners", Body(body: "one too many")), "banners");

        var list = await admin.GetFromJsonAsync<JsonElement>("/api/v1/banners");
        Assert.Equal(BannerRepository.MaxActiveBannersPerScope, list.GetArrayLength());
        Assert.DoesNotContain(list.EnumerateArray(), e => e.GetProperty("body").GetString() == "one too many");
    }

    [Fact]
    public async Task UnknownBanner_Returns404OnUpdateDeleteAndDismiss()
    {
        using var admin = await AdminClient();
        string missing = Guid.NewGuid().ToString("N");

        Assert.Equal(HttpStatusCode.NotFound, (await admin.PutAsJsonAsync($"/api/v1/banners/{missing}", Body())).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.DeleteAsync($"/api/v1/banners/{missing}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.PostAsync($"/api/v1/banners/{missing}/dismiss", null)).StatusCode);
    }

    [Fact]
    public async Task ActiveAndDismiss_HonourRoleTargetingAndPerUserDismissal()
    {
        using var admin = await AdminClient();
        using var member = await MemberClient();
        using var otherMember = await MemberClient();
        string everyone = await CreateAsync(admin, Body(body: "for everyone"));
        string ownersOnly = await CreateAsync(admin, Body(body: "owners only", targetRole: "owner"));
        string disabled = await CreateAsync(admin, Body(body: "switched off", enabled: false));

        var memberSees = await ActiveIdsAsync(member);
        Assert.Contains(everyone, memberSees);
        Assert.DoesNotContain(ownersOnly, memberSees);
        Assert.DoesNotContain(disabled, memberSees);
        var adminSees = await ActiveIdsAsync(admin);
        Assert.Contains(ownersOnly, adminSees);

        Assert.Equal(HttpStatusCode.NoContent, (await member.PostAsync($"/api/v1/banners/{everyone}/dismiss", null)).StatusCode);
        // Dismissal is idempotent.
        Assert.Equal(HttpStatusCode.NoContent, (await member.PostAsync($"/api/v1/banners/{everyone}/dismiss", null)).StatusCode);

        Assert.DoesNotContain(everyone, await ActiveIdsAsync(member));
        Assert.Contains(everyone, await ActiveIdsAsync(otherMember));

        foreach (string id in new[] { everyone, ownersOnly, disabled })
        {
            await admin.DeleteAsync($"/api/v1/banners/{id}");
        }
    }

    [Fact]
    public async Task ServiceTokenWithoutAUser_CannotReadOrDismissBanners()
    {
        using var admin = await AdminClient();
        string id = await CreateAsync(admin, Body(body: "user scoped"));
        using var service = _factory.CreateClientWithBearer(await _factory.CreateToken("push"));

        Assert.NotEqual(HttpStatusCode.OK, (await service.GetAsync("/api/v1/banners/active")).StatusCode);
        Assert.NotEqual(HttpStatusCode.NoContent, (await service.PostAsync($"/api/v1/banners/{id}/dismiss", null)).StatusCode);
        await admin.DeleteAsync($"/api/v1/banners/{id}");
    }

    [Fact]
    public async Task ForeignOrgBanner_IsNotListedNotChangeableAndNotDismissable()
    {
        var orgs = _factory.Services.GetRequiredService<OrgRepository>();
        var other = await orgs.CreateOrgAsync($"bn-{Guid.NewGuid():N}"[..14]);
        var repo = _factory.Services.GetRequiredService<BannerRepository>();
        var foreign = await repo.CreateTenantAsync(other.Id, "",
            new BannerCreateRequest("info", "foreign org notice", null, null, "all", Starts, Ends));
        using var admin = await AdminClient();

        var list = await admin.GetFromJsonAsync<JsonElement>("/api/v1/banners");
        Assert.DoesNotContain(list.EnumerateArray(), e => e.GetProperty("id").GetString() == foreign.Id);
        Assert.DoesNotContain(foreign.Id, await ActiveIdsAsync(admin));

        Assert.Equal(HttpStatusCode.NotFound,
            (await admin.PutAsJsonAsync($"/api/v1/banners/{foreign.Id}", Body(body: "hijacked"))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.DeleteAsync($"/api/v1/banners/{foreign.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.PostAsync($"/api/v1/banners/{foreign.Id}/dismiss", null)).StatusCode);

        var intact = Assert.Single(await repo.ListTenantAsync(other.Id));
        Assert.Equal("foreign org notice", intact.Body);
    }
}
