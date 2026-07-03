using System.Net;
using System.Text;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Verifies the effective-language chain surfaced by GET /api/v1/auth/me:
/// user override → tenant default → negotiated request culture (Accept-Language) → en.
/// The SPA applies me.language after login, so a missing request-culture tier snaps a
/// French-browser user back to English the moment they authenticate.
/// </summary>
[Trait("Category", "Integration")]
public sealed class MeLanguageResolutionTests : IClassFixture<DependablyFactory>
{
    private readonly DependablyFactory _factory;

    public MeLanguageResolutionTests(DependablyFactory factory) => _factory = factory;

    [Fact]
    public async Task Me_WithoutPreferenceOrHeader_ReturnsEnglish()
    {
        string language = await GetMeLanguageAsync(acceptLanguage: null);
        Assert.Equal("en", language);
    }

    [Fact]
    public async Task Me_WithFrenchAcceptLanguage_ReturnsFrench()
    {
        string language = await GetMeLanguageAsync(acceptLanguage: "fr");
        Assert.Equal("fr", language);
    }

    [Fact]
    public async Task Me_WithRegionalFrenchAcceptLanguage_ReturnsFrench()
    {
        string language = await GetMeLanguageAsync(acceptLanguage: "fr-CA,fr;q=0.9,en;q=0.5");
        Assert.Equal("fr", language);
    }

    [Fact]
    public async Task Me_WithUnsupportedAcceptLanguage_FallsBackToEnglish()
    {
        string language = await GetMeLanguageAsync(acceptLanguage: "de-DE,de;q=0.9");
        Assert.Equal("en", language);
    }

    private async Task<string> GetMeLanguageAsync(string? acceptLanguage, string? jwt = null)
    {
        jwt ??= await _factory.CreateAdminJwt();
        using var client = _factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/v1/auth/me");
        req.Headers.Add("Cookie", $"dependably_session={jwt}");
        if (acceptLanguage is not null)
        {
            req.Headers.Add("Accept-Language", acceptLanguage);
        }

        var resp = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        return doc.RootElement.GetProperty("language").GetString()!;
    }
}

/// <summary>
/// The user-override tier beats the negotiated request culture. Kept in its own class
/// (own factory instance) because persisting the override would leak into the
/// header-only resolution tests above.
/// </summary>
[Trait("Category", "Integration")]
public sealed class MeLanguageOverrideTests : IClassFixture<DependablyFactory>
{
    private readonly DependablyFactory _factory;

    public MeLanguageOverrideTests(DependablyFactory factory) => _factory = factory;

    [Fact]
    public async Task Me_UserOverride_WinsOverAcceptLanguage()
    {
        string jwt = await _factory.CreateAdminJwt();
        using var client = _factory.CreateClient();

        // Persist an explicit English preference, then ask with a French browser.
        var set = new HttpRequestMessage(HttpMethod.Post, "/api/v1/users/me/language")
        {
            Content = new StringContent("""{"language":"en"}""", Encoding.UTF8, "application/json"),
        };
        set.Headers.Add("Cookie", $"dependably_session={jwt}");
        var setResp = await client.SendAsync(set);
        Assert.Equal(HttpStatusCode.NoContent, setResp.StatusCode);

        var me = new HttpRequestMessage(HttpMethod.Get, "/api/v1/auth/me");
        me.Headers.Add("Cookie", $"dependably_session={jwt}");
        me.Headers.Add("Accept-Language", "fr");
        var resp = await client.SendAsync(me);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        using var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync());
        Assert.Equal("en", doc.RootElement.GetProperty("language").GetString());
    }
}
