using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Pins the absent-field policy of PUT /api/v1/settings, field by field.
///
/// <para>The two gates on this surface — <c>anonymous_pull</c> and <c>allowlist_mode</c> — are
/// leave-unchanged-on-absent: a body that does not mention a gate does not write it. The
/// alternative (bind the CLR default) turns a partial write into a silent policy downgrade,
/// because the CLR default for both is <c>false</c> and <c>allowlist_mode=false</c> is the
/// permissive direction. Every field on this endpoint is written by one settings tab while the
/// others are absent from that tab's payload, so "absent" must never mean "off".</para>
///
/// <para>The upload-cap fields keep the opposite policy on purpose and are pinned here too:
/// <c>null</c> is their own domain value ("no org-level cap — fall back to the instance limit"),
/// so a caller clearing a cap has to be able to send it.</para>
/// </summary>
[Trait("Category", "Integration")]
public sealed class OrgSettingsPartialPutTests : IClassFixture<DependablyFactory>
{
    private readonly DependablyFactory _factory;

    public OrgSettingsPartialPutTests(DependablyFactory factory) => _factory = factory;

    private async Task<HttpClient> AdminJwtClient()
    {
        string jwt = await _factory.CreateAdminJwt();
        var c = _factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);
        return c;
    }

    private static async Task<JsonElement> ReadSettingsAsync(HttpClient client)
    {
        var get = await client.GetAsync("/api/v1/settings");
        get.EnsureSuccessStatusCode();
        return JsonDocument.Parse(await get.Content.ReadAsStringAsync()).RootElement.Clone();
    }

    [Fact]
    public async Task PartialPut_OmittingAllowlistMode_LeavesTheEnforcingGateOn()
    {
        using var client = await AdminJwtClient();

        // Enforcing starting state: allowlist on, anonymous pull off.
        (await client.PutAsJsonAsync("/api/v1/settings", new
        {
            anonymousPull = false,
            allowlistMode = true,
        })).EnsureSuccessStatusCode();

        // A body from a tab that renders neither gate. Binding the absent fields to their CLR
        // default would disable the allowlist and enable anonymous pull as a side effect.
        var put = await client.PutAsJsonAsync("/api/v1/settings", new { defaultLanguage = "en" });
        Assert.Equal(HttpStatusCode.NoContent, put.StatusCode);

        var settings = await ReadSettingsAsync(client);
        Assert.True(settings.GetProperty("allowlistMode").GetBoolean());
        Assert.False(settings.GetProperty("anonymousPull").GetBoolean());
        Assert.Equal("en", settings.GetProperty("defaultLanguage").GetString());
    }

    [Fact]
    public async Task ExplicitFalse_StillTurnsTheGateOff()
    {
        using var client = await AdminJwtClient();

        (await client.PutAsJsonAsync("/api/v1/settings", new
        {
            anonymousPull = false,
            allowlistMode = true,
        })).EnsureSuccessStatusCode();

        // Leave-unchanged applies to an ABSENT field only: an explicit false is a real write.
        (await client.PutAsJsonAsync("/api/v1/settings", new
        {
            anonymousPull = true,
            allowlistMode = false,
        })).EnsureSuccessStatusCode();

        var settings = await ReadSettingsAsync(client);
        Assert.False(settings.GetProperty("allowlistMode").GetBoolean());
        Assert.True(settings.GetProperty("anonymousPull").GetBoolean());
    }

    [Fact]
    public async Task UploadCap_ExplicitNull_ClearsTheOrgLevelCap()
    {
        using var client = await AdminJwtClient();

        (await client.PutAsJsonAsync("/api/v1/settings", new
        {
            anonymousPull = false,
            allowlistMode = false,
            maxUploadBytes = 4096L,
        })).EnsureSuccessStatusCode();

        var seeded = await ReadSettingsAsync(client);
        Assert.Equal(4096L, seeded.GetProperty("maxUploadBytes").GetInt64());

        // null is the cap's own "no org-level limit" value, not an absent field: it must clear.
        (await client.PutAsJsonAsync("/api/v1/settings", new
        {
            anonymousPull = false,
            allowlistMode = false,
            maxUploadBytes = (long?)null,
        })).EnsureSuccessStatusCode();

        var cleared = await ReadSettingsAsync(client);
        Assert.Equal(JsonValueKind.Null, cleared.GetProperty("maxUploadBytes").ValueKind);
    }
}
