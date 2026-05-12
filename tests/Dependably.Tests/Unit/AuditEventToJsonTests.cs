using System.Text.Json;
using Dependably.Infrastructure.Audit.Events;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers the typed audit-event records' <c>ToJson()</c> helpers (#52). The snake_case
/// serialization is load-bearing: SIEM consumers grep on these keys, and a regression that
/// silently emits PascalCase would only surface as a missing-data alert downstream.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AuditEventToJsonTests
{
    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement;

    // ── ClaimEvents ───────────────────────────────────────────────────────────

    [Fact]
    public void ClaimEvents_Create_SnakeCasesAllFields()
    {
        var ev = new ClaimEvents.Create(
            Ecosystem: "npm", Name: "lodash", State: "reserved",
            Reason: "owner takeover", PurgesProxy: true);

        var root = Parse(ev.ToJson());

        Assert.Equal("npm", root.GetProperty("ecosystem").GetString());
        Assert.Equal("lodash", root.GetProperty("name").GetString());
        Assert.Equal("reserved", root.GetProperty("state").GetString());
        Assert.Equal("owner takeover", root.GetProperty("reason").GetString());
        Assert.True(root.GetProperty("purges_proxy").GetBoolean());
    }

    [Fact]
    public void ClaimEvents_Transition_EmitsPriorAndNewStateInSnakeCase()
    {
        var ev = new ClaimEvents.Transition(
            Ecosystem: "pypi", Name: "django", PriorState: "reserved",
            NewState: "claimed", Reason: "complete", PurgesProxy: false);

        var root = Parse(ev.ToJson());

        Assert.Equal("reserved", root.GetProperty("prior_state").GetString());
        Assert.Equal("claimed", root.GetProperty("new_state").GetString());
        Assert.False(root.GetProperty("purges_proxy").GetBoolean());
    }

    [Fact]
    public void ClaimEvents_Release_EmitsLocalVersionCount()
    {
        var ev = new ClaimEvents.Release(
            Ecosystem: "nuget", Name: "newtonsoft.json", PriorState: "claimed",
            Reason: "owner abandoned", LocalVersionCount: 42);

        var root = Parse(ev.ToJson());

        Assert.Equal(42, root.GetProperty("local_version_count").GetInt32());
        Assert.Equal("owner abandoned", root.GetProperty("reason").GetString());
    }

    [Theory]
    [InlineData(ClaimEvents.TypeCreate, "claim.create")]
    [InlineData(ClaimEvents.TypeTransition, "claim.transition")]
    [InlineData(ClaimEvents.TypeRelease, "claim.release")]
    public void ClaimEvents_TypeConstants_AreCanonicalStrings(string actual, string expected)
    {
        Assert.Equal(expected, actual);
    }

    // ── TenantEvents ──────────────────────────────────────────────────────────

    [Fact]
    public void TenantEvents_SettingChange_EmitsPriorAndNewValueInSnakeCase()
    {
        var ev = new TenantEvents.SettingChange("max_upload_bytes", PriorValue: 1024L, NewValue: 2048L);

        var root = Parse(ev.ToJson());

        Assert.Equal("max_upload_bytes", root.GetProperty("key").GetString());
        Assert.Equal(1024, root.GetProperty("prior_value").GetInt64());
        Assert.Equal(2048, root.GetProperty("new_value").GetInt64());
    }

    [Fact]
    public void TenantEvents_SettingChange_NullValuesSerializeAsJsonNull()
    {
        var ev = new TenantEvents.SettingChange("retention_days", PriorValue: null, NewValue: 30);

        var root = Parse(ev.ToJson());

        Assert.Equal(JsonValueKind.Null, root.GetProperty("prior_value").ValueKind);
        Assert.Equal(30, root.GetProperty("new_value").GetInt32());
    }

    [Fact]
    public void TenantEvents_TokenCreate_EmitsCapabilitiesAsStructuredArrayAndJsonString()
    {
        var ev = new TenantEvents.TokenCreate(
            TokenId: "tok-1",
            CapabilitiesJson: "[\"publish:*\",\"read:metadata\"]",
            Capabilities: new[] { "publish:*", "read:metadata" },
            TokenKind: "user",
            ExpiresAt: new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero));

        var root = Parse(ev.ToJson());

        Assert.Equal("tok-1", root.GetProperty("token_id").GetString());
        Assert.Equal("[\"publish:*\",\"read:metadata\"]", root.GetProperty("capabilities_json").GetString());
        var arr = root.GetProperty("capabilities");
        Assert.Equal(JsonValueKind.Array, arr.ValueKind);
        Assert.Equal(2, arr.GetArrayLength());
        Assert.Equal("publish:*", arr[0].GetString());
        Assert.Equal("user", root.GetProperty("token_kind").GetString());
        Assert.Equal("2027-01-01T00:00:00+00:00", root.GetProperty("expires_at").GetString());
    }

    [Fact]
    public void TenantEvents_TokenRevoke_MinimalShape()
    {
        var ev = new TenantEvents.TokenRevoke("tok-9", "cicd");

        var root = Parse(ev.ToJson());

        Assert.Equal("tok-9", root.GetProperty("token_id").GetString());
        Assert.Equal("cicd", root.GetProperty("token_kind").GetString());
    }

    [Theory]
    [InlineData(TenantEvents.TypeSettingChange, "tenant.setting.change")]
    [InlineData(TenantEvents.TypeTokenCreate, "tenant.token.create")]
    [InlineData(TenantEvents.TypeTokenRevoke, "tenant.token.revoke")]
    public void TenantEvents_TypeConstants_AreCanonicalStrings(string actual, string expected)
    {
        Assert.Equal(expected, actual);
    }

    // ── AuthEvents ────────────────────────────────────────────────────────────

    [Fact]
    public void AuthEvents_LoginSuccess_EmitsRealmAndMethod()
    {
        var ev = new AuthEvents.LoginSuccess(Realm: "tenant", Method: "forms");

        var root = Parse(ev.ToJson());

        Assert.Equal("tenant", root.GetProperty("realm").GetString());
        Assert.Equal("forms", root.GetProperty("method").GetString());
    }

    [Fact]
    public void AuthEvents_LoginFailure_EmitsEmailHashNotPlaintext()
    {
        // Compliance invariant: email is recorded as a hash, never plaintext.
        var ev = new AuthEvents.LoginFailure(Realm: "tenant", EmailHash: "abcd1234");

        var json = ev.ToJson();

        Assert.DoesNotContain("email\"", json); // no plaintext `email` field
        var root = Parse(json);
        Assert.Equal("abcd1234", root.GetProperty("email_hash").GetString());
    }

    [Fact]
    public void AuthEvents_Lockout_SnakeCasesEmailHash()
    {
        var ev = new AuthEvents.Lockout(Realm: "system", EmailHash: "abcd1234");

        var root = Parse(ev.ToJson());

        Assert.Equal("system", root.GetProperty("realm").GetString());
        Assert.Equal("abcd1234", root.GetProperty("email_hash").GetString());
    }

    [Fact]
    public void AuthEvents_SamlSuccess_EmitsIdpEntityIdAndNameId()
    {
        var ev = new AuthEvents.SamlSuccess(
            IdpEntityId: "https://idp.example.com",
            NameId: "user@example.com",
            Path: "/saml/acs");

        var root = Parse(ev.ToJson());

        Assert.Equal("https://idp.example.com", root.GetProperty("idp_entity_id").GetString());
        Assert.Equal("user@example.com", root.GetProperty("name_id").GetString());
        Assert.Equal("/saml/acs", root.GetProperty("path").GetString());
    }

    [Fact]
    public void AuthEvents_SamlFailure_NullablesSerializeAsJsonNull()
    {
        var ev = new AuthEvents.SamlFailure(
            Reason: "signature_invalid",
            IdpEntityId: null,
            NameId: null);

        var root = Parse(ev.ToJson());

        Assert.Equal("signature_invalid", root.GetProperty("reason").GetString());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("idp_entity_id").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("name_id").ValueKind);
    }

    [Theory]
    [InlineData(AuthEvents.TypeLoginSuccess, "auth.login.success")]
    [InlineData(AuthEvents.TypeLoginFailure, "auth.login.failure")]
    [InlineData(AuthEvents.TypeLockout, "auth.lockout.triggered")]
    [InlineData(AuthEvents.TypeSamlSuccess, "auth.saml.login.success")]
    [InlineData(AuthEvents.TypeSamlFailure, "auth.saml.login.failure")]
    public void AuthEvents_TypeConstants_AreCanonicalStrings(string actual, string expected)
    {
        Assert.Equal(expected, actual);
    }
}
