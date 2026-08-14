using System.Net;
using System.Net.Http.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Dependably.Tests.Integration;

/// <summary>
/// Pins the SSO-only residual-session fix: flipping a tenant's <c>forms_login_enabled</c> from
/// true to false via <c>PUT /api/v1/auth-config</c> must bump <c>token_version</c> for the
/// tenant's password-backed users, so a session JWT minted from a password before the flip is
/// rejected on its very next request rather than staying live for the remainder of its 8h
/// lifetime. The bump is scoped precisely: it must not touch SAML JIT-provisioned (passwordless)
/// members, and it must not fire at all when the write leaves the flag unchanged.
/// </summary>
[Trait("Category", "Integration")]
public sealed class SsoOnlyRevokesPasswordSessionsTests : IClassFixture<DependablyFactory>, IAsyncLifetime
{
    private const string IdpEntityId = "https://idp.example.com/entity";

    private readonly DependablyFactory _factory;

    public SsoOnlyRevokesPasswordSessionsTests(DependablyFactory factory) => _factory = factory;

    public Task InitializeAsync() => ((IAsyncLifetime)_factory).InitializeAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task DisableFormsLogin_RejectsPreFlipPasswordSessionOnNextRequest()
    {
        // now-ok: seeds relative to the host's real clock so the server-side 10-minute
        // recency window (ValidateFormsLoginDisable) lands as intended.
        await SeedSamlConfigAsync(formsLoginEnabled: true, lastTestAt: DateTimeOffset.UtcNow.AddMinutes(-2));

        string memberId = await _factory.CreateUser($"pw-{Guid.NewGuid():N}@example.com", "memberPassword123", "member");
        using var memberClient = _factory.CreateClientWithBearer(await _factory.CreateUserJwt(memberId, "member"));

        // The pre-flip session works before the tenant is switched to SSO-only.
        Assert.Equal(HttpStatusCode.OK, (await memberClient.GetAsync("/api/v1/auth/me")).StatusCode);

        // Owner flips forms_login_enabled true -> false. A dedicated per-test owner (rather than
        // the shared bootstrap admin) so the bump this test pins doesn't leave the fixture's
        // shared owner's token_version advanced for a later test in this class.
        using var ownerClient = _factory.CreateClientWithBearer(await CreateOwnerJwtAsync());
        var flip = await ownerClient.PutAsync("/api/v1/auth-config", DisableFormsBody());
        Assert.Equal(HttpStatusCode.NoContent, flip.StatusCode);

        // The pre-flip password session is rejected on its very next request, not after its
        // remaining 8h lifetime.
        Assert.Equal(HttpStatusCode.Unauthorized, (await memberClient.GetAsync("/api/v1/auth/me")).StatusCode);
    }

    [Fact]
    public async Task DisableFormsLogin_DoesNotRejectSamlSessionMintedAfterTheFlip()
    {
        // now-ok: seeds relative to the host's real clock so the server-side 10-minute
        // recency window (ValidateFormsLoginDisable) lands as intended.
        await SeedSamlConfigAsync(formsLoginEnabled: true, lastTestAt: DateTimeOffset.UtcNow.AddMinutes(-2));

        using var ownerClient = _factory.CreateClientWithBearer(await CreateOwnerJwtAsync());
        var flip = await ownerClient.PutAsync("/api/v1/auth-config", DisableFormsBody());
        Assert.Equal(HttpStatusCode.NoContent, flip.StatusCode);

        // A session minted AFTER the flip via SAML — the adversarial twin. The bump must not
        // turn the SSO-only flip into a sign-everyone-out event for the sessions it was never
        // meant to touch.
        var login = _factory.Services.GetRequiredService<LoginService>();
        string orgId = await GetDefaultOrgIdAsync();
        string nameId = $"post-flip-{Guid.NewGuid():N}";
        string email = $"{nameId}@example.com";
        var samlLogin = await login.LoginSamlAsync(orgId, IdpEntityId, nameId, email);
        Assert.NotNull(samlLogin.Token);

        using var samlClient = _factory.CreateClientWithBearer(samlLogin.Token!);
        Assert.Equal(HttpStatusCode.OK, (await samlClient.GetAsync("/api/v1/auth/me")).StatusCode);
    }

    [Fact]
    public async Task UnrelatedSave_WithFlagAlreadyFalse_DoesNotBumpTokenVersion()
    {
        // forms_login_enabled is already false — disablingForms is false for this write, so no
        // lockout precondition (recent test, metadata) is needed either.
        await SeedSamlConfigAsync(formsLoginEnabled: false, lastTestAt: null);

        string memberId = await _factory.CreateUser($"pw-{Guid.NewGuid():N}@example.com", "memberPassword123", "member");
        long versionBefore = await ReadTokenVersionAsync(memberId);
        using var memberClient = _factory.CreateClientWithBearer(await _factory.CreateUserJwt(memberId, "member"));
        Assert.Equal(HttpStatusCode.OK, (await memberClient.GetAsync("/api/v1/auth/me")).StatusCode);

        // An unrelated save that leaves forms_login_enabled=false (only the button label changes).
        using var ownerClient = _factory.CreateClientWithBearer(await CreateOwnerJwtAsync());
        var body = JsonContent.Create(new
        {
            enabled = true,
            formsLoginEnabled = false,
            spEntityId = (string?)null,
            nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            emailAttribute = (string?)null,
            buttonLabel = "Sign in with Corp SSO",
        });
        var resp = await ownerClient.PutAsync("/api/v1/auth-config", body);
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);

        // token_version is untouched...
        Assert.Equal(versionBefore, await ReadTokenVersionAsync(memberId));
        // ...and the member's pre-existing session is still accepted.
        Assert.Equal(HttpStatusCode.OK, (await memberClient.GetAsync("/api/v1/auth/me")).StatusCode);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    // A fresh, disposable owner distinct from the fixture's shared bootstrap admin. Several
    // tests in this class deliberately bump token_version for every password-backed user in the
    // tenant (that is the fix under test), and the shared bootstrap admin is itself
    // password-backed — reusing it as the caller would leave its token_version advanced for
    // whichever test in this class runs next, an ordering hazard the other tests in this
    // repository avoid by never bumping the shared owner.
    private async Task<string> CreateOwnerJwtAsync()
    {
        string ownerId = await _factory.CreateUser($"owner-{Guid.NewGuid():N}@example.com", "ownerPassword123", "owner");
        return await _factory.CreateUserJwt(ownerId, "owner");
    }

    private static JsonContent DisableFormsBody() => JsonContent.Create(new
    {
        enabled = true,
        formsLoginEnabled = false,
        spEntityId = (string?)null,
        nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        emailAttribute = (string?)null,
        buttonLabel = (string?)null,
    });

    private async Task<string> GetDefaultOrgIdAsync()
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        return await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM orgs WHERE slug = 'default' LIMIT 1")
            ?? throw new InvalidOperationException("default org not found");
    }

    private async Task<long> ReadTokenVersionAsync(string userId)
    {
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT token_version FROM users WHERE id = @id", new { id = userId });
    }

    private async Task SeedSamlConfigAsync(bool formsLoginEnabled, DateTimeOffset? lastTestAt)
    {
        string orgId = await GetDefaultOrgIdAsync();
        await using var conn = await _factory.Services.GetRequiredService<IMetadataStore>().OpenAsync();
        await conn.ExecuteAsync("DELETE FROM tenant_saml_config WHERE org_id = @orgId", new { orgId });
        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_saml_config (org_id, enabled, forms_login_enabled,
                idp_entity_id, idp_sso_url, idp_signing_cert, name_id_format, last_test_at)
            VALUES (@orgId, 1, @forms, @entityId, @ssoUrl, @cert, @nameIdFormat, @lastTestAt)
            """,
            new
            {
                orgId,
                forms = formsLoginEnabled ? 1 : 0,
                entityId = IdpEntityId,
                ssoUrl = "https://idp.example.com/sso",
                cert = SampleIdpCertBase64,
                nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                lastTestAt = lastTestAt?.ToUtcIso(),
            });
    }

    // Self-signed cert generated for tests only — never used to actually validate signatures
    // (these tests bypass ITfoxtec via LoginService directly, matching SamlTests's fixture).
    private const string SampleIdpCertBase64 =
        "MIIDXTCCAkWgAwIBAgIJALzWqv6FcU3TMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV" +
        "BAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX" +
        "aWRnaXRzIFB0eSBMdGQwHhcNMjAwMTAxMDAwMDAwWhcNMzAwMTAxMDAwMDAwWjBF" +
        "MQswCQYDVQQGEwJVUzETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50" +
        "ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB" +
        "CgKCAQEAwOlEDR8Y6f6vS0zYxrU5+hmOZDZIMFjF2H7Ckw2P5YuUQrUe7PtbFRFb" +
        "6rL6nZqkGE9OvRnKwbuyYQT9JEH5fQrbi7fIp+W7DdDWvCm0GLP8DNeQZMpvCiKG" +
        "DWTZ52jNk4qJ6uvF5VxC7sIxL5C7r6LRiq5cLR5N8JJF3qXXqjgZS3oNQPuVwjaP" +
        "GJBczQHBu5mJqvr9Q3M7VJqIb8LMNh/tTjvQfQYxEvW5j6mOg4y1L8O9rHb2uVm0" +
        "lPBd/L7UrQUe/pEWjzxxZuBcVxWnkD8+y+wSDUlW0OjjYnBxJ0SSUEMnkqAQM/qj" +
        "FW0Ts7/uXHZb89cqdrx0Q0M7e8C5dwIDAQABo1AwTjAdBgNVHQ4EFgQUqXyR1jyM" +
        "Sc/hSVEXqVwOKy2KTM4wHwYDVR0jBBgwFoAUqXyR1jyMSc/hSVEXqVwOKy2KTM4w" +
        "DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAOlH+YgQYNkPMNgAQ5kQ4" +
        "4u+nE/fF8vQfWEcxZTdVghP7wJ54dkvCQ9wgFKBe8ld6WUEuM4Wr/PyDpOzh7M5g" +
        "9pWUjPqJ5LlIK9HZKcdz5G4UiMRCmnH3wU5q3CUwyDwR3sbpLjyMJZ5fWxIa6KYr" +
        "JaCJjDz+GpHQYHwSjB6X0rmsKzQMhqHa3Q9+FwvKHV60KbkPI9jq37xvwsrsr5kS" +
        "2J0sIQqNbxQcXPGMQfOK3uGNoZmwT1oHVHjMRKOq1A9cYXIKNQjxnIo6TEoCkiZB" +
        "txFvB4i27FwLKCGyGFqB9LGUhQ9rEpKSpXRhJPL8K6jSBWGJpRMAJWOKhOoKIO7g" +
        "kg==";
}
