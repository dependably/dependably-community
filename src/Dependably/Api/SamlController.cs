using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Xml;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Dependably.Infrastructure;
using Dependably.Security;

namespace Dependably.Api;

/// <summary>
/// SAML 2.0 SP endpoints. Per-tenant configuration is loaded at request time from
/// <see cref="SamlConfigRepository"/> — there is no static <c>AddSaml2(...)</c> registration,
/// because each tenant has its own IdP and signing certificate uploaded via the settings UI.
///
/// Routes are tenant-scoped: every request resolves the tenant from
/// <c>HttpContext.Items[TenantContext.HttpItemsKey]</c> (single-mode appliance or multi-mode
/// subdomain). Apex/uninitialized requests get a 404 — SAML is tenant-only by design;
/// system_admin login stays on forms.
/// </summary>
[ApiController]
[Route("saml")]
[AllowAnonymous]
public sealed class SamlController : ControllerBase
{
    private const string TestCookieName = "dependably_saml_test";
    private const string SessionCookieName = "dependably_session";
    private const string DataProtectionPurpose = "saml-test-marker.v1";
    private static readonly TimeSpan TestCookieLifetime = TimeSpan.FromMinutes(15);

    private readonly SamlConfigRepository _samlConfig;
    private readonly LoginService _login;
    private readonly OrgAccessGuard _guard;
    private readonly IDataProtectionProvider _dataProtection;
    private readonly ILogger<SamlController> _logger;
    private readonly IPublicUrlBuilder _urls;

    public SamlController(
        SamlConfigRepository samlConfig,
        LoginService login,
        OrgAccessGuard guard,
        IDataProtectionProvider dataProtection,
        ILogger<SamlController> logger,
        IPublicUrlBuilder urls)
    {
        _samlConfig = samlConfig;
        _login = login;
        _guard = guard;
        _dataProtection = dataProtection;
        _logger = logger;
        _urls = urls;
    }

    // ── SP metadata ───────────────────────────────────────────────────────────

    /// <summary>GET /saml/metadata — XML SP metadata for the resolved tenant.</summary>
    [HttpGet("metadata")]
    public async Task<IActionResult> Metadata(CancellationToken ct)
    {
        var tenant = ResolveTenant();
        if (tenant is null) return NotFound();

        var cfg = await _samlConfig.GetAsync(tenant.TenantId!, ct);
        var saml2Config = BuildSaml2Configuration(cfg, requireIdp: false);

        var entityDescriptor = new EntityDescriptor(saml2Config)
        {
            ValidUntil = 365,
            SPSsoDescriptor = new SPSsoDescriptor
            {
                AuthnRequestsSigned = false,
                WantAssertionsSigned = true,
                NameIDFormats = new[] { new Uri(cfg?.NameIdFormat ?? NameIdentifierFormats.Email.OriginalString) },
                SingleLogoutServices = Array.Empty<SingleLogoutService>(),
                AssertionConsumerServices = new[]
                {
                    // HTTP-POST is the SAML 2.0 spec-recommended binding for assertions; mark
                    // it default. HTTP-Redirect is also advertised because some IdPs (Keycloak,
                    // configurably) emit Response messages via redirect — we accept both at the
                    // ACS endpoint and let the IdP pick whichever its admin has configured.
                    new AssertionConsumerService
                    {
                        Index = 0,
                        IsDefault = true,
                        Binding = ProtocolBindings.HttpPost,
                        Location = new Uri(AcsUri()),
                    },
                    new AssertionConsumerService
                    {
                        Index = 1,
                        Binding = ProtocolBindings.HttpRedirect,
                        Location = new Uri(AcsUri()),
                    },
                },
            },
        };

        var metadata = new Saml2Metadata(entityDescriptor).CreateMetadata();
        return Content(metadata.ToXml(), "application/samlmetadata+xml");
    }

    // ── SP-initiated SSO ──────────────────────────────────────────────────────

    /// <summary>
    /// GET /saml/login — builds an AuthnRequest and redirects to the IdP.
    /// <c>?test=1</c> requires admin/owner role and marks the run with a signed cookie so the
    /// ACS handler skips session issuance and records <c>last_test_at</c> instead.
    /// </summary>
    [HttpGet("login")]
    // `test` is bound as string (not bool) so query forms `?test=1`, `?test=true`, and even
    // `?test` all work. ASP.NET's default bool binder rejects anything that isn't literally
    // "true"/"false" with a 400, which surprises operators clicking the Test SSO button.
    public async Task<IActionResult> Login([FromQuery] string? test = null, CancellationToken ct = default)
    {
        var isTest = test is not null
            && !string.Equals(test, "0", StringComparison.Ordinal)
            && !string.Equals(test, "false", StringComparison.OrdinalIgnoreCase);

        var tenant = ResolveTenant();
        if (tenant is null) return NotFound();

        var cfg = await _samlConfig.GetAsync(tenant.TenantId!, ct);
        if (!IsSamlConfigured(cfg))
        {
            _logger.LogInformation("SAML rejected for tenant {TenantId}: state={SamlState}",
                tenant.TenantId, "config_missing");
            return Problem(statusCode: 404, detail: "SAML SSO is not configured for this tenant.");
        }
        if (!isTest && !cfg!.Enabled)
        {
            _logger.LogInformation("SAML rejected for tenant {TenantId}: state={SamlState}",
                tenant.TenantId, "disabled");
            return Problem(statusCode: 404, detail: "SAML SSO is not enabled for this tenant.");
        }

        string? testCid = null;
        if (isTest)
        {
            // Test runs are admin/owner only. The guard reads the JWT cookie that the user
            // already has from forms-login; failures bubble up as 401/403/404 as usual.
            var guardResult = await _guard.AuthorizeCapAsync(User, HttpContext, Capabilities.TenantConfigure, ct);
            if (guardResult is not null) return guardResult;

            // SetTestCookie issues the server-side test run row and sets a signed cookie.
            // The cid is also placed in RelayState so the ACS can detect test mode even when
            // the cookie is blocked (SameSite=Lax is not sent on cross-site form POSTs from the
            // IdP — relay state is echoed back verbatim by the IdP and has no SameSite restriction).
            testCid = await SetTestCookieAsync(tenant.TenantId!, ct);
        }

        var saml2Config = BuildSaml2Configuration(cfg, requireIdp: true);
        var authnRequest = new Saml2AuthnRequest(saml2Config)
        {
            // Always require fresh IdP auth on SP-initiated login. dependably is a security-
            // sensitive artifact repository; we don't want silent session reuse from any IdP
            // session the browser happens to hold. Also keeps Test SAML and Sign-in-with-SSO
            // symmetric — "test passes" implies "login works".
            ForceAuthn = true,
            NameIdPolicy = new NameIdPolicy
            {
                AllowCreate = true,
                Format = cfg!.NameIdFormat,
            },
        };

        var binding = new Saml2RedirectBinding();
        if (testCid is not null) binding.RelayState = "test:" + testCid;
        binding.Bind(authnRequest);
        return Redirect(binding.RedirectLocation.OriginalString);
    }

    // ── Assertion Consumer ────────────────────────────────────────────────────

    /// <summary>
    /// POST or GET /saml/acs — validates the SAML response, then either issues a session JWT
    /// (normal flow) or records a successful test (test cookie present).
    ///
    /// Both bindings are accepted: HTTP-POST puts the response in a form body, HTTP-Redirect
    /// puts it in the query string with separate Signature/SigAlg parameters. Spec-recommended
    /// is HTTP-POST, but Keycloak (and some other IdPs) configurably emit HTTP-Redirect for the
    /// response too — rejecting GET would lock those tenants out for no real benefit.
    /// </summary>
    [HttpPost("acs")]
    [HttpGet("acs")]
    public async Task<IActionResult> Acs(CancellationToken ct)
    {
        var tenant = ResolveTenant();
        if (tenant is null) return NotFound();

        var cfg = await _samlConfig.GetAsync(tenant.TenantId!, ct);

        var (isTest, testActorId, testError) = await ResolveTestModeAsync(tenant.TenantId!, ct);
        if (testError is not null) return testError;

        // When test mode detection fails (cookie blocked by SameSite=Lax + RelayState absent),
        // isTest is false and the enabled gate below would return a JSON 404. If a SAMLResponse
        // IS present the user completed the IdP round-trip — give them a proper test-result
        // redirect instead of a raw error blob.
        if (!isTest && cfg?.Enabled != true)
        {
            var hasSamlResponse = Request.HasFormContentType
                ? Request.Form.ContainsKey("SAMLResponse")
                : Request.Query.ContainsKey("SAMLResponse");
            if (hasSamlResponse)
                return RedirectToTestResult(error: "test_session_lost",
                    detail: "Test session not found — the browser may have blocked the test cookie. Try the test again.");
        }

        var configError = ValidateSamlConfigured(cfg, tenant.TenantId!, isTest);
        if (configError is not null) return configError;

        var (authnResponse, samlError) = ParseSamlResponse(cfg!, tenant.TenantId!, isTest);
        if (samlError is not null) return samlError;

        var nameId = authnResponse!.NameId?.Value;
        if (string.IsNullOrWhiteSpace(nameId))
            return SamlFailure(isTest, "missing_nameid", "Assertion did not include a NameID.", 400);

        var email = ExtractEmail(authnResponse, cfg!);

        if (isTest)
        {
            await _login.RecordSamlTestAsync(tenant.TenantId!, cfg!.IdpEntityId!, nameId, email, testActorId, ct);
            await _samlConfig.RecordTestSuccessAsync(tenant.TenantId!, email ?? "", ct);
            return RedirectToTestResult(email: email, nameId: nameId);
        }

        var result = await _login.LoginSamlAsync(tenant.TenantId!, cfg!.IdpEntityId!, nameId, email, ct);
        if (result.Token is null)
            return Problem(statusCode: 401, detail: result.Error ?? "SAML login failed.");

        SetSessionCookie(result.Token);
        return Redirect("/");
    }

    // Detect test mode up front, before the Enabled gate, so admins can validate an
    // unpublished SAML config end-to-end. A pending cid in saml_test_runs is the proof
    // of a real test session: TryConsume both validates and atomically marks consumed,
    // so a leaked cid can't drive a second round-trip.
    //
    // Two sources are checked in order:
    //  1. The signed test cookie (same-site requests where SameSite=Lax is honoured).
    //  2. SAML RelayState echoed back by the IdP (cross-site POST binding where the cookie
    //     is suppressed by SameSite=Lax — the normal path for IdP form POSTs).
    private async Task<(bool IsTest, string? ActorId, IActionResult? Error)> ResolveTestModeAsync(string tenantId, CancellationToken ct)
    {
        string? testCid = null;
        string? testActorId = null;

        if (TryReadTestCookie(tenantId, out testActorId, out testCid))
        {
            ClearTestCookie();
        }
        else
        {
            // Cookie was not sent (IdP cross-site POST suppresses SameSite=Lax cookies).
            // Fall back to the RelayState that Login placed on the AuthnRequest — IdPs echo
            // it back verbatim and it has no SameSite restriction.
            var relayState = Request.HasFormContentType
                ? Request.Form["RelayState"].FirstOrDefault()
                : Request.Query["RelayState"].FirstOrDefault();
            if (relayState is not null && relayState.StartsWith("test:", StringComparison.Ordinal))
                testCid = relayState["test:".Length..];
        }

        if (testCid is null) return (false, null, null);

        if (await _samlConfig.TryConsumeTestRunAsync(testCid, tenantId, ct))
            return (true, testActorId, null);

        _logger.LogInformation(
            "SAML test cid for tenant {TenantId} could not be consumed (replayed/expired/missing)",
            tenantId);
        return (false, null, RedirectToTestResult(error: "test_session_invalid",
            detail: "Test session already consumed or expired. Click Test again."));
    }

    private ObjectResult? ValidateSamlConfigured(TenantSamlConfig? cfg, string tenantId, bool isTest)
    {
        if (!IsSamlConfigured(cfg))
        {
            _logger.LogInformation("SAML rejected for tenant {TenantId}: state={SamlState}", tenantId, "config_missing");
            return Problem(statusCode: 404, detail: "SAML SSO is not configured for this tenant.");
        }
        if (!isTest && !cfg!.Enabled)
        {
            _logger.LogInformation("SAML rejected for tenant {TenantId}: state={SamlState}", tenantId, "disabled");
            return Problem(statusCode: 404, detail: "SAML SSO is not enabled for this tenant.");
        }
        return null;
    }

    private (Saml2AuthnResponse? Response, IActionResult? Error) ParseSamlResponse(TenantSamlConfig cfg, string tenantId, bool isTest)
    {
        var saml2Config = BuildSaml2Configuration(cfg, requireIdp: true);
        var authnResponse = new Saml2AuthnResponse(saml2Config);
        Saml2Binding binding = HttpMethods.IsPost(Request.Method)
            ? new Saml2PostBinding()
            : new Saml2RedirectBinding();

        try
        {
            binding.ReadSamlResponse(Request.ToGenericHttpRequest(), authnResponse);
            if (authnResponse.Status != Saml2StatusCodes.Success)
            {
                _logger.LogWarning("SAML response from IdP {IdpEntityId} returned non-success status {Status}",
                    cfg.IdpEntityId, authnResponse.Status);
                return (null, SamlFailure(isTest, "idp_rejected", authnResponse.Status.ToString(), 401,
                    realProblemDetail: $"IdP rejected the request: {authnResponse.Status}"));
            }
            binding.Unbind(Request.ToGenericHttpRequest(), authnResponse);
            return (authnResponse, null);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "SAML response validation failed for tenant {TenantId}", tenantId);
            return (null, SamlFailure(isTest, "validation_failed", ex.Message, 401,
                realProblemDetail: "SAML response validation failed."));
        }
    }

    private IActionResult SamlFailure(bool isTest, string testError, string testDetail, int realStatus, string? realProblemDetail = null)
        => isTest
            ? RedirectToTestResult(error: testError, detail: testDetail)
            : Problem(statusCode: realStatus, detail: realProblemDetail ?? testDetail);

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Single source of truth for "SAML is fully configured" — i.e. IdP metadata is uploaded
    /// and parseable. The three fields are written together by <c>UpsertMetadataAsync</c>;
    /// requiring all three matches the actual write path and prevents partial-state drift.
    /// Distinct from <c>Enabled</c> (the publish-on-sign-in toggle).
    /// </summary>
    private static bool IsSamlConfigured(TenantSamlConfig? cfg) =>
        cfg is not null
        && !string.IsNullOrWhiteSpace(cfg.IdpEntityId)
        && !string.IsNullOrWhiteSpace(cfg.IdpSsoUrl)
        && !string.IsNullOrWhiteSpace(cfg.IdpSigningCert);

    private RedirectResult RedirectToTestResult(
        string? email = null, string? nameId = null, string? error = null, string? detail = null)
    {
        var qs = new QueryString();
        if (!string.IsNullOrEmpty(email)) qs = qs.Add("email", email);
        if (!string.IsNullOrEmpty(nameId)) qs = qs.Add("nameid", nameId);
        if (!string.IsNullOrEmpty(error)) qs = qs.Add("error", error);
        if (!string.IsNullOrEmpty(detail)) qs = qs.Add("detail", detail);
        return Redirect("/saml-test-result" + qs.ToUriComponent());
    }

    private TenantContext? ResolveTenant()
    {
        var ctx = HttpContext.Items[TenantContext.HttpItemsKey] as TenantContext;
        return ctx is not null && ctx.IsTenant && ctx.TenantId is not null ? ctx : null;
    }

    private string AcsUri() => _urls.Absolute(HttpContext, "/saml/acs");
    private string SpEntityIdDefault() => _urls.Absolute(HttpContext, "/saml/metadata");

    private Saml2Configuration BuildSaml2Configuration(TenantSamlConfig? cfg, bool requireIdp)
    {
        var spEntityId = !string.IsNullOrWhiteSpace(cfg?.SpEntityId) ? cfg!.SpEntityId! : SpEntityIdDefault();

        var saml2 = new Saml2Configuration
        {
            Issuer = spEntityId,
            SignAuthnRequest = false,
            AudienceRestricted = true,
            // SAML SP trust is anchored at the IdP cert uploaded via metadata, not at a CA.
            // Self-signed IdP signing certs are the norm (Entra ID, Okta, ADFS, etc.); chain
            // validation rejects them and is the wrong trust model for SAML. Signature is still
            // verified against SignatureValidationCertificates below.
            CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None,
            RevocationMode = X509RevocationMode.NoCheck,
        };
        saml2.AllowedAudienceUris.Add(spEntityId);

        if (requireIdp)
        {
            if (cfg is null || string.IsNullOrWhiteSpace(cfg.IdpEntityId) || string.IsNullOrWhiteSpace(cfg.IdpSigningCert))
                throw new InvalidOperationException("IdP not configured.");

            saml2.AllowedIssuer = cfg.IdpEntityId;
            saml2.SingleSignOnDestination = new Uri(cfg.IdpSsoUrl!);

            var certBytes = Convert.FromBase64String(cfg.IdpSigningCert.Replace("\n", "").Replace("\r", "").Replace(" ", ""));
            var idpCert = X509CertificateLoader.LoadCertificate(certBytes);
            saml2.SignatureValidationCertificates.Add(idpCert);
        }

        return saml2;
    }

    private static string? ExtractEmail(Saml2AuthnResponse response, TenantSamlConfig cfg)
    {
        // Attribute override wins. Look for the configured attribute by name (case-insensitive).
        if (!string.IsNullOrWhiteSpace(cfg.EmailAttribute))
        {
            var match = response.ClaimsIdentity.Claims
                .FirstOrDefault(c => string.Equals(c.Type, cfg.EmailAttribute, StringComparison.OrdinalIgnoreCase));
            if (match is not null && !string.IsNullOrWhiteSpace(match.Value)) return match.Value;
        }

        // Common email claim types issued by Okta/AzureAD/ADFS (in priority order).
        foreach (var name in new[] {
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            "urn:oid:0.9.2342.19200300.100.1.3",
            "email",
            "mail",
            "EmailAddress",
        })
        {
            var match = response.ClaimsIdentity.Claims
                .FirstOrDefault(c => string.Equals(c.Type, name, StringComparison.OrdinalIgnoreCase));
            if (match is not null && !string.IsNullOrWhiteSpace(match.Value)) return match.Value;
        }

        // Fall back to NameID when its format is the email format.
        var nameIdFormat = response.NameId?.Format?.OriginalString;
        var nameIdValue = response.NameId?.Value;
        if (!string.IsNullOrWhiteSpace(nameIdValue) &&
            (nameIdFormat is null
             || nameIdFormat.Equals(NameIdentifierFormats.Email.OriginalString, StringComparison.OrdinalIgnoreCase)
             || nameIdValue.Contains('@')))
        {
            return nameIdValue;
        }

        return null;
    }

    // ── Test cookie (Data Protection-signed) ──────────────────────────────────

    // Returns the cid so the caller can embed it in SAML RelayState as the cross-site
    // fallback for test detection (SameSite=Lax blocks the cookie on IdP form POSTs).
    private async Task<string> SetTestCookieAsync(string tenantId, CancellationToken ct)
    {
        var actorId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        var cid = Guid.NewGuid().ToString("N");
        var expiresAt = DateTimeOffset.UtcNow.Add(TestCookieLifetime);

        // Server-side correlation row makes the cid one-shot: TryConsumeTestRunAsync stamps
        // consumed_at on the first ACS hit, so a replayed relay state or cookie can't drive a
        // second round-trip even within the 15-minute TTL.
        await _samlConfig.IssueTestRunAsync(cid, tenantId, actorId, expiresAt, ct);

        var payload = JsonSerializer.Serialize(new
        {
            tid = tenantId,
            actor = actorId,
            cid,
            exp = expiresAt.ToUnixTimeSeconds(),
        });
        var protector = _dataProtection.CreateProtector(DataProtectionPurpose);
        var protectedValue = protector.Protect(payload);

        var testCookieOptions = _urls.SessionCookieOptions(HttpContext, SameSiteMode.Lax);
        testCookieOptions.MaxAge = TestCookieLifetime;
        Response.Cookies.Append(TestCookieName, protectedValue, testCookieOptions);
        return cid;
    }

    private bool TryReadTestCookie(string tenantId, out string? actorId, out string? cid)
    {
        actorId = null;
        cid = null;
        var raw = Request.Cookies[TestCookieName];
        if (string.IsNullOrEmpty(raw)) return false;
        try
        {
            var protector = _dataProtection.CreateProtector(DataProtectionPurpose);
            var json = protector.Unprotect(raw);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (!root.TryGetProperty("tid", out var tidEl) || tidEl.GetString() != tenantId) return false;
            if (!root.TryGetProperty("exp", out var expEl)) return false;
            if (DateTimeOffset.FromUnixTimeSeconds(expEl.GetInt64()) < DateTimeOffset.UtcNow) return false;
            if (root.TryGetProperty("actor", out var actorEl)) actorId = actorEl.GetString();
            if (root.TryGetProperty("cid", out var cidEl)) cid = cidEl.GetString();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void ClearTestCookie() => Response.Cookies.Delete(TestCookieName);

    private void SetSessionCookie(string token)
    {
        // Lax (not Strict) so the redirect from IdP delivers the cookie on the first request
        // back to the SP. Forms login uses Strict because it's same-site to begin with.
        Response.Cookies.Append(SessionCookieName, token, _urls.SessionCookieOptions(HttpContext, SameSiteMode.Lax));
    }
}

/// <summary>
/// Helpers for parsing IdP metadata XML uploaded by tenant admins. Kept in this file
/// because this is the only consumer; if a second place needs it later, lift it out.
/// </summary>
public static class IdpMetadataParser
{
    public sealed record ParsedIdp(string EntityId, string SsoUrl, string SigningCertBase64);

    private const string MdNs = "urn:oasis:names:tc:SAML:2.0:metadata";
    private const string DsNs = "http://www.w3.org/2000/09/xmldsig#";
    private const string HttpRedirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    private const string HttpPostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

    public static ParsedIdp Parse(string metadataXml)
    {
        if (string.IsNullOrWhiteSpace(metadataXml))
            throw new ArgumentException("Metadata XML is empty.", nameof(metadataXml));

        var doc = new XmlDocument { PreserveWhitespace = false };
        // External entity resolution is disabled by default in modern .NET XmlDocument; we also
        // refuse DTDs explicitly to be safe against XML External Entity (XXE) attacks.
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
        };
        using var reader = XmlReader.Create(new StringReader(metadataXml), settings);
        doc.Load(reader);

        var nsm = new XmlNamespaceManager(doc.NameTable);
        nsm.AddNamespace("md", MdNs);
        nsm.AddNamespace("ds", DsNs);

        var entityDescriptor = doc.SelectSingleNode("//md:EntityDescriptor", nsm)
            ?? throw new InvalidOperationException("Metadata is missing <EntityDescriptor>.");
        var entityId = entityDescriptor.Attributes?["entityID"]?.Value
            ?? throw new InvalidOperationException("Metadata is missing entityID.");

        var idpDescriptor = entityDescriptor.SelectSingleNode("md:IDPSSODescriptor", nsm)
            ?? throw new InvalidOperationException("Metadata is missing <IDPSSODescriptor>.");

        // Prefer HTTP-Redirect; fall back to HTTP-POST.
        var ssoNode = idpDescriptor.SelectSingleNode(
                $"md:SingleSignOnService[@Binding='{HttpRedirectBinding}']", nsm)
            ?? idpDescriptor.SelectSingleNode(
                $"md:SingleSignOnService[@Binding='{HttpPostBinding}']", nsm)
            ?? throw new InvalidOperationException("Metadata is missing a usable SingleSignOnService endpoint.");
        var ssoUrl = ssoNode.Attributes?["Location"]?.Value
            ?? throw new InvalidOperationException("SingleSignOnService is missing Location.");

        // Prefer KeyDescriptor with use='signing'; otherwise the first KeyDescriptor.
        var certNode = idpDescriptor.SelectSingleNode(
                "md:KeyDescriptor[@use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate", nsm)
            ?? idpDescriptor.SelectSingleNode(
                "md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate", nsm)
            ?? throw new InvalidOperationException("Metadata is missing a signing X509Certificate.");
        var certText = certNode.InnerText.Trim();
        var certClean = new StringBuilder(certText.Length);
        foreach (var ch in certText) if (!char.IsWhiteSpace(ch)) certClean.Append(ch);
        var certBase64 = certClean.ToString();

        // Validate it's actually a parseable X.509 certificate.
        try { _ = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(certBase64)); }
        catch (Exception ex) { throw new InvalidOperationException("X509Certificate is not valid base64 X.509.", ex); }

        return new ParsedIdp(entityId, ssoUrl, certBase64);
    }
}
