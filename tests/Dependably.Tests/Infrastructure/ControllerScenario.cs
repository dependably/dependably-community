using System.Globalization;
using System.Security.Claims;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Mail;
using Dependably.Protocol;
using Dependably.Resources;
using Dependably.Security;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Dependably.Tests.Infrastructure;

/// <summary>
/// Builder that owns an <see cref="InMemoryDbFixture"/> and exposes fluent <c>WithX</c>
/// calls to seed prerequisite rows. <see cref="BuildAsync"/> returns a
/// <see cref="ControllerScenarioResult"/> with controllers pre-wired against the seeded
/// state. After <c>BuildAsync</c> the scenario is immutable — any further <c>WithX</c>
/// call throws.
///
/// Builder discipline (enforced):
/// <list type="bullet">
///   <item>Purely additive — <c>WithX</c> only inserts; never mutates existing rows.</item>
///   <item>Explicit relationships — <c>WithUser(org: "acme")</c> requires the org to exist.
///         No silent fix-up.</item>
///   <item>Calling order determines insert order; nothing else is implicit.</item>
/// </list>
/// </summary>
public sealed class ControllerScenario : IAsyncDisposable
{
    /// <summary>
    /// Frozen scenario clock injected into every constructed repository, service, and
    /// controller. Tests read it for "now"-relative assertions and advance it to cross
    /// time windows deterministically.
    /// </summary>
    public Microsoft.Extensions.Time.Testing.FakeTimeProvider Clock { get; } = TestTime.Frozen();

    private readonly InMemoryDbFixture _fixture = new();
    private readonly Dictionary<string, string> _orgIdsBySlug = new();
    private readonly Dictionary<string, string> _userIdsByEmail = new();

    private readonly Dictionary<(string Org, string Eco, string Name), string> _packageIds = new();
    private readonly Dictionary<(string Org, string Eco, string Name, string Version), string> _versionIds = new();

    private string? _primaryOrgSlug;
    private string? _actorUserId;
    private string _actorRole = "owner";
    private bool _actorIsAnonymous;
    private string? _actorOrgOverride;
    private bool _built;

    private ControllerScenario() { }

    /// <summary>
    /// Direct handle on the in-memory metadata store backing this scenario. Tests should
    /// normally go through the typed seeders; this exists for assertions and for the rare
    /// case where a test needs to seed something the builders don't yet expose.
    /// </summary>
    public IMetadataStore Store => _fixture.Store;

    /// <summary>
    /// Async factory — schema is initialized once here so subsequent WithX calls can insert.
    /// Tests use <c>await ControllerScenario.CreateAsync()</c> as the entry point.
    /// </summary>
    public static async Task<ControllerScenario> CreateAsync()
    {
        var scenario = new ControllerScenario();
        await scenario._fixture.InitializeAsync();
        return scenario;
    }

    private void EnsureNotBuilt()
    {
        if (_built)
        {
            throw new InvalidOperationException(
            "ControllerScenario is immutable after BuildAsync. Add seeding before BuildAsync.");
        }
    }

    /// <summary>Inserts a tenant. The first call sets the "primary" org the controller's TenantContext binds to.</summary>
    public async Task<ControllerScenario> WithOrgAsync(string slug = "acme")
    {
        EnsureNotBuilt();
        string id = await OrgSeeder.InsertAsync(_fixture.Store, slug);
        _orgIdsBySlug[slug] = id;
        _primaryOrgSlug ??= slug;
        return this;
    }

    /// <summary>Inserts a user in <paramref name="org"/>. The org must already be present
    /// (use <see cref="WithOrgAsync"/>). The first user inserted becomes the
    /// authenticated principal unless <see cref="WithNoUser"/> is called.</summary>
    public async Task<ControllerScenario> WithUserAsync(
        string email = "owner@acme.test",
        string role = "owner",
        string org = "acme",
        string accountStatus = "active")
    {
        EnsureNotBuilt();
        if (!_orgIdsBySlug.TryGetValue(org, out string? orgId))
        {
            throw new InvalidOperationException(
                $"WithUserAsync references org '{org}' that hasn't been added. Call WithOrgAsync(\"{org}\") first.");
        }

        string id = await UserSeeder.InsertAsync(_fixture.Store, orgId, email, role, accountStatus: accountStatus);
        _userIdsByEmail[email] = id;
        _actorUserId ??= id;
        if (_actorUserId == id)
        {
            _actorRole = role;
        }

        return this;
    }

    /// <summary>Sets the license enforcement mode for <paramref name="org"/>. Org must exist.</summary>
    public async Task<ControllerScenario> WithLicensePolicyAsync(string mode, string org = "acme")
    {
        EnsureNotBuilt();
        if (!_orgIdsBySlug.TryGetValue(org, out string? orgId))
        {
            throw new InvalidOperationException(
                $"WithLicensePolicyAsync references org '{org}' that hasn't been added. Call WithOrgAsync(\"{org}\") first.");
        }

        await LicensePolicySeeder.SetModeAsync(_fixture.Store, orgId, mode);
        return this;
    }

    /// <summary>
    /// Inserts a package row in <paramref name="org"/>. Org must exist. Use
    /// <see cref="WithPackageVersionAsync"/> to attach a version.
    /// </summary>
    public async Task<ControllerScenario> WithPackageAsync(
        string name, string ecosystem = "npm", string org = "acme", bool isProxy = false)
    {
        EnsureNotBuilt();
        if (!_orgIdsBySlug.TryGetValue(org, out string? orgId))
        {
            throw new InvalidOperationException(
                $"WithPackageAsync references org '{org}' that hasn't been added. Call WithOrgAsync(\"{org}\") first.");
        }

        string id = await PackageSeeder.InsertAsync(_fixture.Store, orgId, ecosystem, name, isProxy);
        _packageIds[(org, ecosystem, name)] = id;
        return this;
    }

    /// <summary>
    /// Inserts a version on a previously-seeded package. Package must exist (call
    /// <see cref="WithPackageAsync"/> first). The version's purl is generated unique
    /// to avoid the global UNIQUE(purl) constraint colliding across tests.
    /// </summary>
    public async Task<ControllerScenario> WithPackageVersionAsync(
        string name, string version, string ecosystem = "npm", string org = "acme", string origin = "uploaded")
    {
        EnsureNotBuilt();
        if (!_packageIds.TryGetValue((org, ecosystem, name), out string? pkgId))
        {
            throw new InvalidOperationException(
                $"WithPackageVersionAsync references package '{ecosystem}/{name}' in org '{org}' that hasn't been added. " +
                $"Call WithPackageAsync first.");
        }

        string purl = $"pkg:{ecosystem}/{Guid.NewGuid():N}/{name}@{version}";
        string verId = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId, version, purl, origin: origin, blobKey: $"blob/{Guid.NewGuid():N}");
        _versionIds[(org, ecosystem, name, version)] = verId;
        return this;
    }

    /// <summary>Adds an SPDX entry to the org's license allowlist. Org must exist.</summary>
    public async Task<ControllerScenario> WithLicenseAllowlistEntryAsync(string spdx, string org = "acme")
    {
        EnsureNotBuilt();
        if (!_orgIdsBySlug.TryGetValue(org, out string? orgId))
        {
            throw new InvalidOperationException(
                $"Org '{org}' not seeded. Call WithOrgAsync first.");
        }

        await LicensePolicySeeder.AddAllowlistEntryAsync(_fixture.Store, orgId, spdx);
        return this;
    }

    /// <summary>Adds an SPDX entry to the org's license blocklist. Org must exist.</summary>
    public async Task<ControllerScenario> WithLicenseBlocklistEntryAsync(string spdx, string org = "acme")
    {
        EnsureNotBuilt();
        if (!_orgIdsBySlug.TryGetValue(org, out string? orgId))
        {
            throw new InvalidOperationException(
                $"Org '{org}' not seeded. Call WithOrgAsync first.");
        }

        await LicensePolicySeeder.AddBlocklistEntryAsync(_fixture.Store, orgId, spdx);
        return this;
    }

    // ── Negative scenario helpers ────────────────────────────────────────────

    /// <summary>The HTTP request is unauthenticated (anonymous principal). Use to exercise auth-deny paths.</summary>
    public ControllerScenario WithNoUser()
    {
        EnsureNotBuilt();
        _actorIsAnonymous = true;
        return this;
    }

    /// <summary>
    /// The caller is a valid user but in a *different* tenant than the primary org. Exercises
    /// the BOLA / cross-tenant rejection path: the JWT identifies them legitimately, but the
    /// route's TenantContext doesn't match their tenant_id. Org and user are both seeded.
    /// </summary>
    public async Task<ControllerScenario> WithUserInDifferentOrgAsync(
        string email = "outsider@other.test", string role = "owner", string otherOrgSlug = "other")
    {
        EnsureNotBuilt();
        if (_primaryOrgSlug is null)
        {
            throw new InvalidOperationException(
                "Call WithOrgAsync(...) first to establish the primary org before WithUserInDifferentOrgAsync.");
        }

        string otherOrgId = await OrgSeeder.InsertAsync(_fixture.Store, otherOrgSlug);
        _orgIdsBySlug[otherOrgSlug] = otherOrgId;
        string userId = await UserSeeder.InsertAsync(_fixture.Store, otherOrgId, email, role);
        _userIdsByEmail[email] = userId;
        _actorUserId = userId;
        _actorRole = role;
        _actorOrgOverride = otherOrgId;
        return this;
    }

    /// <summary>
    /// Marker that documents the test depends on the *absence* of a license policy entry.
    /// Currently a no-op (org_settings defaults `license_enforcement_mode` to "off"), but
    /// explicit calls keep test intent legible.
    /// </summary>
    public ControllerScenario WithMissingLicensePolicy() => this;

    // ── Build ────────────────────────────────────────────────────────────────

    public async Task<ControllerScenarioResult> BuildAsync(IInviteMailer? mailer = null)
    {
        EnsureNotBuilt();

        if (_primaryOrgSlug is null)
        {
            throw new InvalidOperationException("A scenario must include at least one WithOrgAsync(...) call.");
        }

        string primaryOrgId = _orgIdsBySlug[_primaryOrgSlug];

        var http = new DefaultHttpContext();
        // Default a sensible host so RequestPublicUrlBuilder.BaseUrl doesn't produce
        // malformed URLs like "http://" when downstream code parses them via new Uri(...).
        http.Request.Scheme = "https";
        http.Request.Host = new HostString($"{_primaryOrgSlug}.example.test");
        http.Items[TenantContext.HttpItemsKey] = TenantContext.ForTenant(primaryOrgId, _primaryOrgSlug);
        if (!_actorIsAnonymous && _actorUserId is not null)
        {
            string orgIdForClaim = _actorOrgOverride ?? primaryOrgId;
            http.User = new ClaimsPrincipal(new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.NameIdentifier, _actorUserId),
                    new Claim("sub", _actorUserId),
                    new Claim("org_id", orgIdForClaim),
                    new Claim("tid", orgIdForClaim),
                    new Claim("role", _actorRole),
                    new Claim("scope", "tenant"),
                ],
                authenticationType: "test"));
        }

        var ctx = new ControllerContext { HttpContext = http };

        var db = _fixture.Store;
        var orgs = new OrgRepository(db);
        var audit = new AuditRepository(db);
        var guard = new OrgAccessGuard(db);
        var licenses = new LicenseRepository(db, Clock);
        var packages = new PackageRepository(db);
        var vulns = new VulnerabilityRepository(db, Clock);
        var problems = new ProblemResults(new EchoLocalizer());

        // Real VulnerabilityScanService over a no-op IOsvSource — the SUT is the controller,
        // not the scanner. Returning zero advisories keeps the rescan path deterministic.
        var osv = Substitute.For<IOsvSource>();
        osv.QueryAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
           .Returns(Task.FromResult(new List<OsvAdvisory>()));
        var noAirGap = Substitute.For<IAirGapMode>();
        noAirGap.IsEnabled.Returns(false);
        noAirGap.DisabledJobs.Returns(new System.Collections.Generic.HashSet<string>());
        noAirGap.IsJobDisabled(Arg.Any<string>()).Returns(false);
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            db, osv, vulns, audit,
            new ConfigurationBuilder().Build(),
            noAirGap,
            NullLogger<VulnerabilityScanService>.Instance,
            Clock));

        var systemAdmins = new SystemAdminRepository(db);
        var tokens = new TokenRepository(db, Clock);
        var invites = new InviteRepository(db, Clock);
        var allowlist = new AllowlistRepository(db, Clock);
        var blocklist = new BlocklistRepository(db, new Microsoft.Extensions.Caching.Memory.MemoryCache(
            new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()), Clock);
        var reservedNamespaces = new ReservedNamespaceService(db, new Microsoft.Extensions.Caching.Memory.MemoryCache(
            new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()), Clock);
        var installScriptAllowlist = new InstallScriptAllowlistService(db, new Microsoft.Extensions.Caching.Memory.MemoryCache(
            new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()), Clock);
        var samlConfig = new SamlConfigRepository(db, Clock);
        var blobs = new Dependably.Storage.InMemoryBlobStore();
        var publicUrl = new RequestPublicUrlBuilder(new ConfigurationBuilder().Build());
        var orgAuditEmitter = Substitute.For<Dependably.Infrastructure.Audit.IAuditEmitter>();

        var license = new LicenseController(licenses, orgs, guard, problems, audit) { ControllerContext = ctx };
        var jobRuns = new BackgroundJobRunRepository(db);
        var instance = new InstanceController(orgs, audit, guard, noAirGap, jobRuns,
            new ConfigurationBuilder().Build())
        { ControllerContext = ctx };
        var vuln = new VulnerabilityController(new VulnerabilityControllerDependencies(
            vulns, packages, scanner, audit,
            new QuarantineRepository(db, Clock), guard,
            NullLogger<VulnerabilityController>.Instance, Clock))
        { ControllerContext = ctx };
        var system = new SystemController(orgs, systemAdmins, db, audit, problems,
            new ConfigurationBuilder().Build(),
            new Dependably.Security.PasswordPolicy(), Clock)
        { ControllerContext = ctx };

        var packageAnalytics = new PackageAnalyticsRepository(db);
        var statsSnapshots = new StatsSnapshotRepository(db);
        var scenarioCache = new Microsoft.Extensions.Caching.Memory.MemoryCache(new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions());
        var orgSvc = new OrgControllerServices(
            Orgs: orgs, Packages: packages, PackageAnalytics: packageAnalytics,
            StatsSnapshots: statsSnapshots,
            Tokens: tokens, Invites: invites,
            Allowlist: allowlist, Blocklist: blocklist, Audit: audit, Guard: guard,
            Blobs: blobs, BlobStorage: new Dependably.Storage.TieredBlobStorage(blobs, blobs),
            Config: new ConfigurationBuilder().Build(),
            Logger: NullLogger<OrgController>.Instance, Problems: problems,
            Licenses: licenses, Vulns: vulns, Urls: publicUrl,
            AuditEmitter: orgAuditEmitter,
            Cache: scenarioCache,
            RpmMergedCache: new Dependably.Infrastructure.Caching.MetadataResponseCache<Dependably.Infrastructure.Caching.RpmMergedRepodataKey, Dependably.Infrastructure.Caching.MergedRepodataCache>(
                scenarioCache, Dependably.Infrastructure.Caching.MetadataCacheKeys.RpmMergedRepodata),
            RpmLocalCache: new Dependably.Infrastructure.Caching.RenderedResponseCache<Dependably.Infrastructure.Caching.RpmLocalRepodataKey>(
                scenarioCache, Dependably.Infrastructure.Caching.MetadataCacheKeys.RpmLocalRepodata),
            CacheArtifacts: new Dependably.Infrastructure.CacheArtifactRepository(db),
            TenantAccess: new Dependably.Infrastructure.TenantArtifactAccessRepository(db),
            Time: Clock);
        var org = new OrgController(orgSvc) { ControllerContext = ctx };
        var orgSettingsRepo = new OrgSettingsRepository(db);
        var orgSettings = new OrgSettingsController(
            orgSettingsRepo, guard, audit, orgAuditEmitter,
            new ConfigurationBuilder().Build(), problems,
            new AirGapMode(new ConfigurationBuilder().Build()),
            new RequireMfaMode(new ConfigurationBuilder().Build()),
            new Dependably.Protocol.Provenance.NpmSignatureKeyStore(
                new ConfigurationBuilder().Build(),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<Dependably.Protocol.Provenance.NpmSignatureKeyStore>.Instance),
            new Dependably.Protocol.Provenance.NuGetSignatureTrustStore(
                new ConfigurationBuilder().Build(),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<Dependably.Protocol.Provenance.NuGetSignatureTrustStore>.Instance),
            new Dependably.Protocol.Provenance.PyPiSigstoreTrustStore(
                new ConfigurationBuilder().Build(),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<Dependably.Protocol.Provenance.PyPiSigstoreTrustStore>.Instance),
            new Dependably.Protocol.Provenance.RpmProvenanceVerifier(
                new ConfigurationBuilder().Build(),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<Dependably.Protocol.Provenance.RpmProvenanceVerifier>.Instance),
            new Dependably.Protocol.Provenance.MavenSignatureKeyStore(
                new ConfigurationBuilder().Build(),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<Dependably.Protocol.Provenance.MavenSignatureKeyStore>.Instance))
        { ControllerContext = ctx };
        var orgTokens = new OrgTokensController(
            tokens, orgs, guard, audit, orgAuditEmitter, problems)
        { ControllerContext = ctx };
        var orgInvites = new OrgInvitesController(
            invites, orgs, guard, audit, new ConfigurationBuilder().Build(),
            NullLogger<OrgInvitesController>.Instance, publicUrl, problems,
            mailer: mailer)
        { ControllerContext = ctx };
        var orgUsers = new OrgUsersController(
            orgs, guard, audit, problems)
        { ControllerContext = ctx };
        var orgLists = new OrgListsController(
            allowlist, blocklist, reservedNamespaces, installScriptAllowlist, guard, audit, problems)
        { ControllerContext = ctx };
        var orgAudit = new OrgAuditController(audit, guard, Clock) { ControllerContext = ctx };
        var orgAuthConfig = new OrgAuthConfigController(
            guard, samlConfig, audit, publicUrl, problems, Clock)
        { ControllerContext = ctx };

        var claimRepo = new ClaimRepository(db);
        var airGap = Substitute.For<IAirGapMode>();
        airGap.IsEnabled.Returns(false);
        var claimResolver = new ClaimResolver(claimRepo, airGap);
        var claimSvc = new ClaimsControllerServices(
            Guard: guard, Claims: claimRepo, Resolver: claimResolver, Audit: audit,
            AuditEmitter: orgAuditEmitter, Packages: packages, Blobs: blobs,
            Logger: NullLogger<ClaimsController>.Instance, Time: Clock);
        var claims = new ClaimsController(claimSvc) { ControllerContext = ctx };

        var siem = new SiemController(audit, vulns, orgs, tokens,
            new ConfigurationBuilder().Build(), Clock)
        { ControllerContext = ctx };

        // ImportController: the heavy publish pipeline (IPackagePublishService) gets mocked
        // so tests focus on auth + form-validation branches, not the storage tail.
        PublishService = Substitute.For<Dependably.Infrastructure.Publish.IPackagePublishService>();
        PublishService.StoreAndRecordAsync(Arg.Any<Dependably.Infrastructure.Publish.PublishRequest>(), Arg.Any<CancellationToken>())
            .Returns(call => new Dependably.Infrastructure.Publish.PublishResult.Accepted(
                "ver-" + Guid.NewGuid().ToString("N"),
                call.Arg<Dependably.Infrastructure.Publish.PublishRequest>().Purl,
                "sha-stub"));
        PublishService.ValidateAsync(Arg.Any<Dependably.Infrastructure.Publish.PublishRequest>(), Arg.Any<CancellationToken>())
            .Returns(call => new Dependably.Infrastructure.Publish.PublishResult.Accepted(
                "", call.Arg<Dependably.Infrastructure.Publish.PublishRequest>().Purl, "sha-stub"));
        var publishGate = new Dependably.Security.PublishGate(new ConfigurationBuilder().Build(), claimResolver);
        var uploadLimitResolver = new Dependably.Protocol.UploadLimitResolver(orgs, new ConfigurationBuilder().Build());
        var importSvc = new ImportControllerServices(
            Guard: guard, PublishGate: publishGate, Orgs: orgs,
            Publish: PublishService, ClaimResolver: claimResolver,
            Licenses: licenses, LimitResolver: uploadLimitResolver,
            StagingPath: Path.GetTempPath(),
            Cache: new Microsoft.Extensions.Caching.Memory.MemoryCache(new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()));
        var import = new ImportController(importSvc) { ControllerContext = ctx };

        _built = true;
        return new ControllerScenarioResult(
            _fixture,
            primaryOrgId,
            _actorUserId,
            license,
            instance,
            vuln,
            system,
            org,
            orgSettings,
            orgTokens,
            orgInvites,
            orgUsers,
            orgLists,
            orgAudit,
            orgAuthConfig,
            claims,
            siem,
            import);
    }

    /// <summary>NSubstitute mock for the publish pipeline. Override return values on a test to exercise rejection paths.</summary>
    public Dependably.Infrastructure.Publish.IPackagePublishService? PublishService { get; private set; }

    public async ValueTask DisposeAsync() => await _fixture.DisposeAsync();

    private sealed class EchoLocalizer : IStringLocalizer<SharedResource>
    {
        public LocalizedString this[string name] => new(name, name, resourceNotFound: false);
        public LocalizedString this[string name, params object[] arguments]
            => new(name, string.Format(CultureInfo.InvariantCulture, name, arguments), resourceNotFound: false);
        public IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures) => [];
    }
}


/// <summary>
/// Immutable result of <see cref="ControllerScenario.BuildAsync"/>. Holds the controllers
/// pre-wired against the seeded DB + HttpContext. Disposing the result tears down the
/// underlying in-memory database.
/// </summary>
public sealed record ControllerScenarioResult(
    InMemoryDbFixture Fixture,
    string PrimaryOrgId,
    string? ActorUserId,
    LicenseController LicenseController,
    InstanceController InstanceController,
    VulnerabilityController VulnerabilityController,
    SystemController SystemController,
    OrgController OrgController,
    OrgSettingsController OrgSettingsController,
    OrgTokensController OrgTokensController,
    OrgInvitesController OrgInvitesController,
    OrgUsersController OrgUsersController,
    OrgListsController OrgListsController,
    OrgAuditController OrgAuditController,
    OrgAuthConfigController OrgAuthConfigController,
    ClaimsController ClaimsController,
    SiemController SiemController,
    ImportController ImportController) : IAsyncDisposable
{
    public IMetadataStore Db => Fixture.Store;

    public async ValueTask DisposeAsync() => await Fixture.DisposeAsync();
}

