using System.Security.Claims;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// The banner scheduling window is stored as canonical UTC regardless of the offset the
/// client sent. Banners are selected by a lexicographic <c>starts_at &lt;= @now</c> comparison
/// against a UTC <c>Z</c> string, so a window persisted verbatim as <c>+02:00</c> — or with no
/// offset at all — does not order against that string and the banner surfaces at the wrong
/// time, or never.
/// </summary>
[Trait("Category", "Unit")]
public sealed class BannerWindowUtcNormalizationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private static readonly DateTimeOffset KnownNow = new(2026, 4, 15, 10, 0, 0, TimeSpan.Zero);
    private string _actorId = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _actorId = Guid.NewGuid().ToString("N");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private SystemBannersController BuildController()
    {
        var http = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.NameIdentifier, _actorId),
                    new Claim("sub", _actorId),
                    new Claim("scope", "system"),
                ],
                authenticationType: "test")),
        };

        return new SystemBannersController(
            new BannerRepository(_db, TestTime.Frozen(KnownNow)),
            new AuditRepository(_db),
            new ProblemResults(new EchoLocalizer()))
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
    }

    private static BannerCreateRequest RequestWithWindow(string startsAt, string endsAt) => new(
        Severity: "info",
        Body: "Scheduled maintenance",
        LinkUrl: null,
        LinkLabel: null,
        TargetRole: "all",
        StartsAt: startsAt,
        EndsAt: endsAt,
        Enabled: true);

    [Fact]
    public async Task OffsetBearingWindowIsStoredAsUtc()
    {
        var ctrl = BuildController();

        // 2026-04-14T12:00:00+02:00 is 10:00Z; 2026-05-15T09:00:00-04:00 is 13:00Z.
        var result = await ctrl.Create(
            RequestWithWindow("2026-04-14T12:00:00+02:00", "2026-05-15T09:00:00-04:00"),
            CancellationToken.None);

        Assert.IsType<CreatedResult>(result);

        var stored = Assert.Single(await new BannerRepository(_db, TestTime.Frozen(KnownNow))
            .ListSystemAsync(CancellationToken.None));

        Assert.Equal("2026-04-14T10:00:00Z", stored.StartsAt);
        Assert.Equal("2026-05-15T13:00:00Z", stored.EndsAt);
    }

    [Fact]
    public async Task OffsetLessWindowIsStoredAsUtcNotServerLocal()
    {
        var ctrl = BuildController();

        var result = await ctrl.Create(
            RequestWithWindow("2026-04-14T12:00:00", "2026-05-15T09:00:00"),
            CancellationToken.None);

        Assert.IsType<CreatedResult>(result);

        var stored = Assert.Single(await new BannerRepository(_db, TestTime.Frozen(KnownNow))
            .ListSystemAsync(CancellationToken.None));

        Assert.Equal("2026-04-14T12:00:00Z", stored.StartsAt);
        Assert.Equal("2026-05-15T09:00:00Z", stored.EndsAt);
    }

    [Fact]
    public async Task BannerScheduledWithAnOffsetIsActiveAtTheInstantItDenotes()
    {
        var ctrl = BuildController();

        // Starts 2026-04-15T09:00:00Z — an hour before KnownNow — but written as +02:00, whose
        // wall-clock text ("11:00") sorts *after* the 10:00Z cutoff. Persisted verbatim the
        // banner would not yet be active; normalized it is.
        var result = await ctrl.Create(
            RequestWithWindow("2026-04-15T11:00:00+02:00", "2026-05-15T00:00:00Z"),
            CancellationToken.None);

        Assert.IsType<CreatedResult>(result);

        var active = await new BannerRepository(_db, TestTime.Frozen(KnownNow))
            .GetActiveAsync(orgId: "any-org", userId: _actorId, role: "admin", CancellationToken.None);

        Assert.Single(active);
    }

    [Fact]
    public async Task WindowOrderingIsValidatedByInstantNotWallClockText()
    {
        var ctrl = BuildController();

        // Ends 12:00Z, starts 13:00Z — inverted as instants, though the raw text reads
        // "09:00" before "13:00".
        var result = await ctrl.Create(
            RequestWithWindow("2026-04-16T13:00:00Z", "2026-04-16T09:00:00-03:00"),
            CancellationToken.None);

        Assert.IsNotType<CreatedResult>(result);
    }

    private sealed class EchoLocalizer : IStringLocalizer<SharedResource>
    {
        public LocalizedString this[string name] => new(name, name, resourceNotFound: false);
        public LocalizedString this[string name, params object[] arguments]
            => new(name, string.Format(System.Globalization.CultureInfo.InvariantCulture, name, arguments), resourceNotFound: false);
        public IEnumerable<LocalizedString> GetAllStrings(bool includeParentCultures) => [];
    }
}
