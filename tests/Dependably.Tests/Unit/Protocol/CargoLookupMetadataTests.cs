using Dependably.Protocol;

namespace Dependably.Tests.Unit.Protocol;

/// <summary>
/// Parsing and host-classification coverage for <see cref="CargoLookupMetadata"/>. Pure — no
/// WireMock, no DB — so the sparse-index and crates.io-API grammars are pinned independently of
/// the fetch orchestration in <see cref="PackageLookupService"/>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CargoLookupMetadataTests
{
    // ── Sparse index ─────────────────────────────────────────────────────────────

    [Fact]
    public void ParseIndex_ReadsVersionAndYankState()
    {
        var entries = CargoLookupMetadata.ParseIndex(
            """
            {"name":"proc-macro2","vers":"1.0.0","cksum":"aa","yanked":false}
            {"name":"proc-macro2","vers":"1.0.1","cksum":"bb","yanked":true}
            """);

        Assert.Equal(2, entries.Count);
        Assert.Equal("1.0.0", entries[0].Version);
        Assert.False(entries[0].Yanked);
        Assert.Equal("1.0.1", entries[1].Version);
        Assert.True(entries[1].Yanked);
    }

    [Fact]
    public void ParseIndex_SkipsBlankAndMalformedLines_KeepingTheRest()
    {
        var entries = CargoLookupMetadata.ParseIndex(
            "{\"vers\":\"1.0.0\"}\n\n   \nnot json at all\n{\"vers\":\"2.0.0\"}\n");

        Assert.Equal(["1.0.0", "2.0.0"], entries.Select(e => e.Version));
    }

    [Fact]
    public void ParseIndex_SkipsLinesWithNoUsableVersion()
    {
        var entries = CargoLookupMetadata.ParseIndex(
            """
            {"name":"x","cksum":"aa"}
            {"vers":"","cksum":"bb"}
            {"vers":123}
            {"vers":"1.0.0"}
            """);

        Assert.Equal(["1.0.0"], entries.Select(e => e.Version));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   \n  \n")]
    public void ParseIndex_EmptyDocument_YieldsNoEntries(string body)
        => Assert.Empty(CargoLookupMetadata.ParseIndex(body));

    // ── crates.io JSON API ───────────────────────────────────────────────────────

    private const string ProcMacro2Api = """
        {
          "crate": { "max_stable_version": "1.0.1" },
          "versions": [
            { "num": "1.0.1", "license": "MIT OR Apache-2.0", "created_at": "2024-03-04T05:06:07Z", "yanked": false },
            { "num": "1.0.0", "license": "Apache-2.0", "created_at": "2023-01-02T03:04:05Z", "yanked": false }
          ]
        }
        """;

    [Fact]
    public void ParseCratesIoCrate_ReadsLicenseAndPublishedAtForTheNamedVersion()
    {
        var facts = CargoLookupMetadata.ParseCratesIoCrate(ProcMacro2Api, "1.0.1");

        Assert.NotNull(facts);
        Assert.Equal(["MIT OR Apache-2.0"], facts!.Spdx);
        Assert.Equal(
            new DateTimeOffset(2024, 3, 4, 5, 6, 7, TimeSpan.Zero),
            facts.PublishedAt);
    }

    [Fact]
    public void ParseCratesIoCrate_SelectsTheRequestedVersion_NotTheFirstListed()
    {
        var facts = CargoLookupMetadata.ParseCratesIoCrate(ProcMacro2Api, "1.0.0");

        Assert.Equal(["Apache-2.0"], facts!.Spdx);
        Assert.Equal(
            new DateTimeOffset(2023, 1, 2, 3, 4, 5, TimeSpan.Zero),
            facts.PublishedAt);
    }

    [Fact]
    public void ParseCratesIoCrate_VersionAbsent_ReturnsNull()
        => Assert.Null(CargoLookupMetadata.ParseCratesIoCrate(ProcMacro2Api, "9.9.9"));

    [Theory]
    [InlineData("not json")]
    [InlineData("{}")]
    [InlineData("""{"versions":"not an array"}""")]
    public void ParseCratesIoCrate_UnusableDocument_ReturnsNull(string body)
        => Assert.Null(CargoLookupMetadata.ParseCratesIoCrate(body, "1.0.0"));

    [Theory]
    [InlineData("""{"versions":[{"num":"1.0.0","license":null}]}""")]
    [InlineData("""{"versions":[{"num":"1.0.0"}]}""")]
    public void ParseCratesIoCrate_NoLicense_YieldsFactsWithNoSpdx(string body)
    {
        var facts = CargoLookupMetadata.ParseCratesIoCrate(body, "1.0.0");

        Assert.NotNull(facts);
        Assert.Empty(facts!.Spdx);
        Assert.Null(facts.PublishedAt);
    }

    [Fact]
    public void ParseCratesIoCrate_UnparsableCreatedAt_LeavesPublishedAtNullButKeepsLicense()
    {
        var facts = CargoLookupMetadata.ParseCratesIoCrate(
            """{"versions":[{"num":"1.0.0","license":"MIT","created_at":"whenever"}]}""", "1.0.0");

        Assert.Equal(["MIT"], facts!.Spdx);
        Assert.Null(facts.PublishedAt);
    }

    // ── Host classification ──────────────────────────────────────────────────────

    [Theory]
    [InlineData("https://index.crates.io")]
    [InlineData("https://index.crates.io/")]
    [InlineData("https://INDEX.CRATES.IO/")]
    [InlineData("https://crates.io/api/v1/crates")]
    public void IsCratesIoIndexHost_AcceptsCratesIoHosts(string url)
        => Assert.True(CargoLookupMetadata.IsCratesIoIndexHost(url));

    /// <summary>
    /// The substring forms are the point: a host-shaped substring can appear in a subdomain, a
    /// path, or a query of a URL an operator controls, and treating any of them as crates.io
    /// would send the API fetch — and, but for the host-pin, a credential — somewhere else.
    /// </summary>
    [Theory]
    [InlineData("https://evil-index.crates.io.attacker.example/")]
    [InlineData("https://attacker.example/?x=index.crates.io")]
    [InlineData("https://attacker.example/index.crates.io/")]
    [InlineData("https://crates.io.attacker.example/")]
    [InlineData("https://mirror.internal/cargo")]
    [InlineData("not-a-url")]
    [InlineData("")]
    public void IsCratesIoIndexHost_RejectsLookalikesAndUnparsableUrls(string url)
        => Assert.False(CargoLookupMetadata.IsCratesIoIndexHost(url));

    [Fact]
    public void CratesIoApiUrl_TargetsTheCratesIoApiHost()
        => Assert.Equal(
            "https://crates.io/api/v1/crates/proc-macro2",
            CargoLookupMetadata.CratesIoApiUrl("proc-macro2"));
}
