using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit;

/// <summary>
/// Chaining the Terraform mirror through another mirror — the edge-node topology, where the master
/// serves the network mirror protocol while the fetcher's own default is the registry protocol.
///
/// The archive-URL containment check carries the weight here. On the registry protocol an archive
/// legitimately lives on a third-party host, so the fetch path follows whatever URL it is handed;
/// a mirror serves its own archives, so the same latitude there would let an upstream mirror steer
/// a server-side fetch at a host of its choosing. These tests pin the containment rule, including
/// the prefix-lookalike case that a naive string comparison lets through.
/// </summary>
[Trait("Category", "Unit")]
public sealed class TerraformMirrorChainingTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public TerraformMirrorChainingTests(InMemoryDbFixture fixture) => _fixture = fixture;

    // ── Archive-URL containment (the SSRF guard) ─────────────────────────────

    [Theory]
    // Relative resolution lands beneath the base — the normal case.
    [InlineData("https://master.example/terraform/registry.terraform.io/hashicorp/random/3.9.0/linux_amd64.zip", true)]
    // Nested deeper is still beneath.
    [InlineData("https://master.example/terraform/a/b/c/d/e.zip", true)]
    public void ArchiveUrlBeneathBase_IsAccepted(string candidate, bool expected) =>
        Assert.Equal(expected, TerraformController.IsBeneathBase(
            new Uri(candidate), "https://master.example/terraform"));

    [Theory]
    // A different host entirely — the case the guard exists for.
    [InlineData("https://evil.example/terraform/x/y/z/1.0.0/linux_amd64.zip")]
    // Same host, but a sibling path that merely shares the base's prefix as a string. A
    // StartsWith on the raw base would accept this; comparing path segments does not.
    [InlineData("https://master.example/terraform-evil/x/y/z/1.0.0/linux_amd64.zip")]
    // Same host and path root, wrong scheme — a downgrade to plaintext.
    [InlineData("http://master.example/terraform/x/y/z/1.0.0/linux_amd64.zip")]
    // Same host and scheme, different port — a different service.
    [InlineData("https://master.example:8443/terraform/x/y/z/1.0.0/linux_amd64.zip")]
    // The base itself is not "beneath" the base: there is no archive at the bare prefix.
    [InlineData("https://master.example/terraform")]
    // Escaping upward out of the configured prefix.
    [InlineData("https://master.example/other/1.0.0/linux_amd64.zip")]
    public void ArchiveUrlOutsideBase_IsRefused(string candidate) =>
        Assert.False(TerraformController.IsBeneathBase(
            new Uri(candidate), "https://master.example/terraform"));

    [Fact]
    public void ContainmentIsUnaffectedByATrailingSlashOnTheBase() =>
        Assert.True(TerraformController.IsBeneathBase(
            new Uri("https://master.example/terraform/h/n/t/1.0.0/linux_amd64.zip"),
            "https://master.example/terraform/"));

    [Fact]
    public void ARootBasePermitsAnyPathOnTheSameOrigin()
    {
        // A master mounted at the origin root has an empty base path; containment then reduces to
        // scheme/host/port, which must still hold.
        Assert.True(TerraformController.IsBeneathBase(
            new Uri("https://master.example/anything.zip"), "https://master.example"));
        Assert.False(TerraformController.IsBeneathBase(
            new Uri("https://elsewhere.example/anything.zip"), "https://master.example"));
    }

    // ── Mirror hash selection ────────────────────────────────────────────────

    private static readonly string Sha = new('a', 64);

    [Fact]
    public void ZipHashIsTakenFromTheZhEntry() =>
        Assert.Equal(Sha, TerraformController.ExtractZipHash([$"zh:{Sha}"]));

    [Fact]
    public void DirHashIsNotUsableAsAFetchChecksum()
    {
        // h1: is a dirhash over the extracted contents, not a digest of the archive, so the fetch
        // path cannot verify against it. Selecting it would produce a guaranteed checksum failure.
        Assert.Null(TerraformController.ExtractZipHash([$"h1:{Sha}"]));
        Assert.Equal(Sha, TerraformController.ExtractZipHash([$"h1:{Sha}", $"zh:{Sha}"]));
    }

    [Fact]
    public void AMalformedOrEmptyZipHashIsTreatedAsAbsent()
    {
        // A zh: entry that is not a well-formed SHA-256 must not be fed to the verifier: a bare
        // "zh:" would silently downgrade to trust-on-first-use, and a short or non-hex value would
        // fail closed as an opaque checksum error. Either way "published a hash" and "published a
        // usable hash" must not be indistinguishable, so the unusable form is dropped.
        Assert.Null(TerraformController.ExtractZipHash(["zh:"]));
        Assert.Null(TerraformController.ExtractZipHash(["zh:abc123"]));
        Assert.Null(TerraformController.ExtractZipHash([$"zh:{new string('a', 63)}"]));
        Assert.Null(TerraformController.ExtractZipHash([$"zh:{new string('z', 64)}"]));
    }

    [Fact]
    public void AbsentHashesAreNotAFailure()
    {
        // A mirror that publishes no hashes leaves the fetch unverified rather than failing it —
        // trust-on-first-use, with the archive hashed and recorded on ingest as an observed fact.
        //
        // This is no longer the case against a chained Dependably master: a master publishes the
        // zh: hash for every archive it holds, so an edge chained to one does verify. The
        // pass-through here covers a third-party mirror that publishes nothing, and refusing that
        // outright would refuse a legitimate topology on a signal that was never mandatory. See
        // docs/adr/0003-terraform-provider-network-mirror.md for the recorded posture.
        Assert.Null(TerraformController.ExtractZipHash(null));
        Assert.Null(TerraformController.ExtractZipHash([]));
    }

    // ── The seeded edge row ──────────────────────────────────────────────────

    [Fact]
    public void EdgeSeedsTerraformAgainstTheMasterMirrorSurface()
    {
        var rows = EdgeUpstreamSeeder.ResolveRows("https://master.example.com");
        var terraform = rows.Single(r => r.Ecosystem == "terraform");

        Assert.Equal("https://master.example.com/terraform", terraform.Url);
        Assert.Equal(UpstreamRegistryRepository.MirrorProtocol, terraform.Protocol);
    }

    [Fact]
    public void NoOtherEdgeEcosystemDeclaresAProtocol()
    {
        // Every other ecosystem serves the protocol it fetches, so naming one would be noise that
        // could later be read as meaningful. Terraform is deliberately the only exception.
        var others = EdgeUpstreamSeeder.ResolveRows("https://master.example.com")
            .Where(r => r.Ecosystem != "terraform")
            .ToList();

        Assert.NotEmpty(others);
        Assert.All(others, r => Assert.Null(r.Protocol));
    }

    [Fact]
    public async Task SeededProtocolSurvivesToTheResolvedUpstreamSource()
    {
        // The column is only useful if it reaches the fetcher, so this asserts the whole path:
        // seeder INSERT -> upstream_registry -> the UpstreamSource the controller resolves.
        string org = await OrgSeeder.InsertAsync(_fixture.Store, $"edge-tf-{Guid.NewGuid():N}");
        // One envelope across seed and read: each Configured() mints a fresh key, so two instances
        // cannot decrypt one another's secret.
        var envelope = TestEnvelope.Configured();
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await EdgeUpstreamSeeder.SeedForEdgeAsync(
                conn, org, "https://master.example.com", "edge-tok", envelope);
        }

        var repo = new UpstreamRegistryRepository(_fixture.Store, TimeProvider.System, envelope);

        var terraform = await repo.ListSourcesForEcosystemAsync(org, "terraform");
        var single = Assert.Single(terraform);
        Assert.Equal("https://master.example.com/terraform", single.Url);
        Assert.Equal(UpstreamRegistryRepository.MirrorProtocol, single.Protocol);

        // The adversarial twin: a sibling ecosystem must come back with no protocol, so a NULL
        // column cannot be read as "mirror" by a mapping that quietly defaults.
        var npm = await repo.ListSourcesForEcosystemAsync(org, "npm");
        Assert.Null(Assert.Single(npm).Protocol);
    }

    // ── Write-path validation ────────────────────────────────────────────────

    [Fact]
    public void OnlyKnownProtocolsAreAccepted()
    {
        // Fresh installs also carry a CHECK, but SQLite cannot add one via ALTER, so on an upgraded
        // database this predicate is the only thing holding the value set.
        Assert.True(UpstreamRegistryRepository.IsSupportedProtocol(null));
        Assert.True(UpstreamRegistryRepository.IsSupportedProtocol("mirror"));
        Assert.False(UpstreamRegistryRepository.IsSupportedProtocol("registry"));
        Assert.False(UpstreamRegistryRepository.IsSupportedProtocol("Mirror"));
        Assert.False(UpstreamRegistryRepository.IsSupportedProtocol(""));
    }

    /// <summary>
    /// AddAsync is the write path IsSupportedProtocol guards — the guard the doc comment claims
    /// exists must actually reject a bad value rather than silently persisting it.
    /// </summary>
    [Fact]
    public async Task Add_UnsupportedProtocol_ThrowsAndPersistsNothing()
    {
        string org = await OrgSeeder.InsertAsync(_fixture.Store, $"tf-bad-{Guid.NewGuid():N}");
        var repo = new UpstreamRegistryRepository(_fixture.Store, TimeProvider.System, TestEnvelope.Configured());

        await Assert.ThrowsAsync<ArgumentException>(() => repo.AddAsync(
            org, new NewUpstreamRegistry("terraform", "https://mirror.example/terraform", Protocol: "registry")));

        Assert.Empty(await repo.ListSourcesForEcosystemAsync(org, "terraform"));
    }

    /// <summary>
    /// A supported 'mirror' value round-trips through the write path (AddAsync) and both read
    /// paths (ListAsync — the API-facing projection — and ListSourcesForEcosystemAsync — the
    /// resolver bridge), confirming the column is neither dropped on write nor omitted on either
    /// read.
    /// </summary>
    [Fact]
    public async Task Add_MirrorProtocol_RoundTripsThroughBothReadPaths()
    {
        string org = await OrgSeeder.InsertAsync(_fixture.Store, $"tf-ok-{Guid.NewGuid():N}");
        var repo = new UpstreamRegistryRepository(_fixture.Store, TimeProvider.System, TestEnvelope.Configured());

        var entry = await repo.AddAsync(
            org, new NewUpstreamRegistry("terraform", "https://mirror.example/terraform", Protocol: "mirror"));
        Assert.Equal("mirror", entry.Protocol);

        var listed = await repo.ListAsync(org);
        Assert.Equal("mirror", Assert.Single(listed).Protocol);

        var sources = await repo.ListSourcesForEcosystemAsync(org, "terraform");
        Assert.Equal("mirror", Assert.Single(sources).Protocol);
    }

    /// <summary>
    /// Mixed partial-failure: adding a valid terraform mirror row for one org and rejecting an
    /// unsupported value for another must not cross-contaminate — the valid write survives and the
    /// rejected one leaves no row anywhere.
    /// </summary>
    [Fact]
    public async Task Add_MixedValidAndInvalidProtocol_ValidSurvivesInvalidLeavesNoRow()
    {
        string orgOk = await OrgSeeder.InsertAsync(_fixture.Store, $"tf-mix-ok-{Guid.NewGuid():N}");
        string orgBad = await OrgSeeder.InsertAsync(_fixture.Store, $"tf-mix-bad-{Guid.NewGuid():N}");
        var repo = new UpstreamRegistryRepository(_fixture.Store, TimeProvider.System, TestEnvelope.Configured());

        await repo.AddAsync(
            orgOk, new NewUpstreamRegistry("terraform", "https://mirror.example/terraform", Protocol: "mirror"));
        await Assert.ThrowsAsync<ArgumentException>(() => repo.AddAsync(
            orgBad, new NewUpstreamRegistry("terraform", "https://mirror.example/terraform", Protocol: "bogus")));

        Assert.Equal("mirror", Assert.Single(await repo.ListAsync(orgOk)).Protocol);
        Assert.Empty(await repo.ListAsync(orgBad));
    }
}
