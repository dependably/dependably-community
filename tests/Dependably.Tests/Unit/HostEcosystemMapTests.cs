using Dependably.Infrastructure;
using Microsoft.Extensions.Configuration;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class HostEcosystemMapTests
{
    private static HostEcosystemMap Build(string? hostRouting)
    {
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["HOST_ROUTING"] = hostRouting })
            .Build();
        return new HostEcosystemMap(cfg);
    }

    [Fact]
    public void NoConfig_IsEmpty_ReturnsNullPrefix()
    {
        var m = Build(null);
        Assert.True(m.IsEmpty);
        Assert.Null(m.PrefixForHost("registry.npmjs.org", "/lodash"));
    }

    [Fact]
    public void Mapped_ReturnsEcosystemPrefix()
    {
        var m = Build("registry.npmjs.org=npm,pypi.org=pypi,api.nuget.org=nuget");
        Assert.Equal("/npm", m.PrefixForHost("registry.npmjs.org", "/lodash"));
        Assert.Equal("/nuget", m.PrefixForHost("api.nuget.org", "/v3/index.json"));
    }

    [Fact]
    public void Mapped_PyPiSimpleAndPackagesPaths_ResolveToEmptyPrefix()
    {
        // PyPI's protocol surface (/simple/, /packages/) is already unprefixed, so mapping
        // pypi.org to "/pypi" would rewrite those real requests onto routes that don't exist.
        var m = Build("pypi.org=pypi");
        Assert.Equal(string.Empty, m.PrefixForHost("pypi.org", "/simple/lodash/"));
        Assert.Equal(string.Empty, m.PrefixForHost("pypi.org", "/packages/lodash-1.0.0.tgz"));
    }

    [Fact]
    public void Mapped_PyPiUploadPath_ResolvesToPypiPrefix()
    {
        // twine's stock upload endpoint is bare-host "/legacy/" (upload.pypi.org/legacy/), with
        // no "/pypi" segment. Only "/pypi/legacy/" is a routed endpoint (PyPiController.Upload),
        // so this path must get the prefix prepended rather than falling into the blanket-empty
        // treatment that /simple and /packages get.
        var m = Build("upload.pypi.org=pypi");
        Assert.Equal("/pypi", m.PrefixForHost("upload.pypi.org", "/legacy/"));
    }

    [Fact]
    public void Mapped_PyPiJsonApiPath_AlreadyCarriesSegment_ResolvesToEmptyPrefix()
    {
        // A bare-host request to the legacy JSON API already carries the "/pypi" segment
        // (https://pypi.org/pypi/{pkg}/json), so no further prefix is needed on top of it.
        var m = Build("pypi.org=pypi");
        Assert.Equal(string.Empty, m.PrefixForHost("pypi.org", "/pypi/lodash/json"));
    }

    [Fact]
    public void Mapped_CaseInsensitiveAndStripsPort()
    {
        var m = Build("registry.npmjs.org=npm");
        Assert.Equal("/npm", m.PrefixForHost("Registry.NPMJS.Org", "/lodash"));
        Assert.Equal("/npm", m.PrefixForHost("registry.npmjs.org:443", "/lodash"));
    }

    [Fact]
    public void UnmappedHost_NullPrefix()
    {
        var m = Build("registry.npmjs.org=npm");
        Assert.Null(m.PrefixForHost("dependably.example.com", "/api/v1/orgs"));
    }

    [Fact]
    public void MalformedEntry_Throws()
    {
        Assert.Throws<InvalidOperationException>(() => Build("registry.npmjs.org"));
    }

    [Fact]
    public void UnknownEcosystem_Throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => Build("conan.io=conan"));
        Assert.Contains("conan", ex.Message);
    }

    [Fact]
    public void MultipleHostsToSameEcosystem_BothMap()
    {
        // PyPI splits across pypi.org and files.pythonhosted.org; both resolve to the empty
        // (no-rewrite) prefix for their /simple/ and /packages/ routes.
        var m = Build("pypi.org=pypi,files.pythonhosted.org=pypi");
        Assert.Equal(string.Empty, m.PrefixForHost("pypi.org", "/simple/lodash/"));
        Assert.Equal(string.Empty, m.PrefixForHost("files.pythonhosted.org", "/packages/lodash-1.0.0.tgz"));
    }

    [Fact]
    public void MalformedEntry_TrailingEquals_Throws()
    {
        // Covers the `eq == pair.Length - 1` branch of the malformed-entry guard.
        Assert.Throws<InvalidOperationException>(() => Build("registry.npmjs.org="));
    }

    [Fact]
    public void MalformedEntry_LeadingEquals_Throws()
    {
        // Covers the `eq == 0` (empty host) side of `eq <= 0`.
        Assert.Throws<InvalidOperationException>(() => Build("=npm"));
    }

    [Fact]
    public void EmptyHost_ReturnsNullPrefix()
    {
        // Covers the IsNullOrEmpty short-circuit for an empty (non-null) host string.
        var m = Build("registry.npmjs.org=npm");
        Assert.Null(m.PrefixForHost("", "/lodash"));
    }
}
