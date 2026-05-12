using Dependably.Infrastructure;
using Microsoft.Extensions.Configuration;
using Xunit;

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
        Assert.Null(m.PrefixForHost("registry.npmjs.org"));
    }

    [Fact]
    public void Mapped_ReturnsEcosystemPrefix()
    {
        var m = Build("registry.npmjs.org=npm,pypi.org=pypi,api.nuget.org=nuget");
        Assert.Equal("/npm",   m.PrefixForHost("registry.npmjs.org"));
        Assert.Equal("/pypi",  m.PrefixForHost("pypi.org"));
        Assert.Equal("/nuget", m.PrefixForHost("api.nuget.org"));
    }

    [Fact]
    public void Mapped_CaseInsensitiveAndStripsPort()
    {
        var m = Build("registry.npmjs.org=npm");
        Assert.Equal("/npm", m.PrefixForHost("Registry.NPMJS.Org"));
        Assert.Equal("/npm", m.PrefixForHost("registry.npmjs.org:443"));
    }

    [Fact]
    public void UnmappedHost_NullPrefix()
    {
        var m = Build("registry.npmjs.org=npm");
        Assert.Null(m.PrefixForHost("dependably.example.com"));
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
        // PyPI splits across pypi.org and files.pythonhosted.org; both must route to /pypi.
        var m = Build("pypi.org=pypi,files.pythonhosted.org=pypi");
        Assert.Equal("/pypi", m.PrefixForHost("pypi.org"));
        Assert.Equal("/pypi", m.PrefixForHost("files.pythonhosted.org"));
    }
}
