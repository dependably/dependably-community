using Dependably.Infrastructure;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// <see cref="InstanceSettingDefaults.ParseCacheSizeWarnBytes"/> — the fallback rule shared by
/// <c>CacheSizeAlertService</c> (the enforcing check) and <c>HealthService</c> (the read-only
/// health flag): absent or unparseable falls back to the seeded default, but an explicit "0" is
/// honoured as a deliberate disable rather than being treated the same as "unset".
/// </summary>
[Trait("Category", "Unit")]
public sealed class InstanceSettingDefaultsTests
{
    [Fact]
    public void ParseCacheSizeWarnBytes_Null_FallsBackToDefault()
    {
        Assert.Equal(long.Parse(InstanceSettingDefaults.CacheSizeWarnBytes),
            InstanceSettingDefaults.ParseCacheSizeWarnBytes(null));
    }

    [Fact]
    public void ParseCacheSizeWarnBytes_EmptyOrGarbage_FallsBackToDefault()
    {
        Assert.Equal(long.Parse(InstanceSettingDefaults.CacheSizeWarnBytes),
            InstanceSettingDefaults.ParseCacheSizeWarnBytes(""));
        Assert.Equal(long.Parse(InstanceSettingDefaults.CacheSizeWarnBytes),
            InstanceSettingDefaults.ParseCacheSizeWarnBytes("not-a-number"));
    }

    [Fact]
    public void ParseCacheSizeWarnBytes_Negative_FallsBackToDefault()
    {
        // A negative threshold is nonsensical, not a deliberate disable — only an explicit
        // zero carries that meaning.
        Assert.Equal(long.Parse(InstanceSettingDefaults.CacheSizeWarnBytes),
            InstanceSettingDefaults.ParseCacheSizeWarnBytes("-1"));
    }

    [Fact]
    public void ParseCacheSizeWarnBytes_ExplicitZero_IsHonouredAsDisabled()
    {
        Assert.Equal(0L, InstanceSettingDefaults.ParseCacheSizeWarnBytes("0"));
    }

    [Fact]
    public void ParseCacheSizeWarnBytes_ExplicitPositiveValue_IsHonoured()
    {
        Assert.Equal(123456789L, InstanceSettingDefaults.ParseCacheSizeWarnBytes("123456789"));
    }

    [Fact]
    public void AllowedKeys_IncludesCacheSizeWarnBytes()
    {
        Assert.Contains("cache_size_warn_bytes", InstanceSettingDefaults.AllowedKeys);
    }
}
