namespace Dependably.Protocol.Hex;

// The registry v2 resources, as the Hex specification's proto2 schemas define them
// (names.proto, versions.proto, package.proto, policy.proto, signed.proto). Field numbers live in
// HexRegistryCodec; these records are the typed view every producer and consumer shares.

/// <summary>The envelope every registry resource travels in: a payload and its RSA signature.</summary>
public sealed record HexSigned(byte[] Payload, byte[]? Signature);

/// <summary>Seconds and nanoseconds since the Unix epoch, as <c>google.protobuf.Timestamp</c> lays them out.</summary>
public sealed record HexTimestamp(long Seconds, int Nanos)
{
    public static HexTimestamp FromDateTimeOffset(DateTimeOffset value)
    {
        long seconds = value.ToUnixTimeSeconds();
        int nanos = (int)((value.UtcTicks - (seconds * TimeSpan.TicksPerSecond + DateTimeOffset.UnixEpoch.UtcTicks)) * 100);
        return new HexTimestamp(seconds, nanos);
    }

    public DateTimeOffset ToDateTimeOffset() =>
        DateTimeOffset.FromUnixTimeSeconds(Seconds).AddTicks(Nanos / 100);
}

/// <summary><c>/names</c>: every package name the repository lists.</summary>
public sealed record HexNames(string Repository, IReadOnlyList<HexNameEntry> Packages);

public sealed record HexNameEntry(string Name, HexTimestamp? UpdatedAt = null);

/// <summary><c>/versions</c>: every package with its version strings and the retired / advisory index sets.</summary>
public sealed record HexVersions(string Repository, IReadOnlyList<HexVersionsEntry> Packages);

public sealed record HexVersionsEntry(
    string Name,
    IReadOnlyList<string> Versions,
    IReadOnlyList<int> Retired,
    IReadOnlyList<int> WithAdvisories);

/// <summary><c>/packages/NAME</c>: the releases of one package and the advisories that touch them.</summary>
public sealed record HexPackage(
    string Name,
    string Repository,
    IReadOnlyList<HexRelease> Releases,
    IReadOnlyList<HexSecurityAdvisory> Advisories);

public sealed record HexRelease(
    string Version,
    byte[] InnerChecksum,
    IReadOnlyList<HexDependency> Dependencies,
    HexRetirementStatus? Retired = null,
    byte[]? OuterChecksum = null,
    IReadOnlyList<uint>? AdvisoryIndexes = null,
    HexTimestamp? PublishedAt = null);

public sealed record HexRetirementStatus(HexRetirementReason Reason, string? Message = null);

/// <summary>Wire values of <c>RetirementReason</c>. An unknown value round-trips as its integer.</summary>
public enum HexRetirementReason
{
    Other = 0,
    Invalid = 1,
    Security = 2,
    Deprecated = 3,
    Renamed = 4,
}

public sealed record HexSecurityAdvisory(
    string Id,
    string Summary,
    string HtmlUrl,
    string ApiUrl,
    HexAdvisorySeverity? Severity = null,
    float? CvssScore = null,
    IReadOnlyList<string>? Aliases = null);

/// <summary>Wire values of <c>AdvisorySeverity</c>.</summary>
public enum HexAdvisorySeverity
{
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

public sealed record HexDependency(
    string Package,
    string Requirement,
    bool? Optional = null,
    string? App = null,
    string? Repository = null);

/// <summary><c>/repos/REPO/policies/NAME</c>: a signed dependency policy opted-in clients enforce at resolution time.</summary>
public sealed record HexPolicy(
    string Repository,
    string Name,
    HexVisibility Visibility,
    IReadOnlyList<HexRepositoryPolicy> Repositories,
    string? Description = null);

public enum HexVisibility
{
    Private = 0,
    Public = 1,
}

public sealed record HexRepositoryPolicy(
    string Repository,
    HexRestriction? Restriction,
    IReadOnlyList<HexOverride> Overrides);

public sealed record HexRestriction(
    HexAdvisorySeverity? AdvisoryMinSeverity,
    IReadOnlyList<HexRetirementReason> RetirementReasons,
    string? Cooldown);

public sealed record HexPackageRef(string Package, string? Requirement = null);

public sealed record HexOverride(
    HexOverrideAction Action,
    HexPackageRef Ref,
    string? AdvisoryId = null,
    HexRetirementReason? RetirementReason = null,
    string? Comment = null);

public enum HexOverrideAction
{
    Allow = 0,
    Deny = 1,
    Advisory = 2,
    Retirement = 3,
    Cooldown = 4,
}
