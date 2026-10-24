namespace Dependably.Infrastructure;

/// <summary>
/// The parsed value of <c>DISABLE_BACKGROUND_JOBS</c>: either the whole job set is switched off
/// (<see cref="AllJobs"/>), or <see cref="Names"/> lists the individual jobs to disable (empty
/// when nothing is disabled).
/// </summary>
public sealed record DisabledBackgroundJobs(bool AllJobs, IReadOnlySet<string> Names)
{
    public static DisabledBackgroundJobs None() =>
        new(false, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
}

/// <summary>
/// Reads <c>DISABLE_BACKGROUND_JOBS</c>. The value is one of:
/// <list type="bullet">
/// <item><c>true</c>, <c>1</c> or <c>all</c> (any case) on its own: every background job is
/// disabled, including a job name this build does not list in <see cref="BackgroundJobs.Known"/>,
/// except the local housekeeping jobs in <see cref="BackgroundJobs.HousekeepingExemptFromWholeSet"/>.</item>
/// <item><c>false</c> or <c>0</c> on its own, blank, or unset: no job is disabled.</item>
/// <item>A comma-separated list of job names from <see cref="BackgroundJobs.Known"/> (any case,
/// surrounding whitespace ignored): those jobs are disabled.</item>
/// </list>
/// Anything else fails startup with an error naming the unrecognised token and the known names.
/// The variable is an egress control, so a mistyped value must stop the node rather than leave
/// every job running while the operator believes they are off. A switch value inside a list
/// (<c>true,vuln-scan</c>) is refused for the same reason: whether it means "everything" or is a
/// typo of a name cannot be told from the value.
///
/// <para>Every reader of <c>DISABLE_BACKGROUND_JOBS</c> goes through this type, so the startup
/// check and <see cref="AirGapMode"/> agree on what a value means.</para>
/// </summary>
public static class DisableBackgroundJobsSetting
{
    public const string Key = "DISABLE_BACKGROUND_JOBS";

    private static readonly IReadOnlySet<string> AllJobsValues =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "true", "1", "all" };

    private static readonly IReadOnlySet<string> NoJobsValues =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "false", "0" };

    public static DisabledBackgroundJobs FromConfiguration(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return Parse(configuration[Key]);
    }

    public static DisabledBackgroundJobs Parse(string? raw)
    {
        string value = (raw ?? "").Trim();
        if (value.Length == 0 || NoJobsValues.Contains(value))
        {
            return DisabledBackgroundJobs.None();
        }

        if (AllJobsValues.Contains(value))
        {
            return new DisabledBackgroundJobs(true, BackgroundJobs.DisabledByWholeSet);
        }

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string token in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (AllJobsValues.Contains(token) || NoJobsValues.Contains(token))
            {
                throw new InvalidOperationException(
                    $"{Key} contains '{token}' inside a list (got '{value}'). " +
                    "'true', '1', 'all', 'false' and '0' switch the whole job set and must be the value on its own; " +
                    $"a list names individual jobs. Known job names: {KnownNamesForMessage()}.");
            }

            if (!BackgroundJobs.Known.Contains(token))
            {
                throw new InvalidOperationException(
                    $"{Key} contains unknown job name '{token}'. Set it to 'true' to disable every " +
                    $"background job, or to a comma-separated list of known job names: {KnownNamesForMessage()}.");
            }

            names.Add(token);
        }

        return new DisabledBackgroundJobs(false, names);
    }

    private static string KnownNamesForMessage() =>
        string.Join(", ", BackgroundJobs.Known.Order(StringComparer.Ordinal));
}
