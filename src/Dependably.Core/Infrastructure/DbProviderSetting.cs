namespace Dependably.Infrastructure;

/// <summary>
/// Reads <c>DB_PROVIDER</c>. Unset or blank selects SQLite; <c>sqlite</c> and <c>postgres</c> are
/// accepted with surrounding whitespace and in any case. Anything else fails startup: a mistyped
/// value (<c>postgresql</c>, <c>pg</c>) must not silently boot a node on a local SQLite file while
/// the operator believes it is writing to the shared Postgres database.
///
/// <para>Every reader of <c>DB_PROVIDER</c> goes through this type so the web host, the HA check,
/// the edge host and the row-level security default agree on what a value means.</para>
/// </summary>
public static class DbProviderSetting
{
    public const string Key = "DB_PROVIDER";

    public static DbProvider FromConfiguration(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        string raw = (configuration[Key] ?? "").Trim();
        return raw.ToLowerInvariant() switch
        {
            "" or "sqlite" => DbProvider.Sqlite,
            "postgres" => DbProvider.Postgres,
            _ => throw new InvalidOperationException(
                $"{Key} must be 'sqlite' or 'postgres' (got '{raw}')."),
        };
    }
}
