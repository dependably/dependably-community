using Npgsql;

namespace Dependably.Infrastructure;

/// <summary>
/// Resolves the Postgres connection string from configuration. <c>DB_CONNECTION_STRING</c> carries
/// the connection; <c>DB_PASSWORD</c> and <c>DB_USERNAME</c>, when set, override the credential
/// inside it. The split exists for orchestrators that inject a secret as its own environment
/// variable and cannot splice it into a larger string (ECS task-definition <c>secrets</c>, a
/// rotated RDS/Aurora managed credential, file-mounted secrets surfaced as variables).
///
/// <para>Every reader of <c>DB_CONNECTION_STRING</c> — the web host and the migration verbs —
/// goes through this type, so the app and the migration tooling cannot disagree about which
/// credential they connect with. The merged string holds the password: never log it.</para>
/// </summary>
public static class PostgresConnectionString
{
    /// <summary>Configuration key for the base connection string.</summary>
    public const string ConnectionStringKey = "DB_CONNECTION_STRING";

    /// <summary>Configuration key whose value, when set, replaces the connection string's password.</summary>
    public const string PasswordKey = "DB_PASSWORD";

    /// <summary>Configuration key whose value, when set, replaces the connection string's username.</summary>
    public const string UsernameKey = "DB_USERNAME";

    /// <summary>
    /// The configured connection string with the credential overrides applied, or null when
    /// <c>DB_CONNECTION_STRING</c> is unset or blank.
    /// </summary>
    public static string? FromConfiguration(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        string? baseConnectionString = configuration[ConnectionStringKey];
        return string.IsNullOrWhiteSpace(baseConnectionString)
            ? null
            : ApplyCredentialOverrides(baseConnectionString, configuration);
    }

    /// <summary>
    /// Returns <paramref name="connectionString"/> with <c>DB_USERNAME</c> / <c>DB_PASSWORD</c>
    /// applied. Each override wins over the value embedded in the string; an unset or empty
    /// override leaves the string's own value in place. With neither override set the input is
    /// returned unchanged, not re-serialized.
    /// </summary>
    public static string ApplyCredentialOverrides(string connectionString, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(connectionString);
        ArgumentNullException.ThrowIfNull(configuration);

        string? password = configuration[PasswordKey];
        string? username = configuration[UsernameKey];
        if (string.IsNullOrEmpty(password) && string.IsNullOrEmpty(username))
        {
            return connectionString;
        }

        var builder = new NpgsqlConnectionStringBuilder(connectionString);
        if (!string.IsNullOrEmpty(username))
        {
            builder.Username = username;
        }

        if (!string.IsNullOrEmpty(password))
        {
            builder.Password = password;
        }

        return builder.ConnectionString;
    }
}
