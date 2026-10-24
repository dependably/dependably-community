using System.Data.Common;
using Dapper;

namespace Dependably.Infrastructure;

/// <summary>
/// Refuses to apply the schema to a database older than the documented upgrade floor (v0.13.3),
/// before anything is changed. The one-time migrations carry the table shapes a floor database can
/// be in and the ones before it; a database from an earlier release reaches migration bodies that
/// are no longer maintained against the current column lists, and the result is not something a
/// later boot can repair. Upgrading through v0.13.3 first is the supported path.
///
/// <para><b>How the floor is recognized.</b> A database is at or above the floor when its ledger
/// holds <see cref="UpgradeFloorSentinel"/>, a one-time migration that every database that booted
/// v0.13.1 or later has recorded (fresh installs record every migration), or
/// <see cref="UpgradeFloorMarker"/>, which this check writes the first time it passes. The marker is
/// what keeps a fresh install whose first boot was interrupted before the sentinel ran from being
/// mistaken for an old database. A database with no <c>orgs</c> table is a fresh install and
/// passes, recording the marker first.</para>
///
/// <para><b>The default never blocks a healthy database.</b> Every database a supported upgrade
/// path produces passes, including the one documented exception: a Postgres database created by
/// 0.2.2 to 0.4.4, which upgrades directly because no release between it and the floor can start on
/// it (<see cref="IsPrePlaneMigrationPostgresAsync"/>). Once a later boot has failed partway on such
/// a database it is no longer recognizable, and the refusal says so. <c>UPGRADE_FLOOR_OVERRIDE=true</c>
/// is the explicit opt-out for a database known to be below the floor: the boot proceeds and logs an
/// error naming the risk.</para>
/// </summary>
public sealed partial class SchemaInitializer
{
    /// <summary>The release below which a database is refused.</summary>
    internal const string UpgradeFloorVersion = "0.13.3";

    /// <summary>A one-time migration first shipped in v0.13.1 and recorded by every later database.</summary>
    internal const string UpgradeFloorSentinel = "expand_usage_daily_meter_check_cache_storage";

    /// <summary>The ledger row this check records once a database has passed it.</summary>
    internal const string UpgradeFloorMarker = "upgrade_floor_0_13_3";

    /// <summary>The setting that boots a below-floor database anyway.</summary>
    public const string UpgradeFloorOverrideKey = "UPGRADE_FLOOR_OVERRIDE";

    // xtenant: _applied_migrations and the catalogue are instance-wide; there is no tenant column.
    private const string SqliteTableExistsSql =
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = @name";

    // xtenant: _applied_migrations and the catalogue are instance-wide; there is no tenant column.
    private const string PostgresTableExistsSql =
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = @name";

    internal async Task EnforceUpgradeFloorAsync(DbConnection conn)
    {
        string existsSql = _db.Provider == DbProvider.Postgres ? PostgresTableExistsSql : SqliteTableExistsSql;
        bool established = await conn.ExecuteScalarAsync<long>(existsSql, new { name = "orgs" }) > 0;
        if (established && !await AtUpgradeFloorAsync(conn, existsSql)
            && !await IsPrePlaneMigrationPostgresAsync(conn))
        {
            if (!string.Equals(_config?[UpgradeFloorOverrideKey], "true", StringComparison.OrdinalIgnoreCase))
            {
                throw new UpgradeFloorException(
                    UpgradeFloorVersion, UpgradeFloorOverrideKey, _db.Provider == DbProvider.Postgres);
            }

            _logger.LogError(
                "{Setting}=true: applying the schema to a database below the v{Floor} upgrade floor (its migration "
                + "ledger lacks {Sentinel}). Migrations for releases before v{Floor} are not maintained against the "
                + "current schema, so columns or rows may be lost. Restore from a backup and upgrade through "
                + "v{Floor} first if this boot leaves the schema wrong, and remove the setting once it has completed.",
                UpgradeFloorOverrideKey, UpgradeFloorVersion, UpgradeFloorSentinel, UpgradeFloorVersion, UpgradeFloorVersion);
        }

        await EnsureMigrationsTableAsync(conn);
        // xtenant: _applied_migrations is the instance-wide migration ledger.
        await conn.ExecuteAsync(
            "INSERT INTO _applied_migrations (name) VALUES (@name) ON CONFLICT (name) DO NOTHING",
            new { name = UpgradeFloorMarker });
    }

    // The one documented exception to the floor: a Postgres database created by 0.2.2 to 0.4.4
    // upgrades straight to this release, because every release from 0.4.5 to the floor fails in its
    // base schema on it and so never changes it. Such a database still has nuget_symbol_index in the
    // shape those releases created, without cache_artifact_id. Any boot that reaches the additive
    // pass adds the column, including one that then fails partway through the one-time migrations
    // and so records neither the sentinel nor the marker; from then on the shape no longer
    // identifies the database, and the refusal names UPGRADE_FLOOR_OVERRIDE for that case.
    private async Task<bool> IsPrePlaneMigrationPostgresAsync(DbConnection conn)
    {
        if (_db.Provider != DbProvider.Postgres
            || await conn.ExecuteScalarAsync<long>(PostgresTableExistsSql, new { name = "nuget_symbol_index" }) == 0)
        {
            return false;
        }

        // xtenant: reads the Postgres catalogue, not application data.
        bool hasColumn = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM information_schema.columns
            WHERE table_schema = current_schema() AND table_name = 'nuget_symbol_index'
              AND column_name = 'cache_artifact_id'
            """) > 0;
        if (!hasColumn)
        {
            _logger.LogInformation(
                "This Postgres database was created by a release from 0.2.2 to 0.4.4, which upgrades directly to this "
                + "release rather than through v{Floor}; applying the schema.",
                UpgradeFloorVersion);
        }

        return !hasColumn;
    }

    private static async Task<bool> AtUpgradeFloorAsync(DbConnection conn, string existsSql)
    {
        if (await conn.ExecuteScalarAsync<long>(existsSql, new { name = "_applied_migrations" }) == 0)
        {
            return false;
        }

        // xtenant: _applied_migrations is the instance-wide migration ledger.
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM _applied_migrations WHERE name IN (@sentinel, @marker)",
            new { sentinel = UpgradeFloorSentinel, marker = UpgradeFloorMarker }) > 0;
    }
}

/// <summary>Raised at boot when the database is older than the supported upgrade floor.</summary>
public sealed class UpgradeFloorException(string floor, string overrideKey, bool postgres = false)
    : Exception(
        $"Refusing to start: this database predates v{floor}, the oldest release this version upgrades from. "
        + $"Upgrade it by running v{floor} against it once, then start this version. Nothing has been changed. "
        + (postgres
            ? $"One case cannot take that route: a Postgres database created by 0.2.2 to 0.4.4 on which a 0.14.x or "
              + $"later boot already failed partway. v{floor} cannot start on it; set {overrideKey}=true for one boot "
              + "instead, after backing it up, and remove the setting once that boot has completed. "
            : "")
        + $"To apply the schema anyway, set {overrideKey}=true; columns or rows may be lost.");
