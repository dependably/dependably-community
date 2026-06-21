namespace Dependably.Tests.Integration;

/// <summary>
/// xUnit collection marker that serialises all live-Postgres test classes against each other.
/// Tests in this collection share the same single Postgres <c>public</c> schema and each
/// perform a full <c>DROP SCHEMA public CASCADE; CREATE SCHEMA public;</c> reset at the start
/// of every test, so they must not run concurrently. xUnit runs test classes within the same
/// collection sequentially.
/// </summary>
[CollectionDefinition("LivePostgres")]
public sealed class LivePostgresCollection;
