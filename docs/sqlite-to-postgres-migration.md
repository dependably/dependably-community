# SQLite → Postgres migration — operator runbook

A standalone dependably deployment runs on SQLite (`DB_PROVIDER=sqlite`, a single file at
`DB_PATH`). A high-availability deployment cannot: SQLite is a single-writer store, and startup
refuses `DEPENDABLY_DEPLOYMENT_MODE=ha` unless `DB_PROVIDER=postgres`. This runbook is the supported path
between the two — it moves an existing standalone installation's metadata onto Postgres in place,
with a verification step you run *before* cutting traffic over and a rollback that is always
available because the source is never modified.

Two things are explicitly **not** in scope:

- **Blob storage is untouched.** Published artifacts and cached upstream artifacts live in the blob
  store (`LOCAL_STORAGE_PATH`, S3, or Azure), not in the database. The migration moves metadata
  only. Point the new deployment at the same blob store — or migrate the blob store separately,
  before or after, using its own tooling.
- **Postgres provisioning is yours.** Create the database and the role; the migration creates the
  schema inside it.

## What the migration does

`migrate-to-postgres` is a subcommand of the product image — the same binary that serves traffic,
so there is no second artifact to install and no second version to keep in step with the schema.

It runs in this order:

1. **Derives the table list from the source database**, not from a list in code. Tables come from
   the SQLite catalogue and the copy order comes from the real foreign keys, so parents are always
   written before their children. A table added in a future release is covered the moment it exists.
2. **Applies the current schema to the target** with the same `SchemaInitializer` the server runs at
   boot — base schema, additive columns, and the one-time migrations. The destination is therefore
   byte-identical in shape to what a fresh server would create.
3. **Refuses to overwrite a target that already holds data** unless you pass `--force`. A target
   that has only ever had the schema applied (you booted the app against it once) still counts as
   free; a target with orgs, users, or packages in it does not.
4. **Copies every table** with the Postgres binary `COPY` protocol, coercing each value to the
   target column's exact type (below). Primary keys, foreign keys, and timestamps are preserved
   verbatim — no identifier is re-minted.
5. **Resets every identity sequence** past the largest value it just inserted. Rows carry their
   original ids, so a sequence left at its initial value would hand the next insert an id that
   already exists.
6. **Verifies the result** — per-table row counts plus a content digest (see
   [Verification](#verification)).

The source SQLite file is opened read/write but never written to. Nothing about the migration
destroys or alters it, which is what makes rollback trivial.

## Type handling

The schema is deliberately engine-agnostic — both `Schema.sql` and `Schema.pg.sql` are maintained in
lockstep and gated by `SchemaParityComplianceTests` — so most columns are `TEXT` on both engines and
the copy is a pass-through. The cases that are not, and what the migrator does with them:

| Source (SQLite) | Target (Postgres) | Conversion |
| --- | --- | --- |
| ISO-8601 `TEXT` | `TEXT` | Copied verbatim. Most timestamps in the schema are this shape on both engines. |
| ISO-8601 `TEXT` | `timestamptz` | Parsed as an instant and normalised to UTC. A value with no offset is UTC, matching every writer in the codebase. Truncated to whole microseconds — Postgres's own resolution — so the value written is bit-for-bit the value read back. Affects `npm_dist_tags.created_at` / `.updated_at` and `upstream_negative_cache.fetched_at`. |
| `INTEGER` (0/1 boolean) | `INTEGER` | Copied as an integer. The schema encodes booleans as `INTEGER` on both engines; nothing is coerced to a Postgres `boolean`. |
| `INTEGER` | `INTEGER` (4-byte) | Range-checked. A value that does not fit aborts the migration; it is never wrapped or truncated. |
| `INTEGER` | `BIGINT` | Copied as a 64-bit integer. Large counters (`download_count`, `size_bytes`, `storage_quota_bytes`) keep full magnitude — they never round-trip through a double. |
| `REAL` (8-byte) | `REAL` (4-byte) | Narrowed to `float4`, which is what the column declares. This is the one lossy conversion in the schema, and it applies to score tolerances (`max_osv_score_tolerance`, `max_epss_tolerance`, `cvss_score`, `epss_score`) where 4-byte precision is the storage the running server already uses. Verification compares the narrowed value on both sides, so it is exact rather than tolerated. |
| `INTEGER PRIMARY KEY AUTOINCREMENT` | `BIGSERIAL` | Ids copied as-is, then the sequence is `setval`'d past the maximum. |
| Any value in a column whose Postgres type has no rule | — | **Aborts.** An unrecognised type is a hard failure, not a best-effort guess. |
| A BLOB stored in a `TEXT`-declared column | — | **Aborts**, naming the table and column. There is no lossless decoding to pick, and picking one is exactly the silent corruption this path exists to prevent. |
| A fractional value in an integer column | — | **Aborts.** `1.5` in an `INTEGER` column is corrupt data, not a rounding opportunity. |

SQLite is dynamically typed: a column *declared* `TEXT` can hold an integer, and vice versa. Every
value is therefore coerced against the **target** column's type explicitly, never by implicit
conversion.

### Rows with broken foreign keys

An old database can carry rows whose foreign keys do not resolve — SQLite does not re-validate
existing rows when enforcement is turned back on. Postgres would reject them. The migrator reports
them up front and, where the connecting role permits it (`SET session_replication_role = replica`,
which needs a superuser), copies them through with enforcement bypassed so the target is an exact
reproduction of the source, orphans included. If the role cannot bypass enforcement *and* the source
has orphans, the migration aborts before writing anything and names the rows, so you can decide
whether to delete them or connect as a superuser.

## Procedure

### 1. Before the window (no downtime)

- **Upgrade the standalone instance to the release you are migrating with.** The migrator refuses to
  run if the source has a column the target schema lacks — that means the two are on different
  releases. Get both on the same one first.
- **Provision the Postgres database** and a role that owns it. Prefer a role with superuser rights
  for the migration itself (see [broken foreign keys](#rows-with-broken-foreign-keys)); the running
  server does not need them.
- **Take a copy of the SQLite file** anyway. `sqlite3 dependably.db ".backup backup.db"`, or stop the
  service and copy `dependably.db`, `dependably.db-wal`, and `dependably.db-shm` together.
- **Dry-run against a scratch Postgres** with a copy of the file. The migration is deterministic;
  a successful rehearsal is the best predictor of the real run.

### 2. Quiesce writes

The migration takes a point-in-time copy. Anything written to SQLite after the copy starts is lost.

**Stop every dependably process pointed at the database.** The instance lock is the chokepoint that
makes this checkable: a file-backed SQLite deployment writes a heartbeat row to `instance_lock`
while it runs, and releases it on graceful shutdown.

```bash
docker compose stop dependably     # or: systemctl stop dependably

# The lock row should be gone. If it is not, the process did not shut down gracefully.
sqlite3 /data/dependably.db "SELECT instance_id, hostname, heartbeat_at FROM instance_lock;"
```

`migrate-to-postgres` re-checks this itself and logs a warning if the heartbeat is younger than the
default 90-second staleness window (the fixed default, not a per-instance
`INSTANCE_LOCK_STALE_SECONDS` override) — a live node is very likely still writing, and a copy taken
from underneath one is a torn snapshot. Treat that warning as a stop sign.

The downtime window is from this stop until the cutover in step 5. It scales with the row count, not
the artifact count — the blob store is not touched — so it is typically minutes.

### 3. Migrate

Run the subcommand from the product image, with both databases reachable:

```bash
docker run --rm \
  -v /data:/data \
  dependably/community:<version> \
  ./Dependably migrate-to-postgres \
    --source /data/dependably.db \
    --target "Host=pg.internal;Port=5432;Database=dependably;Username=dependably;Password=…"
```

`--source` defaults to `DB_PATH` and `--target` to `DB_CONNECTION_STRING`, so a container already
configured for either provider needs only the missing half on the command line.

| Option | Effect |
| --- | --- |
| `--source <path>` | SQLite database to read. Defaults to `DB_PATH`. |
| `--target <conn>` | Postgres connection string. Defaults to `DB_CONNECTION_STRING`. |
| `--force` | Replace data already present in the target. **Destructive** — it truncates every migrated table first. |
| `--skip-verify` | Copy without the verification pass. Run `verify-postgres-migration` separately before cutting over. |

Exit codes: `0` success, `1` the migration could not run or failed, `2` the copy ran but
verification found a difference.

Progress and the per-table row counts are logged through the normal Serilog pipeline, so they land
in whatever sink the instance is configured for.

### 4. Verify

Verification runs by default at the end of the copy, and can be re-run at any time — hours later, or
after a suspected incident — as long as the source SQLite file is still around:

```bash
docker run --rm -v /data:/data dependably/community:<version> \
  ./Dependably verify-postgres-migration \
    --source /data/dependably.db \
    --target "Host=pg.internal;…"
```

It reads only. **Do not cut over unless this exits `0`.**

#### What verification actually checks

For every table it compares:

- **Row counts** on both sides.
- **A content digest.** Each row is rendered to a canonical string through the *same* conversion the
  copy uses — so a representation difference that is correct (an ISO-8601 string landing in a
  `timestamptz`, a double narrowed to a 4-byte `real`) does not register as drift — then hashed, and
  folded into the table digest with two order-independent operators (an XOR and a wrapping sum). A
  single changed byte in a single column changes the digest. The row count is compared alongside the
  digest, so duplicated or missing rows cannot cancel out.

A digest comparison rather than a row-by-row join is deliberate: several tables have composite or
opaque keys, and there is no engine-independent ordering to join them on.

Tables present in the source but absent from the current schema (dropped by a later release) are
reported as *skipped*, not failed. If **every** table is skipped — the target has no dependably
schema at all, because you pointed at the wrong database or the migration never ran — verification
**fails** rather than reporting a vacuous pass over zero tables.

### 5. Cut over

Point the instance at Postgres and start it:

```
DB_PROVIDER=postgres
DB_CONNECTION_STRING=Host=pg.internal;Port=5432;Database=dependably;Username=dependably;Password=…
```

Leave `DB_PATH` set or unset as you like — it is ignored when `DB_PROVIDER=postgres`.

Smoke-test before adding replicas: log in, list packages in each org, resolve one artifact from each
ecosystem you use, and confirm existing sessions and API tokens still work (they will — `jwt_secret`,
the DataProtection key ring, and the token hashes all came across). Only then scale out with
`DEPENDABLY_DEPLOYMENT_MODE=ha` and `REDIS_CONNECTION_STRING`.

### 6. Rollback

The source SQLite file is never modified, so rollback is always available and always clean:

1. Stop the instance.
2. Restore `DB_PROVIDER=sqlite` (and `DB_PATH`) in the environment.
3. Start it.

You are back on the pre-migration state with no data loss, because no write reached Postgres that
was not first read from SQLite. Drop or truncate the Postgres database before retrying, or re-run
with `--force`.

The one thing that does *not* roll back is anything written to Postgres after the cutover in step 5.
Roll back promptly if you are going to, and keep the SQLite file until you are confident.

## Failure modes and what they mean

| Symptom | Meaning | Action |
| --- | --- | --- |
| `The Postgres target already holds data and will not be overwritten` | The target has orgs/users/packages in it. | Point at an empty database, or re-run with `--force` if replacing its contents is what you intend. |
| `column(s) … exist in the SQLite source but not in the Postgres target` | The two sides are on different releases. | Upgrade both to the same release and re-run. |
| `a … BLOB is stored in a column Postgres declares TEXT` | A row holds binary data in a text column. | Inspect and fix (or delete) the named row; re-run. |
| `Postgres type '…' has no migration rule` | A schema change introduced a column type the migrator has no explicit conversion for. | This is a bug — the conversion belongs in `PostgresValueConverter`. Do not work around it. |
| `The source holds N row(s) whose foreign keys do not resolve` and the role cannot bypass enforcement | Dangling rows the target would reject. | Connect as a superuser, or delete the named rows first. |
| `Verification FAILED for <table>` | The target does not match the source. | **Do not cut over.** Roll back (the source is untouched), investigate, re-run with `--force`. |
| `Verification FAILED: not one table could be compared` | The target has no dependably schema. | Wrong database, or the migration never ran. Check `--target`. |
| `Table … exists in the SQLite source but not in the current schema` | A table a later release dropped. | Informational. Confirm nothing you need lives there. |

## Notes

- The migration is **not incremental**. There is no way to copy "just the changes since last time";
  each run is a full replacement. This is why the write-quiesce in step 2 is load-bearing.
- The Postgres `_applied_migrations` ledger is written by the target's own schema apply and is not
  copied from the source. Each database's ledger describes that database.
- `spdx_license` is copied from the source rather than left as the target's freshly seeded copy, so
  the two databases agree exactly and verification is meaningful for that table too.
- Only the `dependably/community` image carries these subcommands. The `dependably/edge` image does
  not: an edge node holds no durable state worth migrating.
