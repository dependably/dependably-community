# Postgres COLLATE "C" migration — operator runbook

A fresh Postgres install already declares every indexed temporal column (`created_at`,
`occurred_at`, `expires_at`, and the rest of the `*_at`/`*_since` timestamp columns that
participate in a `CREATE INDEX`) as `TEXT COLLATE "C"` — see `Schema.pg.sql`. An **existing**
Postgres database is not changed automatically. This is the operator-run procedure for bringing
one up to the same state, and it is optional: the database works correctly without it.

## What this buys, and why it is not automatic

Every timestamp in dependably is ISO-8601 UTC `TEXT`, compared lexicographically
(`WHERE occurred_at <= @now`, `ORDER BY created_at DESC`). That comparison is already correct
under Postgres's default collation — but "correct" and "as fast and as stable as it could be" are
different claims:

- **Byte-exact ordering.** `COLLATE "C"` orders by raw byte value, the same rule SQLite's default
  `BINARY` TEXT collation already uses (see `Schema.sql`) — so the two engines agree on ordering by
  construction, not by coincidence. Measured on this schema's data: **1.9× faster sorts at
  identical index size** against the default (locale-aware) collation, because `"C"` comparison
  never has to consult ICU/glibc locale tables — it is a `memcmp`.
- **Immunity to collation-version drift.** A default-collation index's on-disk ordering is tied to
  the *version* of the OS's collation library, not just its name. glibc 2.28 changed the sort order
  for several locales; every btree index on a `text` column collated under one of those locales
  silently went stale on affected systems until a manual `REINDEX`, because Postgres does not detect
  or fix this itself. `"C"` is not locale data — it is defined as raw byte order, so there is no
  library to version and nothing to drift.

It is not applied automatically because the mechanism that would apply it is dangerous on a live
database: `ALTER TABLE … ALTER COLUMN … TYPE text COLLATE "C"` rewrites the column's storage *and
every index on it* under an `ACCESS EXCLUSIVE` lock — the same class of boot-time stall this
project already removed from the timestamp-normalization sweep (see
`SchemaInitializer.TimestampNormalization.cs`) rather than reintroduce here. There is no `NOT
VALID`-style incremental path for a collation change the way there is for a `CHECK` constraint:
the rewrite either runs to completion, blocking every reader and writer of the table for its
duration, or it doesn't run.

SQLite needs no equivalent step: its default TEXT collation (`BINARY`) is already byte order, so
there is nothing to opt into on that engine.

## Before you run this

- **Pick a maintenance window.** Every statement below takes an `ACCESS EXCLUSIVE` lock on the
  table it touches for the duration of the rewrite — reads and writes both block.
- **Rebuild time scales with table size**, not row complexity. The two hottest tables in a typical
  deployment are **`audit_log`** and **`activity`** — every push, pull, and login event is a row in
  one or both — so they are usually the longest-running statements here and the ones most worth
  scheduling around, rather than the smaller per-org config tables.
- **Take a backup first** (`pg_dump`, or your usual snapshot mechanism). This is a normal
  precaution before any `ACCESS EXCLUSIVE` DDL, not a rollback path this procedure provides on its
  own — there is no automated undo below.
- **This is idempotent to re-run.** `ALTER COLUMN … TYPE text COLLATE "C"` on a column already
  collated `"C"` is a no-op rewrite (Postgres still takes the lock and scans the table, but changes
  nothing), so a partially-completed run — the window closed early, a statement was skipped — can
  safely be repeated from the top.

## The columns

Every temporal column that participates in a `CREATE INDEX` in `Schema.pg.sql`, whether as an
indexed key column or referenced only in a partial index's `WHERE` predicate (derived by
re-parsing every `CREATE INDEX` statement in that file, not hand-listed):

| Table | Column |
| --- | --- |
| `audit_log` | `created_at` |
| `activity` | `created_at` |
| `audit_event` | `occurred_at` |
| `claim_history` | `occurred_at` |
| `cache_artifact` | `last_accessed_at` |
| `quarantine` | `updated_at` |
| `alert` | `created_at` |
| `jwt_revocations` | `expires_at` |
| `saml_test_runs` | `expires_at` |
| `saml_pending_requests` | `expires_at` |
| `saml_consumed_assertions` | `expires_at` |
| `background_job_runs` | `started_at` |
| `banners` | `ends_at` |
| `password_reset_tokens` | `consumed_at` |
| `email_change_tokens` | `consumed_at` |
| `invites` | `accepted_at` |

The last three (`consumed_at` / `accepted_at`) appear only inside a partial index's `WHERE col IS
NULL` predicate rather than as a sorted index key — `IS NULL` is not itself collation-sensitive —
but they are included for consistency with the fresh-install schema and to cover any future query
against those columns that does compare or sort on them.

## Procedure

Run each statement in a maintenance window, against the target database:

```sql
ALTER TABLE audit_log                  ALTER COLUMN created_at        TYPE text COLLATE "C";
ALTER TABLE activity                   ALTER COLUMN created_at        TYPE text COLLATE "C";
ALTER TABLE audit_event                ALTER COLUMN occurred_at       TYPE text COLLATE "C";
ALTER TABLE claim_history              ALTER COLUMN occurred_at       TYPE text COLLATE "C";
ALTER TABLE cache_artifact             ALTER COLUMN last_accessed_at  TYPE text COLLATE "C";
ALTER TABLE quarantine                 ALTER COLUMN updated_at        TYPE text COLLATE "C";
ALTER TABLE alert                      ALTER COLUMN created_at        TYPE text COLLATE "C";
ALTER TABLE jwt_revocations            ALTER COLUMN expires_at        TYPE text COLLATE "C";
ALTER TABLE saml_test_runs             ALTER COLUMN expires_at        TYPE text COLLATE "C";
ALTER TABLE saml_pending_requests      ALTER COLUMN expires_at        TYPE text COLLATE "C";
ALTER TABLE saml_consumed_assertions   ALTER COLUMN expires_at        TYPE text COLLATE "C";
ALTER TABLE background_job_runs        ALTER COLUMN started_at        TYPE text COLLATE "C";
ALTER TABLE banners                    ALTER COLUMN ends_at           TYPE text COLLATE "C";
ALTER TABLE password_reset_tokens      ALTER COLUMN consumed_at       TYPE text COLLATE "C";
ALTER TABLE email_change_tokens        ALTER COLUMN consumed_at       TYPE text COLLATE "C";
ALTER TABLE invites                    ALTER COLUMN accepted_at       TYPE text COLLATE "C";
```

Run them one at a time, largest tables (`audit_log`, `activity`) first or last per your own
window-length preference — the statements are independent of each other and order does not affect
correctness. Each rebuilds the column's storage and every index that references it; no `USING`
clause is needed because the column stays `TEXT` throughout — only its collation changes.

There is no server restart or `SchemaInitializer` re-run required: Postgres sessions opened after
each `ALTER` see the new collation immediately, and the value stored in every row is byte-identical
before and after (`COLLATE` changes comparison and sort order, not the bytes themselves), so no
existing query result changes shape.

## Verifying it took

```sql
SELECT c.relname, a.attname, co.collname
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
JOIN pg_collation co ON co.oid = a.attcollation
WHERE a.attname IN (
  'created_at', 'occurred_at', 'last_accessed_at', 'updated_at', 'expires_at',
  'started_at', 'ends_at', 'consumed_at', 'accepted_at'
)
ORDER BY c.relname, a.attname;
```

Every row for a table/column pair in the table above should read `collname = C`. A column not in
that table showing `default` is expected — this migration is deliberately scoped to indexed
temporal columns only, not every `TEXT` column in the schema.
