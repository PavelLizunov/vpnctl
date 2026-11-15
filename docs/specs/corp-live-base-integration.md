# Corp launch compatibility with the actual live base

## Intent and invariants

The owner authorized production launch. Live build `432c6aab5fbdfb3c7bf37c5989db06369ea72c09`
is not an ancestor of accepted main `7aad3a93`. It already supplies private checks,
full-node traffic/quotas, client metadata and Boosty reliability. Preserve that
behavior while adding Corp; do not import the separate later TCP-outage PR324.
The daemon has not been replaced. A private consistent snapshot is being checked.

Integrate that exact live commit with the accepted Corp/artifact branch. Preserve
live migration `0070_server_traffic_limits.sql` byte-for-byte. It is applied on the
live inventory, whose current Corp tables are absent. Rename the unreleased,
not-deployed `0070_corp_policy.sql` to `0071_corp_policy.sql` without changing its schema.
Do not edit live migration history or run hand-written schema fixes on production.
Retain the newer reviewed SQLite security dependency floor on conflicts and all
independent tests from both branches; regenerate only the derived inventory map.

## Independent migration verification

Add inventory tests from this contract only, without reading implementation.
SqliteInventory::open(&Path).await runs ordinary migrations; the existing public
user/server/grant APIs and Corp store APIs are in the neighboring store specs.
SQLx0.8 Migrator may prepare a legacy fixture using versions1..69 from the
repository's unchanged migration files, then apply the frozen production70 SQL
and register its original checksum as a successful sqlx migration. Freeze that
SQL/checksum in the test fixture, rather than reading the new Corp implementation
as the expected result. Root supplies the original SQL below before test writing.
Public IDs are `vpnctl_core::UserId(pub String)` and `ServerId(pub String)`;
they are string identifiers, not UUID parsers. Legacy data can be seeded/asserted
with the unchanged SQL fixtures and SQLx directly.

Required cases: legacy70 -> open succeeds and adds Corp tables with binding absent;
legacy user/subscription/grant/traffic-limit data and migration70 checksum survive;
fresh open creates both traffic columns and Corp tables; reopen is idempotent;
normal Corp setup remains disabled with revision0 after legacy upgrade. A changed
legacy70 checksum must still fail, never bypass SQLx validation. No live inventory,
secret, network or locally executed test belongs in this fixture.

## Gates and rollback

Resolve only source merge conflicts; review the combined source and migration
boundary independently. Run all canonical CI, browser, static musl, managed
runtime and legacy migration tests at one exact SHA before deployment. Keep
artifact sets/manifest SHAs consistent. Rollback preserves current production
binaries and the verified pre-migration snapshot; no published revision exists
yet. No build/test runs on the control host or development workstation.


Frozen live migration70 SQL (original checksum SHA384
0825cd86fedec2dc342689a78d69d6ba6181c5a3c6adc281f5863566c92c07c0f0d008bc84109a071a9b0efd6c0916de):

```sql
-- Optional hoster quotas; do not assign an allowance to existing servers.
CREATE TABLE server_traffic_limits (
    server_id TEXT PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    limit_bytes INTEGER NOT NULL CHECK(limit_bytes > 0),
    direction TEXT NOT NULL CHECK(direction IN ('rx', 'tx', 'both')),
    reset_day INTEGER NOT NULL CHECK(reset_day BETWEEN 1 AND 31),
    warning_pct INTEGER NOT NULL CHECK(warning_pct BETWEEN 1 AND 100)
);
```

## Publication receipt

The exact live base is integrated, including quotas, private checks and client
metadata. Both independent diff-only reviews returned no important or critical
findings. The independent spec writer added four upgrade regressions, including
checksum rejection and preservation of legacy identities and quota/traffic rows.
Live migration70 and renamed Corp71 were compared byte-for-byte with their
respective source revisions; the retained snapshot passed integrity and foreign
key checks. No replacement daemon or migration has run on production.

Formatting, workflow lint, generated map/CSS, whitespace and staged secret checks
passed locally. Compilation and test execution are not run on this control host;
the combined source still requires exact-head canonical CI and the static musl
artifacts before deployment. Earlier green results at d37cd22 cover only the
pre-integration source and do not validate this merge.
