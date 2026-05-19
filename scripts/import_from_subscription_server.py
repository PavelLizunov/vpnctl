#!/usr/bin/env python3
"""Phase 2 of the ninitux subscription-server absorption — see
docs/COMPREHENSIVE_AUDIT_2026-05-19.md.

WHAT THIS DOES
==============
Reads per-(client, server) VLESS UUIDs out of subscription-server's
SQLCipher database on 192.168.0.207 and writes them into vpnctld's
`grants.client_uuid` column on 192.168.0.236 (the column added by
inventory migration 0016 in commit 89cd16c). The net effect:
vpnctld's /sub/<token> renders the EXACT SAME UUIDs that ninitux'
/api/v1/app/config/<device_id> returns today, for every (user,
server) pair that exists in both systems.

After this script runs cleanly, both endpoints serve byte-equivalent
share-links for the overlapping user set. Phase 3 then puts a
byte-equivalent /api/v1/app/config/ Rust handler on vpnctld and
Phase 5 cuts ninitux nginx over to it.

INVARIANTS
==========
* DRY-RUN BY DEFAULT. Pass --apply to actually write. Without
  --apply the script prints the plan + summary and exits 0.

* Naming join: subscription-server's `clients.name` must match
  vpnctld's `users.id` for the row to be imported. A miss is
  logged as MISSING_USER and skipped (operator must decide whether
  to add the user in vpnctld first or accept the divergence).

* Server name join: subscription-server's `servers.name` must
  match vpnctld's `servers.id`. Mismatches → MISSING_SERVER, skip.
  vps-nk-01 (only in subscription-server, per «Вариант A»):
  expected to land in MISSING_SERVER and is fine to skip.

* Per-row transaction: every (user, server) update commits its
  own SQLite transaction (UPDATE grants + INSERT audit_log). A
  failure on row N rolls back row N only; rows 0..N-1 stay
  committed. Resumable.

* No grant creation. If a (user, server) grant doesn't exist in
  vpnctld but the same pair exists in subscription-server, the
  row is reported as MISSING_GRANT and skipped. The operator
  must grant() first (via web UI or the bash project's old script
  if they prefer) — script never silently materialises a grant.

* No user creation. Same reasoning.

* Audit row format matches `SqliteInventory::set_grant_client_uuid`
  exactly so a /admin/audit reader can't tell whether the change
  came from the Rust path or this script.

USAGE
=====
Dry-run from the claude-chat container (or anywhere with SSH to
both 192.168.0.207 and 192.168.0.236):

    python3 scripts/import_from_subscription_server.py

Apply for real:

    python3 scripts/import_from_subscription_server.py --apply

Use --source-host / --target-host to override the SSH targets.
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Iterable


# ── Strict input validators ─────────────────────────────────────
#
# The apply paths below build SQL via f-string interpolation (because
# `sudo sqlite3 <file>` over SSH has no parameterised-query channel).
# Every value that lands in the SQL MUST pass through one of these
# regexes — a stray single-quote in `client_name` would otherwise
# inject DDL into the inventory DB running as root. The 33 production
# names in subscription-server today are all `[A-Za-z0-9._-]+`, so
# this is a tight gate that doesn't reject any real data. New clients
# in subscription-server inheriting names with quotes / control chars
# would FAIL LOUDLY here instead of silently corrupting the audit log.
_RE_USER_NAME = re.compile(r'^[A-Za-z0-9._-]+\Z')
_RE_SERVER_NAME = re.compile(r'^[A-Za-z0-9._-]+\Z')
_RE_UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')
_RE_DEVICE_ID = re.compile(r'^[0-9a-f]{32}\Z')


def _assert_safe(value: str, pattern: re.Pattern, label: str) -> None:
    if not pattern.match(value):
        raise ValueError(
            f'{label}={value!r} failed strict shape check '
            f'(pattern={pattern.pattern!r}); refusing to interpolate into SQL'
        )


# ── SSH multiplexing (ControlMaster) ────────────────────────────
#
# The script makes O(N) SSH calls (one per CHANGE row + a few setup
# queries). On a flaky network each fresh TCP handshake risks a
# Connection-Timed-Out failure that aborts the whole run — caught
# live on 2026-05-19 trying to apply 23 rows from claude-chat to
# 192.168.0.236. ControlMaster keeps a single TCP+SSH session alive
# for the script's lifetime; all subsequent calls go through it.

_SSH_CONTROL_DIR: str | None = None


def ssh_base_opts() -> list[str]:
    """SSH options that enable ControlMaster reuse. Caller appends
    `user@host` + remote-command after these."""
    global _SSH_CONTROL_DIR
    if _SSH_CONTROL_DIR is None:
        _SSH_CONTROL_DIR = tempfile.mkdtemp(prefix='vpnctl-import-ssh-')
        atexit.register(_teardown_ssh_master)
    socket = os.path.join(_SSH_CONTROL_DIR, 'cm-%r@%h:%p')
    return [
        'ssh',
        '-o', 'BatchMode=yes',
        '-o', 'ConnectTimeout=15',
        '-o', f'ControlPath={socket}',
        '-o', 'ControlMaster=auto',
        '-o', 'ControlPersist=300',
    ]


def _teardown_ssh_master() -> None:
    """Drop any persistent ControlMaster sockets on script exit."""
    if not _SSH_CONTROL_DIR or not os.path.isdir(_SSH_CONTROL_DIR):
        return
    for entry in os.listdir(_SSH_CONTROL_DIR):
        full = os.path.join(_SSH_CONTROL_DIR, entry)
        try:
            os.unlink(full)
        except OSError:
            pass
    try:
        os.rmdir(_SSH_CONTROL_DIR)
    except OSError:
        pass


# ── Source extraction (subscription-server on 207) ──────────────

SOURCE_EXTRACT_PY = r"""
import json
import os
import sys
from sqlcipher3 import dbapi2 as sqlite

key = os.environ.get('DB_ENCRYPTION_KEY')
if not key:
    print('ERR: DB_ENCRYPTION_KEY not set in subscription-server container', file=sys.stderr)
    sys.exit(2)

conn = sqlite.connect('/data/subscriptions.db')
cur = conn.cursor()
cur.execute(f"PRAGMA key = \"x'{key}'\"")

# Server-id → server-name map.
servers = dict(cur.execute('SELECT id, name FROM servers').fetchall())

# Active client_server_links rows joined with the client's name + device_id.
rows = cur.execute('''
    SELECT c.name, c.device_id, csl.server_id, csl.client_uuid
    FROM client_server_links csl
    JOIN clients c ON c.device_id = csl.device_id
    WHERE c.active = 1
    ORDER BY c.name, csl.server_id
''').fetchall()

# clients table — for the device_id-only sync (Phase 3 column
# `users.vpn_router_device_id`). Includes clients with no grants too,
# since a registered-but-ungranted client is still a valid
# /api/v1/app/config/<device_id> lookup target (returns empty config).
clients = cur.execute(
    'SELECT name, device_id FROM clients WHERE active = 1 ORDER BY name'
).fetchall()

out = {
    'grants': [
        {
            'user_name': name,
            'device_id': did,
            'server_name': servers.get(sid, f'server-id-{sid}'),
            'client_uuid': cu,
        }
        for (name, did, sid, cu) in rows
    ],
    'clients': [
        {'user_name': name, 'device_id': did}
        for (name, did) in clients
    ],
}
json.dump(out, sys.stdout, separators=(',', ':'))
"""


def fetch_source(host: str) -> dict:
    """SSH to `host`, exec the subscription-server container's
    Python, run SOURCE_EXTRACT_PY via stdin, parse the JSON output.
    Returns dict with two keys: `grants` (per-server-link rows) and
    `clients` (per-user device_id rows)."""
    cmd = ssh_base_opts() + [host, 'sudo docker exec -i subscription-server python3']
    result = subprocess.run(
        cmd,
        input=SOURCE_EXTRACT_PY,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        print(f'source fetch failed (exit={result.returncode})', file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(2)
    return json.loads(result.stdout)


# ── Target inspection (vpnctld on 236) ───────────────────────────

INVENTORY_DB_PATH = '/var/lib/vpnctl/inv.db'


def _ssh_sqlite(host: str, sql: str, *, dot_commands: str = '') -> str:
    """Execute SQL on the inventory DB via SSH + sqlite3 CLI.

    sudo because /var/lib/vpnctl/ is owned by the vpnctld service
    user. Output mode is `-cmd '.mode tabs' -cmd '.headers off'` so
    we can split on \\t. `dot_commands` lets the caller force a
    different mode (e.g. .schema)."""
    base = f'sudo sqlite3 {INVENTORY_DB_PATH}'
    if dot_commands:
        cmd_str = f'{base} {shlex.quote(dot_commands)} {shlex.quote(sql)}'
    else:
        cmd_str = f"{base} -cmd '.mode tabs' -cmd '.headers off' {shlex.quote(sql)}"
    cmd = ssh_base_opts() + [host, cmd_str]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode != 0:
        raise RuntimeError(f'sqlite3 exit={result.returncode}: {result.stderr.strip()}')
    return result.stdout


def fetch_target_state(
    host: str,
) -> tuple[
    set[str],
    set[str],
    dict[tuple[str, str], str | None],
    dict[str, str | None],
]:
    """Return (user_ids, server_ids, {(user, server): client_uuid_or_None},
    {user_id: vpn_router_device_id_or_None})."""
    users = {
        line.strip()
        for line in _ssh_sqlite(host, 'SELECT id FROM users').splitlines()
        if line.strip()
    }
    servers = {
        line.strip()
        for line in _ssh_sqlite(host, 'SELECT id FROM servers').splitlines()
        if line.strip()
    }
    grants: dict[tuple[str, str], str | None] = {}
    for line in _ssh_sqlite(
        host,
        "SELECT user_id, server_id, COALESCE(client_uuid, '') FROM grants",
    ).splitlines():
        if not line:
            continue
        parts = line.split('\t')
        if len(parts) != 3:
            continue
        uid, sid, cu = parts
        grants[(uid, sid)] = cu or None
    device_ids: dict[str, str | None] = {}
    for line in _ssh_sqlite(
        host,
        "SELECT id, COALESCE(vpn_router_device_id, '') FROM users",
    ).splitlines():
        if not line:
            continue
        parts = line.split('\t')
        if len(parts) != 2:
            continue
        uid, did = parts
        device_ids[uid] = did or None
    return users, servers, grants, device_ids


# ── Plan + apply ────────────────────────────────────────────────


@dataclass
class PlanRow:
    user: str
    server: str
    src_uuid: str
    cur_uuid: str | None
    action: str  # MATCH / CHANGE / MISSING_USER / MISSING_SERVER / MISSING_GRANT


@dataclass
class DeviceIdPlanRow:
    """Phase 3 — per-user `users.vpn_router_device_id` sync. Separate
    plan from grants because device_id lookup is per-user (not
    per-(user, server)) and the failure modes differ — a user with
    no grants can still be a valid device_id lookup target (returns
    empty config). """

    user: str
    src_device_id: str
    cur_device_id: str | None
    action: str  # MATCH / SET / DRIFT / MISSING_USER


def build_plan(
    source_rows: Iterable[dict],
    users: set[str],
    servers: set[str],
    grants: dict[tuple[str, str], str | None],
) -> list[PlanRow]:
    plan: list[PlanRow] = []
    for row in source_rows:
        user = row['user_name']
        server = row['server_name']
        src = row['client_uuid']
        if user not in users:
            plan.append(PlanRow(user, server, src, None, 'MISSING_USER'))
            continue
        if server not in servers:
            plan.append(PlanRow(user, server, src, None, 'MISSING_SERVER'))
            continue
        cur = grants.get((user, server))
        if (user, server) not in grants:
            plan.append(PlanRow(user, server, src, None, 'MISSING_GRANT'))
            continue
        if cur == src:
            plan.append(PlanRow(user, server, src, cur, 'MATCH'))
        else:
            plan.append(PlanRow(user, server, src, cur, 'CHANGE'))
    return plan


def build_device_id_plan(
    source_clients: Iterable[dict],
    users: set[str],
    device_ids: dict[str, str | None],
) -> list[DeviceIdPlanRow]:
    plan: list[DeviceIdPlanRow] = []
    for row in source_clients:
        user = row['user_name']
        src = row['device_id']
        if user not in users:
            plan.append(DeviceIdPlanRow(user, src, None, 'MISSING_USER'))
            continue
        cur = device_ids.get(user)
        if cur is None:
            plan.append(DeviceIdPlanRow(user, src, None, 'SET'))
        elif cur == src:
            plan.append(DeviceIdPlanRow(user, src, cur, 'MATCH'))
        else:
            # Different device_id pinned. Rare — would happen if the
            # operator rotated device_id in subscription-server between
            # two runs of this script. NOT auto-fixed because rotating
            # device_id breaks every issued share-link URL — needs
            # explicit operator intent.
            plan.append(DeviceIdPlanRow(user, src, cur, 'DRIFT'))
    return plan


def print_plan(plan: list[PlanRow]) -> dict[str, int]:
    counts: dict[str, int] = {}
    rows_by_action: dict[str, list[PlanRow]] = {}
    for row in plan:
        counts[row.action] = counts.get(row.action, 0) + 1
        rows_by_action.setdefault(row.action, []).append(row)

    print('\n=== Phase 2 import plan ===')
    for action in (
        'CHANGE',
        'MISSING_USER',
        'MISSING_SERVER',
        'MISSING_GRANT',
        'MATCH',
    ):
        rows = rows_by_action.get(action, [])
        print(f'\n[{action}] {len(rows)} row(s)')
        for r in rows[:50]:
            cur = r.cur_uuid or '(none)'
            print(f'  {r.user:<24} {r.server:<12} {cur:<40} → {r.src_uuid}')
        if len(rows) > 50:
            print(f'  ... {len(rows) - 50} more')

    print('\n--- summary ---')
    for action, n in sorted(counts.items()):
        print(f'  {action:<16} {n}')
    return counts


def print_device_id_plan(plan: list[DeviceIdPlanRow]) -> dict[str, int]:
    counts: dict[str, int] = {}
    rows_by_action: dict[str, list[DeviceIdPlanRow]] = {}
    for row in plan:
        counts[row.action] = counts.get(row.action, 0) + 1
        rows_by_action.setdefault(row.action, []).append(row)

    print('\n=== Phase 3 device_id plan ===')
    for action in ('SET', 'DRIFT', 'MISSING_USER', 'MATCH'):
        rows = rows_by_action.get(action, [])
        print(f'\n[{action}] {len(rows)} row(s)')
        for r in rows[:50]:
            cur = r.cur_device_id or '(none)'
            print(f'  {r.user:<24} {cur:<35} → {r.src_device_id}')
        if len(rows) > 50:
            print(f'  ... {len(rows) - 50} more')

    print('\n--- device_id summary ---')
    for action, n in sorted(counts.items()):
        print(f'  {action:<16} {n}')
    return counts


def apply_device_id_changes(host: str, plan: list[DeviceIdPlanRow]) -> int:
    """For every SET row, run UPDATE users + INSERT audit_log in a
    single SQLite transaction over SSH. DRIFT rows are NOT applied —
    operator intervention required."""
    applied = 0
    for row in plan:
        if row.action != 'SET':
            continue
        _assert_safe(row.user, _RE_USER_NAME, 'user')
        _assert_safe(row.src_device_id, _RE_DEVICE_ID, 'device_id')
        # Key order matches Rust's `set_vpn_router_device_id` audit
        # payload — alphabetical via `sort_keys=True` (same reasoning
        # as the grant.set_client_uuid path above: Rust's
        # `serde_json::json!` uses a BTreeMap, so the wire format is
        # always alphabetical).
        payload = json.dumps(
            {
                'old_vpn_router_device_id': row.cur_device_id,
                'new_vpn_router_device_id': row.src_device_id,
            },
            separators=(',', ':'),
            sort_keys=True,
        )
        sql_script = (
            'BEGIN IMMEDIATE;\n'
            f"UPDATE users SET vpn_router_device_id = '{row.src_device_id}' "
            f"WHERE id = '{row.user}';\n"
            "INSERT INTO audit_log (actor, action, target, payload) "
            "VALUES ('phase3-import', 'user.set_vpn_router_device_id', "
            f"'{row.user}', '{payload.replace(chr(39), chr(39) + chr(39))}');\n"
            'COMMIT;\n'
        )
        cmd = ssh_base_opts() + [host, f'sudo sqlite3 {INVENTORY_DB_PATH}']
        result = subprocess.run(
            cmd, input=sql_script, capture_output=True, text=True, timeout=15, check=False,
        )
        if result.returncode != 0:
            print(
                f'ERROR on {row.user}: exit={result.returncode}: {result.stderr.strip()}',
                file=sys.stderr,
            )
            print('aborting; rows committed before this one stay applied', file=sys.stderr)
            return applied
        applied += 1
        print(f'  applied  {row.user:<24} → {row.src_device_id}')
    return applied


def apply_changes(host: str, plan: list[PlanRow]) -> int:
    """For every CHANGE row, run UPDATE grants + INSERT audit_log
    in a single SQLite transaction over SSH. One BEGIN…COMMIT per
    row (cheap; keeps vpnctld writer-lock contention minimal).

    Every interpolated value is gated through `_assert_safe` first —
    a row that fails validation raises ValueError before any SQL is
    sent, so a malformed name in subscription-server can't inject
    DDL into the inventory DB running as root."""
    applied = 0
    for row in plan:
        if row.action != 'CHANGE':
            continue
        _assert_safe(row.user, _RE_USER_NAME, 'user')
        _assert_safe(row.server, _RE_SERVER_NAME, 'server_id')
        _assert_safe(row.src_uuid, _RE_UUID, 'client_uuid')
        # Key order matches Rust's `set_grant_client_uuid` audit
        # payload. The Rust path builds the payload via
        # `serde_json::json!` whose underlying `serde_json::Map` is a
        # `BTreeMap` (no `preserve_order` feature) and therefore
        # emits keys in ALPHABETICAL order. `sort_keys=True` aligns
        # Python's output, so a /admin/audit reader sees byte-
        # identical JSON regardless of writer. Verified by
        # `audit_payload_has_alphabetical_key_order_for_byte_equality_with_python`.
        payload = json.dumps(
            {
                'server_id': row.server,
                'old_client_uuid': row.cur_uuid,
                'new_client_uuid': row.src_uuid,
            },
            separators=(',', ':'),
            sort_keys=True,
        )
        sql_script = (
            'BEGIN IMMEDIATE;\n'
            f"UPDATE grants SET client_uuid = '{row.src_uuid}' "
            f"WHERE user_id = '{row.user}' AND server_id = '{row.server}';\n"
            "INSERT INTO audit_log (actor, action, target, payload) "
            "VALUES ('phase2-import', 'grant.set_client_uuid', "
            f"'{row.user}', '{payload.replace(chr(39), chr(39) + chr(39))}');\n"
            'COMMIT;\n'
        )
        cmd = ssh_base_opts() + [host, f'sudo sqlite3 {INVENTORY_DB_PATH}']
        result = subprocess.run(
            cmd, input=sql_script, capture_output=True, text=True, timeout=15, check=False,
        )
        if result.returncode != 0:
            print(
                f'ERROR on {row.user}/{row.server}: '
                f'exit={result.returncode}: {result.stderr.strip()}',
                file=sys.stderr,
            )
            print('aborting; rows committed before this one stay applied', file=sys.stderr)
            return applied
        applied += 1
        print(f'  applied  {row.user:<24} {row.server:<12} → {row.src_uuid}')
    return applied


# ── CLI ─────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument(
        '--source-host',
        default='user@192.168.0.207',
        help='SSH target running subscription-server (default: %(default)s)',
    )
    ap.add_argument(
        '--target-host',
        default='user@192.168.0.236',
        help='SSH target running vpnctld (default: %(default)s)',
    )
    ap.add_argument(
        '--apply',
        action='store_true',
        help='Write changes to the target inv.db (default: dry-run only)',
    )
    args = ap.parse_args()

    print(f'[1/5] fetching subscription-server rows from {args.source_host} …')
    src = fetch_source(args.source_host)
    print(
        f'      → {len(src["grants"])} (client, server, uuid) rows, '
        f'{len(src["clients"])} client device_ids'
    )

    print(f'[2/5] inspecting vpnctld inventory on {args.target_host} …')
    users, servers, grants, device_ids = fetch_target_state(args.target_host)
    print(
        f'      → {len(users)} users, {len(servers)} servers, '
        f'{len(grants)} grants, '
        f'{sum(1 for v in device_ids.values() if v)} users with vpn_router_device_id'
    )

    print('[3/5] building plans …')
    grant_plan = build_plan(src['grants'], users, servers, grants)
    dev_plan = build_device_id_plan(src['clients'], users, device_ids)
    grant_counts = print_plan(grant_plan)
    dev_counts = print_device_id_plan(dev_plan)

    n_change = grant_counts.get('CHANGE', 0)
    n_set = dev_counts.get('SET', 0)
    n_drift = dev_counts.get('DRIFT', 0)

    if n_drift:
        print(
            f'\n⚠  {n_drift} DRIFT row(s) require manual review — '
            'these users have a DIFFERENT vpn_router_device_id pinned in vpnctld '
            'than subscription-server currently advertises. Not auto-applied. '
            'Resolve with `UPDATE users SET vpn_router_device_id=NULL WHERE id=...` '
            'first, then re-run.'
        )

    total_writes = n_change + n_set
    if not args.apply:
        print(
            f'\nDry-run finished. Re-run with --apply to write '
            f'{n_change} grant CHANGE + {n_set} device_id SET = '
            f'{total_writes} total.'
        )
        return 0

    if total_writes == 0:
        print('\nNothing to apply.')
        return 0

    applied_grants = applied_dev = 0
    if n_change:
        print(f'\n[4/5] applying {n_change} grant change(s) to {args.target_host} …')
        applied_grants = apply_changes(args.target_host, grant_plan)
        print(f'      → {applied_grants}/{n_change} grant CHANGE rows applied')
    if n_set:
        print(f'\n[5/5] applying {n_set} device_id SET(s) to {args.target_host} …')
        applied_dev = apply_device_id_changes(args.target_host, dev_plan)
        print(f'      → {applied_dev}/{n_set} device_id rows applied')

    success = applied_grants == n_change and applied_dev == n_set
    print(f'\nDone. Grants: {applied_grants}/{n_change}  device_ids: {applied_dev}/{n_set}')
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
