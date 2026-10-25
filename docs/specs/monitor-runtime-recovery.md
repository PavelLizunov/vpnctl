# Contract: Monitor recovery and shutdown

## Intent & Invariants

- Successful node probes recover an open `server.unreachable` alert from the database even when the daemon has lost its in-memory failure counters.
- Extra steady health samples must not hide the latest service transition. Replayed source events must not create duplicate alerts or audit rows.
- Transient notification failures get bounded retries. Graceful HTTP shutdown drains already-queued subscription access records before the runtime exits.
- Automatic health remediation uses the same per-node operation lock as deploy and never waits for a busy node.

## Interface / Data Contract

- The health monitor selects the latest transition for each condition in its existing 24-hour sample window, keeping the transition's original sample IDs for deduplication.
- Health sample ordering, latest health and kernel versions, NIC counter deltas, and last probe/outage selection use monotonic `sample_seq`, not wall-clock `ts`. Time windows still use `ts`. Fleet latest lookups seek one sample per server through the `(server_id, sample_seq)` index.
- With automatic remediation enabled, open supported condition alerts are retried independently of alert insertion, including when no transition remains in the sample window. Each alert gets at most one attempt per scan and no more than one per 60 seconds, measured by a monotonic clock. Retry times are in memory and reset on daemon restart.
- After acquiring `DeployGuard`, remediation re-reads the server and latest health sample. A missing server, disabled required kernel, recovered condition, or unknown health skips the action without a remediation audit row. The guard remains held through the remote action, verification, and recovery recording.
- One-shot restart insertion atomically ignores an already-recorded `_source_event` for the same kind and server, including acknowledged history. A distinct source remains eligible.
- An immediate alert push still attempts delivery at most three times, waiting 30 seconds between failures. Migration `0069_alert_delivery_state.sql` adds delivery bookkeeping to `admin_alerts`: `telegram_delivered_at`, `telegram_attempts`, `telegram_next_attempt_at`, and `telegram_gave_up_at`. `telegram_attempts` counts delivery rounds (the initial round includes its existing three transport attempts).
- The digest scheduler checks delivery every minute, including on startup. Only open, undelivered alerts younger than 24 hours are retried, with one transport attempt per round and exponential delay after failed rounds: 1, 2, 4, 8, 16, 32, then 60 minutes. At 24 hours from alert creation, delivery is abandoned and `telegram_gave_up_at` is recorded; the alert remains open. Delivery bookkeeping writes no audit rows.
- A round atomically reserves the alert for five minutes before sending, so immediate and scheduled sends do not overlap. An interrupted round becomes eligible after that reservation expires. An alert interrupted before its first round becomes eligible five minutes after creation. State survives daemon restart. Telegram-disabled ticks perform no delivery or bookkeeping.
- Success records `telegram_delivered_at` even when the sink returns no message ID, saves any returned ID for edit-on-recover, and clears the next attempt. Delivered alerts are never resent. Migration marks existing message IDs as delivered. Acknowledged one-shot events retain their immediate push but do not receive later retries. Telegram delivery remains at-least-once: a crash after Telegram accepts a message but before the database records success can duplicate it.
- `build(DaemonConfig)` returns `(Router, JoinHandle<()>)`; the handle belongs to the access-log writer. After HTTP serving finishes and releases the router, the binary awaits this handle for up to 10 seconds. On timeout it logs the incomplete drain and aborts the writer.

## Verification Checklist

- [ ] A fresh failure tracker recovers a database-backed unreachable alert exactly once.
- [ ] `true, false, false, false` raises one service-down alert; later steady healthy samples recover it.
- [ ] Repeated scans and an inventory reopen preserve one restart event and one fire audit row per source.
- [ ] The immediate push retains three attempts; after their failure, reopening inventory and a later scheduler tick retry delivery and record success without further resends.
- [ ] Backoff doubles from one minute to one hour, then stays capped. Delivery stops at 24 hours and records expiry exactly once, leaving the alert open.
- [ ] Disabled Telegram sends nothing and changes no delivery state. Acknowledged and delivered alerts are not retried; existing message IDs survive migration without resends.
- [ ] Concurrent claims reserve at most one delivery round. Abandoned reservations become eligible after five minutes. Success without a message ID is final; delivery bookkeeping and its no-ops do not add audit rows.
- [ ] Dropping router senders and awaiting the writer persists multiple queued batches.
- [ ] Busy node locks skip immediately; a completed deploy that disabled sing-box or recorded recovery prevents a stale restart. Eligible remediation holds both deploy and process locks and uses the current server connection settings.
- [ ] A busy-lock skip is retried on later scans without duplicate alerts or fire audit rows; scans inside the minimum retry interval skip the attempt.
- [ ] A backwards clock step preserves insertion order and latest health, kernel versions, probe/outage selection, and NIC deltas. Fleet latest results equal individual latest lookups and omit servers without samples.
