# Contract: Monitor recovery and shutdown

## Intent & Invariants

- Successful node probes recover an open `server.unreachable` alert from the database even when the daemon has lost its in-memory failure counters.
- Extra steady health samples must not hide the latest service transition. Replayed source events must not create duplicate alerts or audit rows.
- Transient notification failures get bounded retries. Graceful HTTP shutdown drains already-queued subscription access records before the runtime exits.

## Interface / Data Contract

- The health monitor selects the latest transition for each condition in its existing 24-hour sample window, keeping the transition's original sample IDs for deduplication.
- One-shot restart insertion atomically ignores an already-recorded `_source_event` for the same kind and server, including acknowledged history. A distinct source remains eligible.
- An alert push attempts delivery at most three times, waiting 30 seconds between failed attempts. A successful retry records the Telegram message ID through the existing delivery path. Retries are in memory and do not survive daemon shutdown.
- `build(DaemonConfig)` returns `(Router, JoinHandle<()>)`; the handle belongs to the access-log writer. After HTTP serving finishes and releases the router, the binary awaits this handle for up to 10 seconds. On timeout it logs the incomplete drain and aborts the writer.

## Verification Checklist

- [ ] A fresh failure tracker recovers a database-backed unreachable alert exactly once.
- [ ] `true, false, false, false` raises one service-down alert; later steady healthy samples recover it.
- [ ] Repeated scans and an inventory reopen preserve one restart event and one fire audit row per source.
- [ ] A transient sink failure is retried successfully; permanent failures stop after three attempts.
- [ ] Dropping router senders and awaiting the writer persists multiple queued batches.
