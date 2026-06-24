# vpnctl backlog

Deferred work items with enough context to pick up cold. Newest first.

## v2ray stats → billing-grade per-user attribution (Go helper)

**Status:** deferred (not needed now). Current clash-snapshot polling at 60 s
attributes **84–99 %** of bytes per user across all nodes — enough for
"who eats the traffic".

**Problem it would solve.** clash `/connections` is a snapshot of *active*
connections. Bytes from connections that open+close *between* polls are counted
in the server total but never sampled per-user → a residual sampling-ceiling gap
(worst on cdn / hysteria2 QUIC churn: ~84 %; VLESS nodes 88–99 %). Dropping the
poll interval to 60 s shrank the gap but cannot fully close it.

**Fix.** Enable sing-box `experimental.v2ray_api.stats` — **cumulative** per-user
uplink/downlink counters that survive connection close → no sampling gap, ~100 %
on every node including churny QUIC. Verified in sing-box v1.13.12 source
(`experimental/v2rayapi/stats.go` `RoutedConnection` / `RoutedPacketConnection`)
that the *same* counter mechanism already counts VLESS+vision and hysteria2 — the
clash per-connection bytes are already non-zero for both, so the vision/splice
worry is unfounded.

**Why deferred.** 84–99 % already answers the per-user question. The hoster bills
*wire* traffic (~2× payload + caddy / slipstream), reconciled via
`servers.usage_coefficient`, so exact per-user *payload* isn't needed for billing.

**Becomes worth doing when:**
- enforcing hard `users.monthly_bandwidth_limit_bytes` to the GB on churny nodes, or
- wanting to drop poll frequency back to 5 min (less node CPU / SSH) while keeping
  accuracy — cumulative counters don't need frequent sampling.

**Implementation — lean path (Go helper, NOT Rust gRPC):**
1. **Keep Rust untouched.** vpnctl SSH-execs a helper and parses its output,
   exactly like the current `curl 127.0.0.1:9090/connections` for clash. The gRPC
   weight stays isolated in a throwaway binary, off `Cargo.toml` / `cargo-deny`.
   (gRPC is heavy in *both* Go and Rust — the win is isolating it, not the language.)
2. **Helper** (`tools/singbox-stats-helper/`, ~60 lines Go): dials the local
   v2ray_api gRPC `StatsService`, `QueryStats` pattern `user>>>`, prints
   `name → {up, dn}` JSON. Reuses sing-box's own `stats.proto`. Built with the same
   Go toolchain/recipe as `tools/singbox-attr-patch`; static `CGO=0`; deployed per
   node like the patched sing-box.
3. **Config.** Render `experimental.v2ray_api.{listen, stats:{enabled, users:[…]}}`
   in `crates/kernels/src/sing_box.rs`. Per-user counting requires the user be
   listed (`countUser := user != "" && s.users[user]`) — mirror the inbound user
   list, which the config already re-renders on every user add/remove, so no new
   operational coupling. Bind the gRPC listener to loopback only.
4. **Poller.** Switch the per-user-row byte source in `daemon/src/clash_poller.rs`
   from the clash snapshot to the helper's cumulative per-user totals (diff vs
   prior — same shape as today). `DiffEngine` already handles cumulative counters +
   restart detection; the server-wide-remainder logic is unchanged. The clash
   `/connections` poll can stay — it still feeds the live-connections drill-down,
   destinations, source IPs and sessions.
5. **First step:** 10-min spike on one node — temp `v2ray_api` config, confirm
   vision/hysteria2 counters increment as expected — before committing.

See also `tools/singbox-attr-patch/` (the clash `user` patch this builds on).
