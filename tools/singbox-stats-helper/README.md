# singbox-stats-helper

Node-side, read-only client for sing-box's loopback V2Ray Stats API. It queries
cumulative inbound totals, per-user totals, and process uptime without resetting
counters, then prints one JSON object for vpnctld to ingest atomically.

```sh
./build.sh /tmp/singbox-stats-helper
/tmp/singbox-stats-helper --address 127.0.0.1:10085 --timeout 5s
```

The managed sing-box build must include the `with_v2ray_api` build tag and its
config must list the users and inbounds to count. The API remains bound to loopback. Errors
exit non-zero; user IDs and counter values are never written to stderr.
