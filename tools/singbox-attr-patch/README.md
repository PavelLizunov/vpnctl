# sing-box clash-api `user` patch (NM-11 fix)

Restores **per-user traffic attribution** in vpnctl's clash poller.

## The problem (NM-11)

Upstream sing-box's clash-api `/connections` response omits the
per-connection `user` field — `experimental/clashapi/trafficontrol/tracker.go`
builds the JSON metadata map by hand and simply never includes it, even
though `adapter.InboundContext` carries `User`.

vpnctl attributes traffic per user by reading `connection.metadata.user`
from that response. With the field absent, **~70 % of traffic on busy
nodes landed unattributed** (server-wide `user_id = NULL` rows). The old
work-around — scraping the sing-box on-disk log to correlate
`(source_ip, source_port) → user` — was defeated by client-side **mux**
(one physical connection carries many logical streams whose accept lines
have different conn-ids) and by long-lived connections whose accept line
had scrolled out of the tail window. It also pulled the full
multi-hundred-MB log over SSH every poll.

## The fix

One line — add `user` to the marshalled metadata map (`clash-user.patch`):

```go
"user": t.Metadata.User,
```

Now every connection in `/connections` carries its inbound user, so the
poller reads it straight off the wire (100 % attribution, mux-proof). The
log scraper was removed from the daemon as a result.

## Build

Needs Go >= 1.25.x. Produces a static linux/amd64 binary:

```bash
SINGBOX_VERSION=1.13.12 ./build.sh
```

The feature tags match the SagerNet release minus `with_naive_outbound`
(needs CGO/cronet; unused by our nodes) and `with_musl` (CGO-only). See
`build.sh` for details.

## Deploy

Per node (amd64; SSH as root):

```bash
install -m 0755 sing-box-1.13.12-userattr /tmp/sb && \
  /tmp/sb check -D /var/lib/sing-box -C /etc/sing-box && \   # gate
  cp -a /usr/bin/sing-box /usr/bin/sing-box.orig-1.13.12 && \ # rollback copy
  install -m 0755 /tmp/sb /usr/bin/sing-box && \
  systemctl restart sing-box && \
  apt-mark hold sing-box                                      # block apt clobber
```

Verify: `curl -s 127.0.0.1:9090/connections | jq '.connections[0].metadata|has("user")'`
should be `true`.

Rollback: `cp -a /usr/bin/sing-box.orig-1.13.12 /usr/bin/sing-box && systemctl restart sing-box`.

## Durability notes

- `apt-mark hold sing-box` stops a system `apt upgrade` from replacing the
  binary. vpnctl's install gate (`SING_BOX_MIN_VERSION`) compares
  `dpkg --compare-versions` — `1.13.12-userattr` sorts **≥** `1.13.12`, so
  `vpnctl deploy` / `update-kernels` will not reinstall it.
- **Re-apply on sing-box upgrade:** when bumping `SING_BOX_MIN_VERSION`,
  rebuild this patch at the new tag and redeploy the patched binary before
  (or instead of) letting apt install the stock one.
- **New nodes:** until the patched binary is wired into vpnctl's installer,
  a freshly-deployed node runs stock sing-box and reports 0 per-user
  attribution (the daemon's `sub_access_log` fallback still gives a partial
  online badge). Apply this patch as part of node bring-up.
