# vpnctl managed sing-box build

vpnctl ships a managed sing-box node binary for exact per-user traffic
accounting while preserving Clash API live metadata.

## Why a managed build exists

The stock Clash API exposes cumulative server totals and active connections,
but stock sing-box omits `metadata.user`. Snapshot attribution consequently
loses connections that open and close between polls. More importantly, the
V2Ray Stats API that provides cumulative per-user counters is not included in
the default sing-box build.

The managed build therefore makes two narrow changes:

1. enables the upstream `with_v2ray_api` build tag; and
2. applies `clash-user.patch`, a one-line live-metadata patch adding
   `"user": t.Metadata.User` to `/connections` JSON.

V2Ray Stats is the byte-accounting source. The Clash field remains useful for
live connection/session/source/destination views; accounting correctness no
longer depends on observing every connection snapshot.

## Build

Requires Go 1.25 or newer, Git, and network access:

```bash
SINGBOX_VERSION=1.13.19 OUT=/tmp/sing-box ./build.sh
```

The result is a static linux/amd64 binary whose version suffix is `-vpnctl`.
Feature tags match the required SagerNet features plus `with_v2ray_api`, minus
CGO-only `with_naive_outbound` and `with_musl`.

## Packaging and node installation

`scripts/deploy.sh` builds or accepts this binary together with vpnctld, vpnctl,
and `singbox-stats-helper`, validates all four inputs, and atomically installs
them on the control plane. A subsequent web/CLI node deployment uploads both
managed node artifacts over the existing pinned SSH transport.

The kernel installer validates the build tag and current config, keeps the
first replaced package binary as `/usr/bin/sing-box.vpnctl-stock`, preserves the
immediately previous managed binary/helper pair for automatic rollback, and
holds the APT package so an unattended upgrade cannot silently remove
accounting support. No client links
or subscription artifacts change.

The Stats API listens only on `127.0.0.1:10085`. The existing Clash API remains
on `127.0.0.1:9090`; neither listener is exposed publicly.

Production rollout and service restarts require a separate operator-approved
deployment after CI passes.
