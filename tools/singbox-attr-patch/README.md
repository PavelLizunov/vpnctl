# vpnctl managed sing-box build

vpnctl ships the hardened `sing-box-vpnctl` binary for exact per-user traffic
accounting, native AmneziaWG (2.0 and 3.1) and XHTTP, while preserving Clash API live metadata.

## Why a managed build exists

The stock Clash API exposes cumulative server totals and active connections,
but stock sing-box omits `metadata.user`. Snapshot attribution consequently
loses connections that open and close between polls. More importantly, the
V2Ray Stats API that provides cumulative per-user counters is not included in
the default sing-box build.

`PavelLizunov/sing-box-vpnctl` resolves this with:

1. Upstream `with_v2ray_api` build tag enabled on all architectures;
2. Native AmneziaWG 2.0/3.1 (`with_awg`) and XHTTP (`with_xhttp`);
3. Live-metadata `"user": c.Metadata.User` in `/connections` JSON in `experimental/clashapi/connections.go`.

V2Ray Stats is the byte-accounting source. The Clash field remains useful for
live connection/session/source/destination views; accounting correctness no
longer depends on observing every connection snapshot.

## Acquire / Build

Downloads official verified release binaries by default (curl + sha256sum), or builds from source when `FORCE_BUILD=1`:

```bash
# Default (detects host architecture):
OUT=/tmp/sing-box ./build.sh

# Cross-acquisition for ARM64:
TARGET_ARCH=arm64 OUT=/tmp/sing-box-arm64 ./build.sh
```

Supported target architectures via `TARGET_ARCH`:
- `x86_64` (default): `sing-box-1.14.2-vpnctl.2-linux-amd64.tar.gz` (SHA256: `095a575fb412e5520b5c16449002073a5ba587646b96e3dddd2c59473d5be2d8`)
- `aarch64` / `arm64`: `sing-box-1.14.2-vpnctl.2-linux-arm64.tar.gz` (SHA256: `2758b44eda76465281e3c6d14b91dd5e6b5e9d50f549f8e3205cdc0a31c577d3`)
- `armv7`: `sing-box-1.14.2-vpnctl.2-linux-armv7.tar.gz` (SHA256: `85567a8809bed3abc0b385faa04c51c3edf976445f30dc0ef935bd4cb1f08c6f`)

The result is a static Linux binary (`x86_64`, `arm64`, or `armv7`) with version `1.14.2-vpnctl.2`.
This release updates sing-box to 1.14.2 and fixes reachable gRPC/SSH dependency vulnerabilities.
It retains CPS packet bounds, CRLF-safe AWG UAPI, cryptographic XHTTP session IDs and upload rejection teardown.
Release source: `f62085aa7cc0f3ee665ac3043d35698760a386e9`.
`1.14.0-vpnctl.3` must not be used for AWG3 client delivery.
Feature tags include `with_v2ray_api`, `with_clash_api`, `with_xhttp`, and `with_awg`.

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
