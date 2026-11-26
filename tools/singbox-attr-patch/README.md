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
- `x86_64` (default): `sing-box-1.14.4-vpnctl.4-linux-amd64.tar.gz` (SHA256: `a6014cfad5494fe8fa3f178facad6a7c6dab59f5143f7b5af645e8e4e5d84094`)
- `aarch64` / `arm64`: `sing-box-1.14.4-vpnctl.4-linux-arm64.tar.gz` (SHA256: `281cd5214208147b869d654fd8d86ea7b77a61b312fc6112fb7e0d4ddd8beabf`)
- `armv7`: `sing-box-1.14.4-vpnctl.4-linux-armv7.tar.gz` (SHA256: `36fec164b839c707a086f9ff404af1ba7ab40cf4d532270b186444bc5d203fc0`)

The result is a static Linux binary (`x86_64`, `arm64`, or `armv7`) with version `1.14.4-vpnctl.4`.
This release uses sing-box 1.14.4 and supports per-user bandwidth overrides.
Release source: `de4d55ca046482cc3d90c3a97693651768020866`.
`1.14.0-vpnctl.3` must not be used for AWG3 client delivery.
Feature tags include `with_v2ray_api`, `with_clash_api`, `with_xhttp`, `with_awg`, and `with_turnrelay`.

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
