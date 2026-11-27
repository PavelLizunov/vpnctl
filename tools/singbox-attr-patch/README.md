# vpnctl managed sing-box build

vpnctl ships the hardened `sing-box-vpnctl` binary for exact per-user traffic
accounting, native AmneziaWG (2.0 and 3.1), XHTTP, TrustTunnel and Mieru.

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

Downloads the checksum-pinned Linux archive from sing-box-vpnctl
`v1.14.5-vpnctl.1` (revision `74153cb4e936af1b846cfa26053981daedd61f81`).
The release includes TrustTunnel and Mieru and excludes NaiveProxy outbound
and Cronet. CI and the candidate workflow use these published binaries.
CI also exercises the pinned source build.

```bash
# Download for the host architecture:
OUT=/tmp/sing-box ./build.sh

# Download the ARM64 archive on any host:
TARGET_ARCH=arm64 OUT=/tmp/sing-box-arm64 ./build.sh

# Rebuild the managed profile from the pinned revision with Go 1.26+:
FORCE_BUILD=1 OUT=/tmp/sing-box ./build.sh
```

Archive pins by target:

- `x86_64` (default): `sing-box-1.14.5-vpnctl.1-linux-amd64.tar.gz` (SHA256: `72a65339089f9f41a05d746f03c2ee0105878a91a373295a0fae2af07cd2b7d4`)
- `aarch64` / `arm64`: `sing-box-1.14.5-vpnctl.1-linux-arm64.tar.gz` (SHA256: `4e8963ca3400238938948dc730e081923d07ed24152653981f6604d73db0888e`)
- `armv7`: `sing-box-1.14.5-vpnctl.1-linux-armv7.tar.gz` (SHA256: `fe2d91bebf34d4f6d2bc3b60ab1a3f8b43d47b172eed496cb3dc0d2b00abfea3`)

Both modes produce a static Linux binary for the selected architecture. The
source build uses the managed profile and reports `1.14.5-vpnctl.1+74153cb4`.
The script checks the revision and feature tags when the host can execute
the target binary. The release supports per-user bandwidth overrides through
the managed Stats API. AWG 3.1 client delivery requires a managed build with
AWG 3.1 support.

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
