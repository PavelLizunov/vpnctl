# Corp launch artifact delivery

The owner authorized launch on2026-11-15 after PR323 and VPNRouter PR675 passed
CI and were merged. Backend accepted merge is7aad3a93; client target isbusiness,
notmain. Preserve unrelated VPNctl users/services and private client identities.

Production has2CPU/1966MiB RAM and cannot safely host a full release compile.
Linux101 has the SDK but only4.54GiB free at94% disk use; its lease was released
without a build. Use existing exact-SHA GitHub CI release jobs, retaining their
already built executables/assets as artifacts rather than provisioning SDKs or
deleting shared caches. No credentials/private provisioning enter CI artifacts.

Retain two artifact sets after their respective gates pass: static musl daemon,
CLI and matching admin assets; managed sing-box and its stats helper. Each set
has source-sha.txt and SHA256SUMS. Stamp the Rust build with VPNCTL_BUILD_SHA.
The existing deploy script still stages all four binaries and matching assets
atomically. Artifacts from different source SHAs cannot be combined.

Verification: actionlint, formatting/map/whitespace/secret checks locally;
independent diff review; all normal exact-SHA CI. Then compare artifact manifests,
verify recovery snapshot, deploy through scripts/deploy.sh and check the live
health build, operator/Corp ingress and authenticated probe behavior. No local
builds. Preserve previous binaries/configuration and use an inventory backup
for migration recovery; do not lower a published policy revision during rollback.
