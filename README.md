# vpnctl

A Linux control plane for self-hosted VPN servers: manage nodes, users and
subscriptions from one web admin UI, using SSH without a node-side agent.

**[Deployment guide](docs/specs/deployment.md)** ·
[Releases](https://github.com/PavelLizunov/vpnctl/releases) ·
[Full guide](docs/guide.md)

Linux x86_64 · Rust · SQLite · English and Russian admin UI.

[![CI](https://github.com/PavelLizunov/vpnctl/actions/workflows/ci.yml/badge.svg)](https://github.com/PavelLizunov/vpnctl/actions/workflows/ci.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2024%20edition-orange.svg)](Cargo.toml)
[![Platform](https://img.shields.io/badge/platform-Linux%20x86__64-lightgrey.svg)](docs/guide.md#project-size)

## What it does

- Add a server through the web wizard: paste its address and root password,
  then follow bootstrap, hardening and deployment progress.
- Create users and grant access; hand each user an importable subscription,
  QR code or native configuration file.
- Manage several VPN protocols and node kernels through one inventory.
  See the [supported combinations](docs/guide.md#architecture).
- Monitor current TCP availability, incident history, node health, traffic
  and historical service quality. TCP reachability is scoped to the named
  measurement network; it does not verify a VPN login or UDP.
- Review alerts and audit history, manage billing and optionally connect Boosty.
- Keep subscription identities in SQLite, with snapshot and encrypted
  disaster-recovery backup workflows.

The web UI is the operator surface. The CLI provides automation, scripting
and recovery commands. Existing client configurations have a
[compatibility contract](docs/specs/migration-compatibility.md).

## Quickstart

The [deployment contract](docs/specs/deployment.md) covers the controller
build, installation and runtime settings. The
[developer quickstart](docs/guide.md#quickstart) lists workspace checks and
CLI examples.

With the controller running, open the admin UI, use **Servers → Add server**,
then create a user and grant access from their page.

The [operator flows](docs/guide.md#operator-flows-all-web-driven) pair each
web action with its automation command. End-user import instructions are in
the [client setup guides](docs/CLIENT_GUIDES.md).

## Production health check

The [health and build-provenance guide](docs/guide.md#production-health-check)
explains the health endpoint, version suffix and production install paths.
Read the [deployment contract](docs/specs/deployment.md) before a rollout.

## Architecture

Node kernels and wire protocols are independent. Protocol rendering is
stateless; the inventory owns mutable state and server secrets.

- [Architecture and supported protocols](docs/guide.md#architecture)
- [Workspace layout](docs/guide.md#workspace-layout)
- [Standing architecture contract](docs/specs/architecture.md)

## Documentation

- [Full guide: features, build, operator flows and known gaps](docs/guide.md)
- [Specification index](docs/specs/README.md)
- [Commercial operations runbook (RU)](docs/specs/commercial-operations.md)
- [backup/restore contract](docs/specs/backup-restore.md)
- [Current TCP availability and incidents](docs/specs/current-path-availability.md)
- [Protocol testing](docs/PROTOCOL_TESTING.md)
- [Deferred work](BACKLOG.md)

## Development

[AGENTS.md](AGENTS.md) is the project instruction file. The
[agent workflow](docs/specs/agent-workflow.md) defines review and verification.
Run `just ci` for the canonical checks. See the
[SSH integration tests](docs/guide.md#ssh-integration-tests) for target checks.
Historical investigations are recoverable from Git history.

## License

[AGPL-3.0-or-later](LICENSE). Vendored components retain their own licences;
see [vendor provenance](vendor/README.md).
