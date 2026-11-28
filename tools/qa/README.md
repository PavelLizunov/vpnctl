# Local vpnctl operator QA

This Linux stand runs an unpacked vpnctl CI artifact and its matching assets. It creates a new inventory, deploy key and backup directory at every start. `qa-node` runs OpenSSH in its own filesystem, `qa-offline` exercises connection failure, and the inventory includes `qa-alice` and `qa-bob`. Bob starts with a 50 MiB traffic limit.

## Setup

Use a Linux workstation with Python 3.10+, OpenSSH client and server, Bash, iproute2, socat, Bubblewrap and util-linux with `unshare --map-auto`. The account needs subordinate UID and GID ranges and working user namespaces. Unpack a trusted candidate from the **Build candidate artifacts** workflow and verify its companion SHA-256 checksum.

```bash
export VPNCTL_QA_BUNDLE=/absolute/path/to/unpacked/candidate
python3 -m venv /tmp/vpnctl-qa-venv
/tmp/vpnctl-qa-venv/bin/pip install -r tools/qa/requirements.txt
/tmp/vpnctl-qa-venv/bin/playwright install chromium --only-shell
/tmp/vpnctl-qa-venv/bin/python tools/qa/qa.py serve
```

Open the printed loopback URL in a separate browser window. The stand lasts until the process stops. Use `serve --port 28741` for a stable address. Each browser run gets a separate disposable stand, so a run preserves the manual stand's data.

## Browser checks and MCP

```bash
/tmp/vpnctl-qa-venv/bin/python tools/qa/qa.py run --suite all
/tmp/vpnctl-qa-venv/bin/python tools/qa/test_mcp.py
```

The CLI prints one pass/fail result per operator journey and exits 1 for any failed expectation. A failed product expectation remains visible on subsequent runs. The checks cover menu links on desktop and mobile, search, audit export and filters, monitoring, Boosty help, users, subscriptions, traffic limits, server tabs, SSH, failed updates, protocol visibility, billing, appearance and backup restore verification.

Register the same interpreter and absolute script path as an MCP stdio command, with the bundle path in the server environment. For Codex:

```bash
codex mcp add vpnctl-qa --env "VPNCTL_QA_BUNDLE=$VPNCTL_QA_BUNDLE" -- \
  /tmp/vpnctl-qa-venv/bin/python "$PWD/tools/qa/qa.py" mcp
```

Call `qa_catalog({})` to list suites and `qa_run({"suite":"all"})` to execute them. Set the MCP client's tool timeout to at least 120 seconds for full runs on slower machines. The server returns check names and boolean outcomes. Setup errors are reported separately.

## What the stand exercises

The daemon, SSH node and automated browser use a network namespace containing only loopback. The desktop URL forwards through a private Unix socket into this namespace. Only the packaged binaries/assets and generated fixtures enter the controller. The node gets its generated host key and authorized public key. A full package install, live VPN handshake, payment, Telegram delivery, authenticated corporate HTTPS deployment and external reachability require additional fixtures. A passing SSH or subscription UI check covers only that stage.
