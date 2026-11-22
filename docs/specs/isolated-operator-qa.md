# Isolated operator QA

## Intent and invariants

Run the released Linux vpnctl admin UI against synthetic inventory. Each stand owns an empty database, deploy key, backups and an ephemeral SSH node. The controller and node share a private network namespace with loopback only. Neither mounts the operator's home, SSH agent, production state or Docker socket. The desktop reaches the controller through a private Unix socket forwarded to an explicitly loopback-only port. The manual stand survives browser checks. Each automated run starts and disposes its own stand. Use a trusted, unpacked CI candidate containing bin/vpnctl, bin/vpnctld and assets.

## Interface and data contract

Run `tools/qa/qa.py serve` for manual use, `tools/qa/qa.py run` for all browser scenarios and `tools/qa/qa.py mcp` for MCP over stdio. Set `VPNCTL_QA_BUNDLE` to the unpacked release. Browser runs use fresh Chromium profiles. Seed server `qa-node` and users `qa-alice`, `qa-bob`. Test tools accept no URL, host, credentials, commands, database paths or browser selectors. The two MCP tools are `qa_catalog()` and `qa_run(suite)`. The catalog returns JSON with `suites` equal to the ordered list `navigation, users, servers, settings`. A run takes one of these names or `all` and returns JSON with a nonempty `checks` list of objects with a name and a boolean `passed`. Input errors must fail before starting a stand. Results contain no page dumps, subscription tokens, passwords or SSH keys.

## Verification

Exercise the MCP handshake, discovery, invalid arguments and a full run. Verify SSH via the UI, server settings, user lifecycle and access, backup snapshot and restore self-test, audit/search, navigation and mobile layout. Check namespace interfaces and production isolation. Cover failure feedback for an offline node. Report unavailable external integrations and full VPN provisioning separately.
