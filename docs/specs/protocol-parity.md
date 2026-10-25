# Contract: client/server protocol parity

## 1. Intent & Invariants

- Reject incompatible Caddy front protocols before saving, while retaining the
  renderer's refusal as a backstop.
- Legacy AmneziaWG server and clients use the same effective obfuscation values.
  Existing INI, `awg://` and client JSON output with complete parameter sets,
  and unrelated client output, retain their exact bytes. Peer addresses follow
  the [persisted address contract](wireguard-peer-addresses.md). AWG `vpn://` output
  deliberately adds the structured fields described below to repair imports.

## 2. Interface / Data Contract

- `Caddy::validate_server_support` rejects `naive` + `vless-ws` on one server.
  CLI validation and web protocol enabling call this hook before persistence.
  Rejection changes neither inventory nor audit history.
- `vpnctl_core::amneziawg::effective_params` resolves the nine legacy parameters
  in INI order, preserving supplied strings and filling missing keys with the
  existing server defaults: Jc=4, Jmin=40, Jmax=70, S1=50, S2=100, H1–H4=1–4.
- Clients include this block when the legacy `amneziawg` kernel is assigned or
  any legacy parameter exists. Plain WireGuard without either keeps no block.
- AmneziaVPN `vpn://` exports keep the `amnezia-wireguard` container and place
  these effective string values in its structured `wireguard.last_config` as
  `Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1`–`H4`, with boolean
  `isObfuscationEnabled: true`, alongside the text config. These names match
  [AmneziaVPN's protocol keys](https://github.com/amnezia-vpn/amnezia-client/blob/4.8.12.9/client/protocols/protocols_defs.h).
  Plain WireGuard exports retain their exact bytes without these fields.
- Bootstrap mints a random set for a new AWG server. A partial legacy set is
  completed with those effective defaults without rotating supplied values.
  Each inserted key is audited; repeated bootstrap writes no no-op audit rows.

## 3. Verification

- Both protocol enabling orders fail before persistence; each protocol alone
  remains supported. CLI uses the same registry/kernel validation hook.
- Partial sets, including ones missing H1, render identical server/client
  parameters. Complete client JSON, INI and share-link bytes remain pinned.
- AmneziaVPN links pin the complete envelope bytes for full, partial and
  kernel-default AWG parameters, and for unaffected plain WireGuard.
- Bootstrap completes partial sets, preserves existing keys and is idempotent.
