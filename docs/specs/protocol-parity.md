# Contract: client/server protocol parity

## 1. Intent & Invariants

- Reject incompatible Caddy front protocols before saving, while retaining the
  renderer's refusal as a backstop.
- Legacy AmneziaWG server and clients use the same effective obfuscation values.
  Complete parameter sets and unrelated client output retain their exact bytes.

## 2. Interface / Data Contract

- `Caddy::validate_server_support` rejects `naive` + `vless-ws` on one server.
  CLI validation and web protocol enabling call this hook before persistence.
  Rejection changes neither inventory nor audit history.
- `vpnctl_core::amneziawg::effective_params` resolves the nine legacy parameters
  in INI order, preserving supplied strings and filling missing keys with the
  existing server defaults: Jc=4, Jmin=40, Jmax=70, S1=50, S2=100, H1–H4=1–4.
- Clients include this block when the legacy `amneziawg` kernel is assigned or
  any legacy parameter exists. Plain WireGuard without either keeps no block.
- Bootstrap mints a random set for a new AWG server. A partial legacy set is
  completed with those effective defaults without rotating supplied values.
  Each inserted key is audited; repeated bootstrap writes no no-op audit rows.

## 3. Verification

- Both protocol enabling orders fail before persistence; each protocol alone
  remains supported. CLI uses the same registry/kernel validation hook.
- Partial sets, including ones missing H1, render identical server/client
  parameters. Complete client JSON, INI and share-link bytes remain pinned.
- Bootstrap completes partial sets, preserves existing keys and is idempotent.
