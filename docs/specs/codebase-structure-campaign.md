# Spec: Useful module splits and project map

## 1. Intent & Invariants
- Split only large files containing genuinely independent domains; do not optimize for line count alone.
- Execute independent files through Gemini workers while the lead owns boundaries, integration, review, and acceptance.
- Preserve public APIs, routes, SQL, HTML, serialization, text, ordering, and byte-level compatibility.
- Add no dependencies, speculative abstractions, or behavioral cleanup.
- Keep cohesive drivers and files large mainly because of local tests intact.
- Maintain the canonical project map in-repository; defer a DSH GUI plugin until static generated data is insufficient.

## 2. Interface / Data Contract
```text
Wave 1 — admin:
  legacy/{server_detail,user_sections,dashboard,settings}.rs
  admin/{server_actions,user_detail}.rs
  tests/admin_smoke.rs

Wave 2 — daemon:
  health_monitor.rs, wizard_bootstrap.rs, node_probe_poller.rs, app.rs
  handlers/{vpn_router,sub}.rs

Wave 3 — inventory:
  sqlite/{servers,access,users,stats}.rs, backup.rs, migrate.rs

Wave 4 — selective:
  alert_text.rs, protocols/wireguard.rs, kernels/caddy.rs, endpoint/spec tests

Project map:
  docs/CODEBASE_INVENTORY.md  # canonical human-readable generated map
  scripts/project-map.py      # deterministic generator/check command
```

## 3. Verification Checklist
- [ ] Capture original public symbols before each wave.
- [ ] Each worker edits only one assigned facade and its new submodules.
- [ ] Keep `admin_smoke` as one Cargo test binary with thematic Rust submodules.
- [ ] Generate the map from repository files and `cargo metadata`; do not hand-duplicate structure.
- [ ] Review every wave independently and fix critical/important findings.
- [ ] Run formatting, check, Clippy, tests, deny, and Gitleaks.
- [ ] Commit each completed wave and wait for green GitHub CI before stacking unrelated work.
- [ ] Do not create a GUI plugin until the static map has a demonstrated usability gap.
