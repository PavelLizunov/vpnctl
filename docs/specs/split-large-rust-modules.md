# Spec: Split large Rust modules

## 1. Intent & Invariants
- What: mechanically split `admin::legacy`, inventory SQLite, and Boosty bridge monoliths into thematic Rust submodules.
- Invariants: public APIs, SQL, routes, HTML, serialization, text, ordering, and byte-level outputs remain unchanged.
- Use native Rust modules only; add no dependencies, abstractions, or functional cleanup.
- Prefer coherent files below 1,500 LOC, but do not break tightly coupled code solely to meet a line limit.

## 2. Interface / Data Contract
```rust
// Existing external paths remain valid.
pub use existing_public_types_and_functions;

// Internal implementations may move into private thematic modules.
mod dashboard;
mod settings;
mod server_detail;
mod models;
mod queries;
```

## 3. Verification Checklist
- [ ] Original public/public(crate) symbols remain reachable with identical signatures.
- [ ] Each worker changes only its assigned facade and new child modules.
- [ ] Independent diff review finds no unresolved critical/important issue.
- [ ] `cargo fmt --all`, check, Clippy, tests, deny, and Gitleaks pass.
- [ ] Changes are committed, pushed, and GitHub Actions is green.
- [ ] Production is not deployed for this structural-only change.
