# async-trait generated double must-use lint

PR #270 preserves an existing README change, but required Clippy CI fails under current stable Rust on unchanged async-trait methods in Kernel/SshTransport. async-trait 0.1.89 appends #[must_use] to boxed Future return values; current Clippy diagnoses double_must_use from the macro expansion.

Apply a narrowly scoped allow on affected async_trait trait definitions, with the exact macro rationale. Full CI exposed the same generated lint in daemon ClashClient, StatsClient, AlertSink and ProbeClient after core passed; include those exact sites. Do not disable clippy globally, change runtime behavior or branch checks. Verify cargo clippy -p vpnctl-core --all-targets -- -D warnings locally and full required workspace CI before merging.
