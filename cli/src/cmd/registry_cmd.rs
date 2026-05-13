use crate::OutputFormat;
use serde::Serialize;

#[derive(Serialize)]
struct RegistrySnapshot {
    kernels: Vec<&'static str>,
    protocols: Vec<&'static str>,
}

pub(crate) fn run(format: OutputFormat) -> anyhow::Result<()> {
    // Validate construction (catches duplicate registrations even though
    // `build` is currently the only call-site).
    let _reg = crate::registry::build()?;

    // Hard-coded enumeration for now — Registry doesn't expose iteration
    // helpers yet (will be added when needed beyond this smoke listing).
    let snap = RegistrySnapshot {
        kernels: vec!["sing-box"],
        protocols: vec!["vless+reality", "tuic-v5"],
    };

    crate::ui::print(format, &snap, |s| {
        println!("Kernels:");
        for k in &s.kernels {
            println!("  - {k}");
        }
        println!("Protocols:");
        for p in &s.protocols {
            println!("  - {p}");
        }
        Ok(())
    })
}
