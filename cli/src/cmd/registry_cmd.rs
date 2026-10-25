use crate::OutputFormat;
use serde::Serialize;

#[derive(Serialize)]
struct RegistrySnapshot {
    kernels: Vec<String>,
    protocols: Vec<String>,
}

pub(crate) fn run(format: OutputFormat) -> anyhow::Result<()> {
    let snap = snapshot(&crate::registry::build()?);

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

fn snapshot(registry: &vpnctl_core::Registry) -> RegistrySnapshot {
    RegistrySnapshot {
        kernels: registry.kernel_ids().into_iter().map(|id| id.0).collect(),
        protocols: registry.protocol_ids().into_iter().map(|id| id.0).collect(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_contains_every_registered_kernel_and_protocol() {
        let registry = crate::registry::build().unwrap();
        let snap = snapshot(&registry);
        assert_eq!(
            snap.kernels,
            registry
                .kernel_ids()
                .into_iter()
                .map(|id| id.0)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            snap.protocols,
            registry
                .protocol_ids()
                .into_iter()
                .map(|id| id.0)
                .collect::<Vec<_>>()
        );
        assert!(snap.kernels.contains(&"xray".to_string()));
        assert!(snap.protocols.contains(&"vless+xhttp".to_string()));
    }
}
