use super::scripts::DEFAULT_SING_BOX_ARTIFACT;

pub(crate) fn resolve_sing_box_artifact_path(arch: &str) -> std::path::PathBuf {
    match arch {
        "aarch64" | "arm64" => std::env::var_os("VPNCTL_SING_BOX_ARM64_ARTIFACT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from("/opt/vpnctl/node-artifacts/sing-box-arm64")
            }),
        "armv7l" | "armv7" | "armhf" => std::env::var_os("VPNCTL_SING_BOX_ARMV7_ARTIFACT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from("/opt/vpnctl/node-artifacts/sing-box-armv7")
            }),
        _ => std::env::var_os("VPNCTL_SING_BOX_ARTIFACT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_SING_BOX_ARTIFACT)),
    }
}
