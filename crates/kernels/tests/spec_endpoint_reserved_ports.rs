//! Endpoint listeners must honor the same reservations as ordinary inbounds.
use vpnctl_kernels::validate_config_excludes_ports;

#[test]
fn endpoint_only_config_cannot_bypass_reserved_port() {
    let config = br#"{"endpoints":[{"type":"wireguard","listen_port":51821}]}"#;
    assert!(validate_config_excludes_ports(config, &[51821]).is_err());
    assert!(validate_config_excludes_ports(config, &[443]).is_ok());
}

#[test]
fn endpoints_are_checked_alongside_disjoint_inbounds() {
    let config = br#"{"inbounds":[{"listen_port":443}],"endpoints":[{"listen_port":51822}]}"#;
    assert!(validate_config_excludes_ports(config, &[51822]).is_err());
    assert!(validate_config_excludes_ports(config, &[443]).is_err());
    assert!(validate_config_excludes_ports(config, &[8444]).is_ok());
}
