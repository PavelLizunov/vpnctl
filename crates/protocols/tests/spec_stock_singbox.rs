#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Spec test for stock sing-box protocol compatibility.
//!
//! Source of truth: `docs/specs/singbox-chain-subscription.md`.
//!
//! Standard sing-box clients (stock sing-box 1.13+) do not support custom
//! transport extensions such as `vless+xhttp` (which target sing-box-lx /
//! VPNRouter). Stock sing-box JSON subscriptions MUST exclude `VlessXhttp`
//! while including native sing-box protocols like `VlessReality`.

use vpnctl_core::Protocol;
use vpnctl_protocols::{
    AnyTls, Hysteria2, Naive, Shadowsocks2022, Trojan, TuicV5, VlessReality, VlessWs, VlessXhttp,
    WireGuard,
};

#[test]
fn vless_xhttp_does_not_appear_in_stock_sing_box_sub() {
    let proto: Box<dyn Protocol> = Box::new(VlessXhttp::new());
    assert!(
        proto.appears_in_sing_box_sub(),
        "legacy sing-box-lx JSON must keep XHTTP for byte compatibility"
    );
    assert!(
        !proto.appears_in_stock_sing_box_sub(),
        "stock sing-box JSON must exclude the fork-only XHTTP transport"
    );
}

#[test]
fn vless_reality_appears_in_stock_sing_box_sub() {
    let proto: Box<dyn Protocol> = Box::new(VlessReality::new());
    assert!(
        proto.appears_in_stock_sing_box_sub(),
        "VlessReality MUST appear in stock sing-box subscriptions as a native protocol"
    );
}

#[test]
fn native_singbox_protocols_appear_in_stock_sing_box_sub() {
    let native_protocols: Vec<Box<dyn Protocol>> = vec![
        Box::new(VlessReality::new()),
        Box::new(VlessWs::new()),
        Box::new(Trojan::new()),
        Box::new(Hysteria2::new()),
        Box::new(TuicV5::new()),
        Box::new(Shadowsocks2022::new()),
        Box::new(AnyTls::new()),
        Box::new(Naive::new()),
    ];

    for proto in native_protocols {
        assert!(
            proto.appears_in_stock_sing_box_sub(),
            "Native protocol {} MUST appear in stock sing-box subscriptions",
            proto.id()
        );
    }
}

#[test]
fn non_singbox_native_protocols_do_not_appear_in_stock_sing_box_sub() {
    let non_singbox_protocols: Vec<Box<dyn Protocol>> =
        vec![Box::new(VlessXhttp::new()), Box::new(WireGuard::new())];

    for proto in non_singbox_protocols {
        assert!(
            !proto.appears_in_stock_sing_box_sub(),
            "Non-stock protocol {} MUST NOT appear in stock sing-box subscriptions",
            proto.id()
        );
    }
}
