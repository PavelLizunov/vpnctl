//! Spec tests for protocol retirement.
//!
//! Retired protocols must disappear from new-configuration discovery while
//! staying resolvable (and identifiable by their stored id) so existing
//! nodes and configurations keep working and can be rolled back.

use std::collections::BTreeSet;

use vpnctl_core::ProtocolId;
use vpnctl_kernels::build_registry;

/// Types that must no longer be offered for new configuration.
const RETIRED: [&str; 4] = ["trojan", "anytls", "shadowsocks-2022", "amneziawg2"];

/// Representative types that must remain offered and usable.
const ACTIVE: [&str; 3] = ["vless+reality", "amneziawg3", "dnstt"];

fn discover(name: &str) -> ProtocolId {
    ProtocolId(name.to_owned())
}

#[test]
fn retired_protocols_are_hidden_from_discovery_but_still_resolve()
-> Result<(), Box<dyn std::error::Error>> {
    let registry = build_registry()?;
    let discovered = registry.protocol_ids();

    for name in RETIRED {
        let id = discover(name);
        assert!(
            !discovered.contains(&id),
            "retired protocol {name} must not be offered for new configuration"
        );

        let protocol = registry
            .protocol(&id)
            .ok_or_else(|| format!("retired protocol {name} must stay resolvable"))?;
        assert!(
            protocol.is_retired(),
            "retired protocol {name} must report is_retired() == true"
        );
        assert_eq!(
            protocol.id().0,
            name,
            "retired protocol {name} must keep its stored identifier"
        );
    }

    Ok(())
}

#[test]
fn active_protocols_remain_discoverable_and_are_not_retired()
-> Result<(), Box<dyn std::error::Error>> {
    let registry = build_registry()?;
    let discovered = registry.protocol_ids();
    assert!(
        !discovered.is_empty(),
        "the registry must still offer active protocol types"
    );

    for name in ACTIVE {
        let id = discover(name);
        assert!(
            discovered.contains(&id),
            "active protocol {name} must remain discoverable"
        );

        let protocol = registry
            .protocol(&id)
            .ok_or_else(|| format!("active protocol {name} must resolve"))?;
        assert!(
            !protocol.is_retired(),
            "active protocol {name} must not be reported as retired"
        );
        assert_eq!(
            protocol.id().0,
            name,
            "active protocol {name} must keep its requested identifier"
        );
    }

    Ok(())
}

#[test]
fn discovery_lists_each_non_retired_type_exactly_once() -> Result<(), Box<dyn std::error::Error>> {
    let registry = build_registry()?;
    let mut seen = BTreeSet::new();

    for id in registry.protocol_ids() {
        assert!(
            seen.insert(id.0.clone()),
            "protocol {} appears more than once in discovery",
            id.0
        );

        let protocol = registry
            .protocol(&id)
            .ok_or_else(|| format!("discovered protocol {} must resolve", id.0))?;
        assert!(
            !protocol.is_retired(),
            "discovered protocol {} must not be retired",
            id.0
        );
        assert_eq!(
            protocol.id().0,
            id.0,
            "discovered protocol {} must resolve to itself",
            id.0
        );
    }

    for name in RETIRED {
        assert!(
            !seen.contains(name),
            "retired protocol {name} leaked into discovery"
        );
    }

    Ok(())
}

#[test]
fn protocol_id_is_a_public_tuple_struct_that_round_trips_stored_values()
-> Result<(), Box<dyn std::error::Error>> {
    let registry = build_registry()?;

    // Stored configs persist the protocol name as a string; rebuilding the id
    // through the public tuple struct must resolve for every retired type.
    for name in RETIRED.iter().chain(ACTIVE.iter()) {
        let stored = (*name).to_owned();
        let from_config = ProtocolId(stored.clone());
        assert_eq!(
            from_config.0, stored,
            "ProtocolId must expose its payload as a public field"
        );
        assert_eq!(
            from_config,
            discover(name),
            "ProtocolId must compare by the stored identifier"
        );

        let protocol = registry
            .protocol(&from_config)
            .ok_or_else(|| format!("protocol {name} stored in an existing config must resolve"))?;
        assert_eq!(
            protocol.id().0,
            stored,
            "protocol {name} must resolve under its stored identifier"
        );
    }

    Ok(())
}
