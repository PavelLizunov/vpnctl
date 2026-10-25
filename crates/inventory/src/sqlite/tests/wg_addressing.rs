use super::{fresh, sample_server, sample_user};
use vpnctl_core::UserId;

#[tokio::test]
async fn migration_0066_preserves_old_peer_order_and_skips_disabled_grants() {
    let inv = fresh().await;
    // Recreate the pre-0066 schema to test the migration against legacy grants.
    sqlx::raw_sql(
        "DROP INDEX idx_grants_server_wg_octet; ALTER TABLE grants DROP COLUMN wg_octet;",
    )
    .execute(inv.pool())
    .await
    .unwrap();
    let server = sample_server("wg");
    let other = sample_server("other");
    inv.add_server(&server).await.unwrap();
    inv.add_server(&other).await.unwrap();
    for id in ["clara", "alice", "disabled", "bob", "ungranted"] {
        let mut user = sample_user(id);
        user.disabled = id == "disabled";
        inv.add_user(&user).await.unwrap();
        if id != "ungranted" {
            sqlx::query("INSERT INTO grants (user_id, server_id) VALUES (?1, ?2)")
                .bind(id)
                .bind(&server.id.0)
                .execute(inv.pool())
                .await
                .unwrap();
        }
    }
    sqlx::query("INSERT INTO grants (user_id, server_id) VALUES ('clara', ?1)")
        .bind(&other.id.0)
        .execute(inv.pool())
        .await
        .unwrap();
    let before = inv.users_for_server(&server.id).await.unwrap();
    assert_eq!(
        before.iter().map(|u| u.id.0.as_str()).collect::<Vec<_>>(),
        ["alice", "bob", "clara"]
    );
    sqlx::raw_sql(include_str!("../../../migrations/0066_grant_wg_octet.sql"))
        .execute(inv.pool())
        .await
        .unwrap();
    let assigned = inv.wg_octets_for_server(&server.id).await.unwrap();
    for (index, user) in before.iter().enumerate() {
        assert_eq!(assigned[&user.id], 2 + u16::try_from(index).unwrap());
    }
    assert_eq!(
        inv.wg_octets_for_server(&other.id).await.unwrap()[&UserId("clara".into())],
        2
    );
    let disabled: Option<i64> =
        sqlx::query_scalar("SELECT wg_octet FROM grants WHERE user_id = 'disabled'")
            .fetch_one(inv.pool())
            .await
            .unwrap();
    assert_eq!(disabled, None);
    let audits = inv.recent_audit(20).await.unwrap();
    assert_eq!(
        audits
            .iter()
            .filter(|a| a.action == "grant.wg_octet.assign")
            .count(),
        4
    );
    assert!(
        sqlx::query("UPDATE grants SET wg_octet = 2 WHERE user_id = 'bob'")
            .execute(inv.pool())
            .await
            .is_err(),
        "addresses must be unique per server"
    );
}

#[tokio::test]
async fn grant_addresses_survive_add_disable_remove_and_reenable() {
    let inv = fresh().await;
    let server = sample_server("wg");
    inv.add_server(&server).await.unwrap();
    for id in ["bob", "clara", "alice"] {
        inv.add_user(&sample_user(id)).await.unwrap();
        assert!(
            inv.grant_audited(&UserId(id.into()), &server.id, "test", "wg-test")
                .await
                .unwrap()
        );
    }
    let original = inv.wg_octets_for_server(&server.id).await.unwrap();
    assert_eq!(original[&UserId("bob".into())], 2);
    assert_eq!(original[&UserId("clara".into())], 3);
    assert_eq!(original[&UserId("alice".into())], 4);
    inv.set_user_disabled(&UserId("bob".into()), true)
        .await
        .unwrap();
    inv.add_user(&sample_user("aaron")).await.unwrap();
    inv.grant_audited(&UserId("aaron".into()), &server.id, "test", "test")
        .await
        .unwrap();
    let after = inv.wg_octets_for_server(&server.id).await.unwrap();
    assert_eq!(
        after[&UserId("aaron".into())],
        5,
        "disabled address is reserved"
    );
    for id in ["alice", "clara"] {
        assert_eq!(after[&UserId(id.into())], original[&UserId(id.into())]);
    }
    inv.set_user_disabled(&UserId("bob".into()), false)
        .await
        .unwrap();
    assert_eq!(
        inv.wg_octets_for_server(&server.id).await.unwrap()[&UserId("bob".into())],
        2
    );
    inv.remove_user(&UserId("alice".into())).await.unwrap();
    inv.revoke(&UserId("bob".into()), &server.id).await.unwrap();
    inv.add_user(&sample_user("dave")).await.unwrap();
    inv.grant_audited(&UserId("dave".into()), &server.id, "test", "test")
        .await
        .unwrap();
    let after = inv.wg_octets_for_server(&server.id).await.unwrap();
    assert_eq!(
        after[&UserId("dave".into())],
        2,
        "revocation frees the lowest slot"
    );
    assert_eq!(after[&UserId("clara".into())], 3);
    assert_eq!(after[&UserId("aaron".into())], 5);
    let audits = inv.recent_audit(100).await.unwrap();
    let grants: Vec<_> = audits.iter().filter(|a| a.action == "user.grant").collect();
    assert_eq!(grants.len(), 5);
    let bob = grants
        .iter()
        .find(|a| a.target.as_deref() == Some("bob"))
        .unwrap();
    assert_eq!(bob.actor, "test");
    assert_eq!(bob.payload.as_ref().unwrap()["wg_octet"], 2);
    assert!(
        !inv.grant_audited(&UserId("clara".into()), &server.id, "test", "wg-test")
            .await
            .unwrap()
    );
    assert_eq!(
        audits.len(),
        inv.recent_audit(100).await.unwrap().len(),
        "no-op grant and reads must not audit"
    );
}

#[tokio::test]
async fn lazy_assignment_is_atomic_audited_once_and_loaded_by_subscription() {
    let inv = fresh().await;
    let mut server = sample_server("wg");
    server
        .enabled_protocols
        .push(vpnctl_core::ProtocolId("wireguard".into()));
    inv.add_server(&server).await.unwrap();
    for id in ["alice", "bob"] {
        inv.add_user(&sample_user(id)).await.unwrap();
        // A NULL grant models a disabled user skipped by migration 0066.
        sqlx::query("INSERT INTO grants (user_id, server_id) VALUES (?1, ?2)")
            .bind(id)
            .bind(&server.id.0)
            .execute(inv.pool())
            .await
            .unwrap();
    }
    let revision = inv.deploy_input_revision(&server.id).await.unwrap();
    let (left, right) = tokio::join!(
        inv.wg_octets_for_server(&server.id),
        inv.wg_octets_for_server(&server.id)
    );
    let octets = left.unwrap();
    assert_eq!(octets, right.unwrap());
    assert_eq!(octets[&UserId("alice".into())], 2);
    assert_eq!(octets[&UserId("bob".into())], 3);
    assert_ne!(
        revision,
        inv.deploy_input_revision(&server.id).await.unwrap()
    );
    // Exercise the batch loader's lazy path for a re-enabled legacy grant too.
    sqlx::query("UPDATE grants SET wg_octet = NULL WHERE user_id = 'bob'")
        .execute(inv.pool())
        .await
        .unwrap();
    let inputs = inv
        .subscription_render_inputs(&UserId("alice".into()), true)
        .await
        .unwrap();
    assert_eq!(inputs[0].wg_octets, octets);
    let audits = inv.recent_audit(100).await.unwrap();
    assert_eq!(
        audits
            .iter()
            .filter(|a| a.action == "grant.wg_octet.assign")
            .count(),
        3
    );
    inv.wg_octets_for_server(&server.id).await.unwrap();
    assert_eq!(audits.len(), inv.recent_audit(100).await.unwrap().len());
    assert!(
        inv.wg_octets_for_server(&vpnctl_core::ServerId("missing".into()))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn full_wg_subnet_still_grants_and_assigns_the_next_free_slot_lazily() {
    let inv = fresh().await;
    let server = sample_server("wg");
    inv.add_server(&server).await.unwrap();
    for index in 0..253 {
        let user = sample_user(&format!("peer-{index:03}"));
        inv.add_user(&user).await.unwrap();
        inv.grant(&user.id, &server.id).await.unwrap();
    }
    let highest: i64 = sqlx::query_scalar("SELECT MAX(wg_octet) FROM grants")
        .fetch_one(inv.pool())
        .await
        .unwrap();
    assert_eq!(highest, 254);
    // A full /24 must not block access to the server's other protocols.
    let extra = sample_user("extra");
    inv.add_user(&extra).await.unwrap();
    assert!(
        inv.grant_audited(&extra.id, &server.id, "test", "wg-test")
            .await
            .unwrap()
    );
    let boosty = sample_user("boosty-user");
    inv.add_boosty_user(&boosty, 7).await.unwrap();
    let missing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM grants WHERE wg_octet IS NULL")
        .fetch_one(inv.pool())
        .await
        .unwrap();
    assert_eq!(missing, 2);
    let before = inv.recent_audit(1).await.unwrap()[0].id;
    let octets = inv.wg_octets_for_server(&server.id).await.unwrap();
    assert!(!octets.contains_key(&extra.id));
    assert_eq!(
        before,
        inv.recent_audit(1).await.unwrap()[0].id,
        "no slot, no write"
    );
    inv.revoke(&UserId("peer-000".into()), &server.id)
        .await
        .unwrap();
    let octets = inv.wg_octets_for_server(&server.id).await.unwrap();
    let assigned: Vec<_> = [&extra.id, &boosty.id]
        .into_iter()
        .filter(|id| octets.get(id) == Some(&2))
        .collect();
    assert_eq!(
        assigned.len(),
        1,
        "the freed slot goes to exactly one waiting grant"
    );
    let audits = inv.recent_audit(5).await.unwrap();
    assert_eq!(
        audits
            .iter()
            .filter(|a| a.action == "grant.wg_octet.assign")
            .count(),
        1
    );
}

#[tokio::test]
async fn boosty_grants_reserve_addresses_in_the_creation_transaction() {
    let inv = fresh().await;
    let server = sample_server("wg");
    inv.add_server(&server).await.unwrap();
    let user = sample_user("boosty-user");
    assert_eq!(inv.add_boosty_user(&user, 7).await.unwrap(), 1);
    let octet: Option<i64> = sqlx::query_scalar("SELECT wg_octet FROM grants WHERE user_id = ?1")
        .bind(&user.id.0)
        .fetch_one(inv.pool())
        .await
        .unwrap();
    assert_eq!(octet, Some(2));
    let audits = inv.recent_audit(10).await.unwrap();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].action, "user.grant");
    assert_eq!(audits[0].payload.as_ref().unwrap()["wg_octet"], 2);
}
