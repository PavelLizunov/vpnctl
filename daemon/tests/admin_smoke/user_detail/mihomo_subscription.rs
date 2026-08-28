use tempfile::TempDir;

use vpnctl_core::UserId;
use vpnctld::router;

use crate::common::*;

#[tokio::test]
async fn delivery_renders_mihomo_subscription_card_and_overview_omits_it() {
    let dir = TempDir::new().unwrap();
    let s = state(&dir).await;
    seed(&s.inv, 1, 1, &[(0, 0)]).await;

    let u0 = s.inv.get_user(&UserId("u0".into())).await.unwrap().unwrap();
    let _token = u0.sub_token.expect("sub_token must be present");

    let app = router(s);

    let html_delivery = fetch_html(app.clone(), "/admin/users/u0/delivery").await;

    assert!(
        html_delivery.contains("Mihomo / Omarchy subscription")
            || html_delivery.contains("Mihomo / Omarchy подписка"),
        "Delivery page must contain the Mihomo / Omarchy card label"
    );

    assert!(
        html_delivery.contains("https://ninitux.com/api/v1/sub/")
            && html_delivery.contains("format=mihomo"),
        "Delivery page must contain canonical public Mihomo URL with format=mihomo"
    );

    assert!(
        html_delivery.contains("vpnctl-qr-frame"),
        "Mihomo card on Delivery must render using share_link_card with QR frame"
    );

    let html_overview = fetch_html(app, "/admin/users/u0/overview").await;

    assert!(
        !html_overview.contains("format=mihomo"),
        "Overview page must NOT render the Mihomo subscription URL"
    );
    assert!(
        !html_overview.contains("Mihomo / Omarchy"),
        "Overview page must NOT render the Mihomo card"
    );
}
