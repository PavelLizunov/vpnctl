//! Independent public-contract tests for the node-reachability admin UI.
//!
//! Scope: only HTTP responses and the public inventory/test-state seams; do not
//! inspect or import the private-check implementation, view, or probe modules.
//! Acceptance: localized headings, semantic TCP matrix/outcomes, separate UDP
//! details, escaped display names, an empty-state server link, and a normal
//! authenticated same-origin POST. A bounded HTTP poll observes run completion.
//! Network fixtures use loopback only; unpinned SSH sources must never connect.
//! Verification constraint: this task permits formatting, not local compilation,
//! cargo checks/tests, guard bypasses, or commits. Deterministic timeout/failed
//! probe outcomes have no public injection seam and are not synthesized here.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "admin_smoke/common.rs"]
#[allow(dead_code)]
mod common;

use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use tokio::net::TcpListener;
use tower::ServiceExt;
use vpnctl_core::{KernelId, ProtocolId, Server, ServerId};
use vpnctld::AppState;

const PATH: &str = "/admin/monitoring/private-checks";
const OUTCOMES: &[&str] = &[
    "reachable",
    "refused",
    "timeout",
    "failed",
    "self",
    "no-address",
    "source-unavailable",
    "not-checked",
];

// These small selectors inspect only non-nested elements of the same tag. They
// deliberately ignore class order, attribute order, and attribute quote style.
fn elements<'a>(mut html: &'a str, tag: &str) -> Vec<&'a str> {
    let opening = format!("<{tag}");
    let closing = format!("</{tag}>");
    let mut found = Vec::new();
    while let Some(start) = html.find(&opening) {
        html = &html[start..];
        let boundary = html.as_bytes().get(opening.len()).copied();
        if !boundary.is_some_and(|b| b == b'>' || b.is_ascii_whitespace()) {
            html = &html[opening.len()..];
            continue;
        }
        let end = html
            .find(&closing)
            .unwrap_or_else(|| panic!("unclosed {tag} element"))
            + closing.len();
        found.push(&html[..end]);
        html = &html[end..];
    }
    found
}

fn attribute<'a>(element: &'a str, name: &str) -> Option<&'a str> {
    let opening = element.split_once('>')?.0;
    for quote in ['"', '\''] {
        let needle = format!(" {name}={quote}");
        if let Some((_, value)) = opening.split_once(&needle) {
            return value.split_once(quote).map(|(value, _)| value);
        }
    }
    None
}

fn has_class(element: &str, class: &str) -> bool {
    attribute(element, "class")
        .is_some_and(|classes| classes.split_whitespace().any(|c| c == class))
}

fn matrix(html: &str) -> &str {
    let tables: Vec<_> = elements(html, "table")
        .into_iter()
        .filter(|table| has_class(table, "pc-matrix"))
        .collect();
    assert_eq!(tables.len(), 1, "one semantic table.pc-matrix is required");
    let table = tables[0];
    assert!(!elements(table, "thead").is_empty(), "missing table header");
    let bodies = elements(table, "tbody");
    assert_eq!(bodies.len(), 1, "one table body is required");
    for row in elements(bodies[0], "tr") {
        for name in ["data-server", "data-protocol", "data-port"] {
            assert!(attribute(row, name).is_some(), "target row needs {name}");
        }
    }
    assert!(!elements(table, "th").is_empty(), "missing header cells");
    table
}

fn target_rows(table: &str) -> Vec<&str> {
    elements(table, "tr")
        .into_iter()
        .filter(|row| attribute(row, "data-server").is_some())
        .collect()
}

fn target_row<'a>(table: &'a str, server: &str, protocol: &str, port: u16) -> &'a str {
    let port = port.to_string();
    let rows: Vec<_> = target_rows(table)
        .into_iter()
        .filter(|row| {
            attribute(row, "data-server") == Some(server)
                && attribute(row, "data-protocol") == Some(protocol)
                && attribute(row, "data-port") == Some(port.as_str())
        })
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "expected one row for {server}/{protocol}/{port}"
    );
    rows[0]
}

fn source_outcome<'a>(row: &'a str, source: &str) -> &'a str {
    let cells: Vec<_> = elements(row, "td")
        .into_iter()
        .filter(|cell| attribute(cell, "data-source") == Some(source))
        .collect();
    assert_eq!(cells.len(), 1, "expected one data cell for source {source}");
    let outcomes: Vec<_> = elements(cells[0], "span")
        .into_iter()
        .filter_map(|span| attribute(span, "data-outcome"))
        .collect();
    assert_eq!(outcomes.len(), 1, "source {source} needs one outcome span");
    assert!(
        OUTCOMES.contains(&outcomes[0]),
        "unknown outcome: {}",
        outcomes[0]
    );
    outcomes[0]
}

fn running(html: &str) -> bool {
    let values: Vec<_> = html
        .split_inclusive('>')
        .filter_map(|tag| attribute(tag, "data-running"))
        .collect();
    assert!(!values.is_empty(), "the page must expose data-running");
    assert!(values.iter().all(|value| *value == values[0]));
    match values[0] {
        "true" => true,
        "false" => false,
        value => panic!("data-running must be true or false, got {value}"),
    }
}

async fn wait_until_finished(app: &Router) -> String {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            // The job may have been spawned by POST on this current-thread runtime.
            tokio::task::yield_now().await;
            let html = common::fetch_html(app.clone(), PATH).await;
            if !running(&html) {
                return html;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("private checks did not expose data-running=false within 10 seconds")
}

async fn add_target(
    state: &AppState,
    id: &str,
    address: &str,
    ssh_port: u16,
    tcp_port: u16,
    udp: bool,
) {
    let sid = ServerId(id.into());
    let mut protocols = vec![ProtocolId("vless+reality".into())];
    if udp {
        protocols.push(ProtocolId("hysteria2".into()));
    }
    state
        .inv
        .add_server(&Server {
            id: sid.clone(),
            address: address.into(),
            ssh_port,
            ssh_user: "root".into(),
            kernels: vec![KernelId("sing-box".into())],
            enabled_protocols: protocols,
            trusted_host_fingerprint: None,
            hoster: "generic".into(),
            jump_via: None,
            usage_coefficient: 1.0,
        })
        .await
        .unwrap();
    state
        .inv
        .set_server_secret(&sid, "vless.listen_port", &tcp_port.to_string())
        .await
        .unwrap();
}

#[tokio::test]
async fn empty_state_has_localized_heading_and_inventory_link() {
    let dir = tempfile::tempdir().unwrap();
    let app = vpnctld::router(common::state(&dir).await);
    for (language, heading) in [("en", "Node reachability"), ("ru", "Доступность узлов")]
    {
        let html =
            common::fetch_html_with_cookie(app.clone(), PATH, &format!("vpnctl_lang={language}"))
                .await;
        let h1 = elements(&html, "h1")
            .into_iter()
            .find(|h1| h1.contains(heading))
            .unwrap_or_else(|| panic!("missing {language} page heading: {heading}"));
        // Do not let the permanent navigation link satisfy the empty-state link.
        let content = html.split_once(h1).unwrap().1;
        assert!(
            elements(content, "a")
                .iter()
                .any(|link| attribute(link, "href") == Some("/admin/servers")),
            "empty inventory needs a working /admin/servers link after its heading"
        );
        assert!(!running(&html), "GET must not launch a run");
    }
}

#[tokio::test]
async fn inventory_becomes_a_tcp_comparison_table_with_udp_details_and_escaped_names() {
    let dir = tempfile::tempdir().unwrap();
    let state = common::state(&dir).await;
    add_target(&state, "node-a", "127.0.0.1", 22, 24101, true).await;
    add_target(&state, "node-<fallback>", "127.0.0.1", 22, 24102, true).await;
    let display_name = "West <img src=x onerror=alert(1)> & edge";
    let escaped_name = "West &lt;img src=x onerror=alert(1)&gt; &amp; edge";
    state
        .inv
        .set_server_display_name(&ServerId("node-a".into()), Some(display_name))
        .await
        .unwrap();
    let app = vpnctld::router(state);
    let html = common::fetch_html_with_cookie(app.clone(), PATH, "vpnctl_lang=en").await;
    let table = matrix(&html);
    let rows = target_rows(table);
    assert_eq!(
        rows.len(),
        2,
        "only the two TCP targets belong in the matrix"
    );
    for (server, port) in [("node-a", 24101), ("node-&lt;fallback&gt;", 24102)] {
        let row = target_row(table, server, "vless+reality", port);
        assert_eq!(source_outcome(row, "controller"), "not-checked");
        for source in ["node-a", "node-&lt;fallback&gt;"] {
            source_outcome(row, source);
        }
        assert_eq!(
            elements(row, "td")
                .iter()
                .filter(|cell| attribute(cell, "data-source").is_some())
                .count(),
            3,
            "each target must compare controller and both inventory sources"
        );
    }
    let header = elements(table, "thead")[0];
    assert!(
        header.contains(escaped_name),
        "source header must use display_name"
    );
    assert!(
        target_row(table, "node-a", "vless+reality", 24101).contains(escaped_name),
        "target label must use display_name"
    );
    assert!(
        header.contains("node-&lt;fallback&gt;"),
        "ID fallback must be escaped"
    );
    assert!(
        !html.contains(display_name),
        "display_name must not inject markup"
    );
    assert!(
        !html.contains("node-<fallback>"),
        "inventory ID must not inject markup"
    );
    assert!(
        rows.iter()
            .all(|row| attribute(row, "data-protocol") != Some("hysteria2"))
    );
    let details: Vec<_> = elements(&html, "details")
        .into_iter()
        .filter(|details| has_class(details, "pc-details"))
        .collect();
    assert!(!details.is_empty(), "UDP belongs in details.pc-details");
    assert!(
        details.iter().any(|details| {
            details.contains("hysteria2")
                && details.to_ascii_lowercase().contains("udp")
                && details.to_ascii_lowercase().contains("not checked")
        }),
        "UDP details must identify the protocol and say UDP is not checked"
    );
    assert!(!running(&html));
    let again = common::fetch_html(app, PATH).await;
    assert_eq!(
        source_outcome(
            target_row(matrix(&again), "node-a", "vless+reality", 24101),
            "controller"
        ),
        "not-checked",
        "repeated GET must not start probes"
    );
}

#[tokio::test]
async fn completed_run_compares_controller_self_and_unavailable_unpinned_sources() {
    let dir = tempfile::tempdir().unwrap();
    let state = common::state(&dir).await;
    let reachable = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ssh_sentinel = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = reachable.local_addr().unwrap().port();
    let ssh_port = ssh_sentinel.local_addr().unwrap().port();
    // Distinct loopback addresses: two IDs on the same IP are self checks,
    // not independent sources, regardless of whether SSH has a pin.
    let reachable_b = TcpListener::bind(("127.0.0.2", tcp_port)).await.unwrap();
    for (id, address) in [("loop-a", "127.0.0.1"), ("loop-b", "127.0.0.2")] {
        add_target(&state, id, address, ssh_port, tcp_port, false).await;
    }
    add_target(&state, "no-address", "", ssh_port, tcp_port, false).await;
    let app = vpnctld::router(state);
    let response = app
        .clone()
        .oneshot(
            common::add_same_origin(Request::builder().method("POST").uri(PATH))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"], PATH);
    let html = wait_until_finished(&app).await;
    let table = matrix(&html);
    assert_eq!(target_rows(table).len(), 3);
    for (target, other_source) in [("loop-a", "loop-b"), ("loop-b", "loop-a")] {
        let row = target_row(table, target, "vless+reality", tcp_port);
        assert_eq!(source_outcome(row, "controller"), "reachable");
        assert_eq!(source_outcome(row, target), "self");
        assert_eq!(source_outcome(row, other_source), "source-unavailable");
    }
    assert_eq!(
        source_outcome(
            target_row(table, "no-address", "vless+reality", tcp_port),
            "controller"
        ),
        "no-address"
    );
    assert!(
        matches!(
            tokio::time::timeout(Duration::from_millis(100), reachable.accept()).await,
            Ok(Ok(_))
        ),
        "reachable must reflect an actual loopback TCP connection"
    );
    assert!(matches!(
        tokio::time::timeout(Duration::from_millis(100), reachable_b.accept()).await,
        Ok(Ok(_))
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), ssh_sentinel.accept())
            .await
            .is_err(),
        "an SSH source without a pinned host key must never connect"
    );
}

// Credentials are process-global; use the existing test-binary child pattern
// rather than mutating the environment of concurrent tests.
#[tokio::test]
async fn start_form_is_plain_post_and_preserves_admin_auth_and_csrf() {
    const CHILD: &str = "VPNCTL_PRIVATE_CHECKS_UI_SPEC_AUTH_CHILD";
    const USER: &str = "private-checks-ui-spec";
    const PASSWORD: &str = "test-only-not-a-deployed-password";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "start_form_is_plain_post_and_preserves_admin_auth_and_csrf",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("VPNCTLD_ADMIN_USER", USER)
            .env("VPNCTLD_ADMIN_PASSWORD", PASSWORD)
            .status()
            .unwrap();
        assert!(status.success(), "isolated UI auth/CSRF contract failed");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let state = common::state(&dir).await;
    add_target(&state, "form-node", "", 22, 24103, false).await;
    let app = vpnctld::router(state);
    let auth = format!("Basic {}", STANDARD.encode(format!("{USER}:{PASSWORD}")));
    for method in ["GET", "POST"] {
        for credentials in [None, Some("Basic invalid")] {
            let mut request = common::add_same_origin(Request::builder().method(method).uri(PATH));
            if let Some(credentials) = credentials {
                request = request.header("authorization", credentials);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} auth bypass"
            );
            assert!(response.headers().contains_key("www-authenticate"));
        }
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(PATH)
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let forms: Vec<_> = elements(&html, "form")
        .into_iter()
        .filter(|form| attribute(form, "action") == Some(PATH))
        .collect();
    assert_eq!(forms.len(), 1, "one native start form must target {PATH}");
    assert!(attribute(forms[0], "method").is_some_and(|m| m.eq_ignore_ascii_case("post")));
    assert!(
        elements(forms[0], "button").iter().any(|button| {
            attribute(button, "type").is_none_or(|kind| kind.eq_ignore_ascii_case("submit"))
        }),
        "the start form needs a native submit button"
    );
    for origin in [None, Some("http://foreign.example")] {
        let mut request = Request::builder()
            .method("POST")
            .uri(PATH)
            .header("host", common::SAME_ORIGIN_HOST)
            .header("authorization", &auth)
            .header("content-type", "application/x-www-form-urlencoded");
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "POST must enforce CSRF"
        );
    }
    let response = app
        .oneshot(
            common::add_same_origin(Request::builder().method("POST").uri(PATH))
                .header("authorization", auth)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"], PATH);
}
