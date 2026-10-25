use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use axum::serve::Listener;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tower::Service;

const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CONNECTIONS: usize = 256;

pub(super) async fn serve(listener: TcpListener, app: Router, shutdown: impl Future<Output = ()>) {
    serve_with_limits(
        listener,
        app,
        shutdown,
        HEADER_READ_TIMEOUT,
        MAX_CONNECTIONS,
    )
    .await;
}

async fn serve_with_limits(
    mut listener: TcpListener,
    app: Router,
    shutdown: impl Future<Output = ()>,
    header_timeout: Duration,
    max_connections: usize,
) {
    let mut make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(header_timeout);
    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            (stream, peer) = Listener::accept(&mut listener) => {
                if graceful.count() >= max_connections {
                    drop(stream);
                    continue;
                }
                let service = match make_service.call(peer).await {
                    Ok(service) => service,
                    Err(err) => match err {},
                };
                let connection = builder.serve_connection(
                    TokioIo::new(stream),
                    TowerToHyperService::new(service),
                );
                // Reserve the slot before spawning, including tasks not yet polled.
                let watcher = graceful.watcher();
                tokio::spawn(async move {
                    if let Err(err) = watcher.watch(connection).await {
                        tracing::trace!(error = %err, "HTTP connection closed");
                    }
                });
            }
        }
    }
    drop(listener);
    drop(make_service);
    graceful.shutdown().await;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::extract::ConnectInfo;
    use axum::routing::get;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::{Notify, oneshot};
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    async fn start(
        app: Router,
        header_timeout: Duration,
        max_connections: usize,
    ) -> (SocketAddr, oneshot::Sender<()>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();
        let task = tokio::spawn(serve_with_limits(
            listener,
            app,
            async move {
                let _ = rx.await;
            },
            header_timeout,
            max_connections,
        ));
        (addr, tx, task)
    }

    async fn read_closed(stream: &mut TcpStream) -> Vec<u8> {
        let mut response = Vec::new();
        let result = timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
            .await
            .expect("connection must close within the deadline");
        if let Err(err) = result {
            assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
        }
        response
    }

    #[tokio::test]
    async fn incomplete_headers_time_out_before_reaching_router() {
        let hits = Arc::new(AtomicUsize::new(0));
        let handler_hits = Arc::clone(&hits);
        let app = Router::new().route(
            "/api/v1/health",
            get(move || async move {
                handler_hits.fetch_add(1, Ordering::SeqCst);
                "ok"
            }),
        );
        let (addr, shutdown, task) = start(app, Duration::from_millis(100), 8).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: x\r\nX-Slow: ")
            .await
            .unwrap();
        let response = read_closed(&mut stream).await;
        assert!(response.is_empty() || response.starts_with(b"HTTP/1.1 408"));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        shutdown.send(()).unwrap();
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn connection_limit_rejects_excess_and_releases_finished_slots() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let handler_entered = Arc::clone(&entered);
        let handler_release = Arc::clone(&release);
        let app = Router::new()
            .route(
                "/hold",
                get(move || {
                    let entered = Arc::clone(&handler_entered);
                    let release = Arc::clone(&handler_release);
                    async move {
                        entered.notify_one();
                        release.notified().await;
                        "done"
                    }
                }),
            )
            .route("/", get(|| async { "ok" }));
        let (addr, shutdown, task) = start(app, Duration::from_secs(10), 1).await;
        let mut first = TcpStream::connect(addr).await.unwrap();
        first
            .write_all(b"GET /hold HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();

        let mut excess = TcpStream::connect(addr).await.unwrap();
        assert!(read_closed(&mut excess).await.is_empty());

        release.notify_one();
        assert!(read_closed(&mut first).await.ends_with(b"done"));
        let mut next = TcpStream::connect(addr).await.unwrap();
        next.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        assert!(read_closed(&mut next).await.ends_with(b"ok"));
        shutdown.send(()).unwrap();
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn peer_info_and_middleware_survive_graceful_shutdown() {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let handler_entered = Arc::clone(&entered);
        let handler_release = Arc::clone(&release);
        let app = Router::new()
            .route(
                "/peer",
                get(move |ConnectInfo(peer): ConnectInfo<SocketAddr>| {
                    let entered = Arc::clone(&handler_entered);
                    let release = Arc::clone(&handler_release);
                    async move {
                        entered.notify_one();
                        release.notified().await;
                        peer.to_string()
                    }
                }),
            )
            .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("no-store"),
            ));
        let (addr, shutdown, mut task) = start(app, Duration::from_secs(10), 8).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let peer = stream.local_addr().unwrap();
        stream
            .write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        timeout(Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        shutdown.send(()).unwrap();
        assert!(timeout(Duration::from_millis(50), &mut task).await.is_err());
        release.notify_one();
        let response = String::from_utf8(read_closed(&mut stream).await).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains("cache-control: no-store\r\n"));
        assert!(response.ends_with(&peer.to_string()));
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert!(TcpStream::connect(addr).await.is_err());
    }
}
