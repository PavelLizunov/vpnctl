//! Loopback HTTP fixture shared by the adapter and admin contract tests.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[derive(Clone)]
pub(crate) struct HttpResponse {
    bytes: Vec<u8>,
    stall: bool,
}

impl HttpResponse {
    pub(crate) fn new(status: &str, headers: &str, body: Vec<u8>) -> Self {
        Self {
            bytes: [
                format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
                    body.len()
                )
                .into_bytes(),
                body,
            ]
            .concat(),
            stall: false,
        }
    }

    pub(crate) fn stall_before_headers() -> Self {
        Self {
            bytes: Vec::new(),
            stall: true,
        }
    }

    pub(crate) fn stream_then_stall(headers: &str, body: Vec<u8>) -> Self {
        // No Content-Length: the body ends only when the fixture closes the socket.
        Self {
            bytes: [
                format!("HTTP/1.1 200 OK\r\nConnection: close\r\n{headers}\r\n").into_bytes(),
                body,
            ]
            .concat(),
            stall: true,
        }
    }
}

pub(crate) struct HttpFixture {
    pub(crate) base_url: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    release: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl HttpFixture {
    pub(crate) fn respond(status: &str, headers: &str, body: Vec<u8>) -> Self {
        Self::scripted(vec![(status, headers, body)])
    }

    pub(crate) fn scripted(responses: Vec<(&str, &str, Vec<u8>)>) -> Self {
        Self::with_responses(
            responses
                .into_iter()
                .map(|(status, headers, body)| HttpResponse::new(status, headers, body))
                .collect(),
        )
    }

    pub(crate) fn with_responses(responses: Vec<HttpResponse>) -> Self {
        assert!(!responses.is_empty());
        Self::from_handler(false, move |_, index| {
            responses[index.min(responses.len() - 1)].clone()
        })
    }

    pub(crate) fn from_handler<F>(blocked: bool, response: F) -> Self
    where
        F: Fn(&str, usize) -> HttpResponse + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback fixture");
        listener.set_nonblocking(true).expect("nonblocking fixture");
        let base_url = format!("http://{}", listener.local_addr().expect("fixture address"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(!blocked));
        let worker_requests = Arc::clone(&requests);
        let worker_stop = Arc::clone(&stop);
        let worker_release = Arc::clone(&release);
        let thread = thread::spawn(move || {
            while !worker_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        socket
                            .set_read_timeout(Some(Duration::from_millis(250)))
                            .expect("request timeout");
                        socket
                            .set_write_timeout(Some(Duration::from_millis(250)))
                            .expect("response timeout");
                        let request = read_request(&mut socket);
                        let index = {
                            let mut requests =
                                worker_requests.lock().expect("record fixture request");
                            let index = requests.len();
                            requests.push(request.clone());
                            index
                        };
                        while !worker_release.load(Ordering::SeqCst)
                            && !worker_stop.load(Ordering::SeqCst)
                        {
                            thread::sleep(Duration::from_millis(2));
                        }
                        if worker_stop.load(Ordering::SeqCst) {
                            break;
                        }
                        let response = response(&request, index);
                        let wrote_response = socket.write_all(&response.bytes).is_ok();
                        while response.stall
                            && wrote_response
                            && !worker_stop.load(Ordering::SeqCst)
                        {
                            thread::sleep(Duration::from_millis(2));
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("accept loopback request: {error}"),
                }
            }
        });
        Self {
            base_url,
            requests,
            stop,
            release,
            thread: Some(thread),
        }
    }

    pub(crate) fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("fixture requests").clone()
    }

    pub(crate) fn release(&self) {
        self.release.store(true, Ordering::SeqCst);
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.release();
        self.thread
            .take()
            .expect("fixture thread")
            .join()
            .expect("fixture worker completed");
    }
}

fn read_request(socket: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut chunk = [0; 1024];
    while request.len() < 16 * 1024 && !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
        match socket.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(length) => request.extend_from_slice(&chunk[..length]),
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}
