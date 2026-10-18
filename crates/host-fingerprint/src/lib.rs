use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ssh-keyscan failed to spawn: {0}")]
    KeyscanSpawn(String),

    #[error(
        "ssh-keyscan for {host}:{port} exited {code:?} (host unreachable or no ed25519/rsa key?): \
         {stderr}"
    )]
    KeyscanFailed {
        host: String,
        port: u16,
        code: Option<i32>,
        stderr: String,
    },

    #[error("ssh-keyscan returned no host key for {host}:{port}")]
    KeyscanEmpty { host: String, port: u16 },

    #[error("ssh-keygen failed to spawn: {0}")]
    KeygenSpawn(String),

    #[error("ssh-keygen stdin pipe missing (Stdio::piped was ignored?)")]
    KeygenStdinPipe,

    #[error("ssh-keygen stdin write failed: {0}")]
    KeygenStdinWrite(String),

    #[error("ssh-keygen wait failed: {0}")]
    KeygenWait(String),

    #[error("ssh-keygen -lf - exited {0:?}")]
    KeygenFailed(Option<i32>),

    #[error("ssh-keygen output had no SHA256: token (got {output:?})")]
    NoFingerprintToken { output: String },
}

pub fn validate_shape(fp: &str) -> bool {
    let Some(rest) = fp.strip_prefix("SHA256:") else {
        return false;
    };
    if !matches!(rest.len(), 43 | 44) {
        return false;
    }
    rest.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_' | b'='))
}

pub fn canonicalize_sha256(fp: &str) -> Option<String> {
    let rest = fp.strip_prefix("SHA256:")?;
    let body = match rest.len() {
        43 => rest,
        44 if rest.ends_with('=') => &rest[..43],
        _ => return None,
    };
    let mut normalized = String::with_capacity(7 + 43);
    normalized.push_str("SHA256:");
    for b in body.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => normalized.push(b as char),
            b'-' => normalized.push('+'),
            b'_' => normalized.push('/'),
            _ => return None,
        }
    }
    Some(normalized)
}

#[inline]
pub fn normalize_sha256(fp: &str) -> Option<String> {
    canonicalize_sha256(fp)
}

pub fn fingerprints_match(expected: &str, observed: &str) -> bool {
    match (canonicalize_sha256(expected), canonicalize_sha256(observed)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

pub fn fetch_via_keyscan(host: &str, port: u16) -> Result<String, Error> {
    let stdout = run_keyscan(host, port)?;
    let chosen =
        pick_key_line(&String::from_utf8_lossy(&stdout)).ok_or_else(|| Error::KeyscanEmpty {
            host: host.to_string(),
            port,
        })?;
    let keygen_out = run_keygen_fingerprint(chosen.as_bytes())?;
    extract_sha256_token(&keygen_out).ok_or(Error::NoFingerprintToken {
        output: keygen_out.trim().to_string(),
    })
}

pub fn fetch_all_fingerprints(host: &str, port: u16) -> Result<Vec<String>, Error> {
    let stdout = run_keyscan(host, port)?;
    let keygen_out = run_keygen_fingerprint(&stdout)?;
    let tokens = extract_all_sha256_tokens(&keygen_out);
    if tokens.is_empty() {
        return Err(Error::NoFingerprintToken {
            output: keygen_out.trim().to_string(),
        });
    }
    Ok(tokens)
}

fn run_keyscan(host: &str, port: u16) -> Result<Vec<u8>, Error> {
    let port_s = port.to_string();
    let args = build_keyscan_args(&port_s, host);
    let scan = Command::new("ssh-keyscan")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| Error::KeyscanSpawn(e.to_string()))?;
    if !scan.status.success() {
        return Err(Error::KeyscanFailed {
            host: host.to_string(),
            port,
            code: scan.status.code(),
            stderr: String::from_utf8_lossy(&scan.stderr).trim().to_string(),
        });
    }
    if scan.stdout.is_empty() {
        return Err(Error::KeyscanEmpty {
            host: host.to_string(),
            port,
        });
    }
    Ok(scan.stdout)
}

fn run_keygen_fingerprint(input: &[u8]) -> Result<String, Error> {
    let mut child = Command::new("ssh-keygen")
        .args(["-lf", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::KeygenSpawn(e.to_string()))?;
    let mut stdin = child.stdin.take().ok_or(Error::KeygenStdinPipe)?;
    stdin
        .write_all(input)
        .map_err(|e| Error::KeygenStdinWrite(e.to_string()))?;
    drop(stdin);
    let keygen = child
        .wait_with_output()
        .map_err(|e| Error::KeygenWait(e.to_string()))?;
    if !keygen.status.success() {
        return Err(Error::KeygenFailed(keygen.status.code()));
    }
    Ok(String::from_utf8_lossy(&keygen.stdout).into_owned())
}

pub fn pick_key_line(stdout: &str) -> Option<String> {
    let mut fallback: Option<String> = None;
    for line in stdout.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if l.split_whitespace().nth(1) == Some("ssh-ed25519") {
            return Some(l.to_string());
        }
        if fallback.is_none() {
            fallback = Some(l.to_string());
        }
    }
    fallback
}

pub fn extract_sha256_token(stdout: &str) -> Option<String> {
    stdout
        .split_whitespace()
        .find(|t| t.starts_with("SHA256:"))
        .map(str::to_owned)
}

pub fn extract_all_sha256_tokens(stdout: &str) -> Vec<String> {
    stdout
        .split_whitespace()
        .filter(|t| t.starts_with("SHA256:"))
        .map(str::to_owned)
        .collect()
}

pub fn build_keyscan_args<'a>(port_s: &'a str, host: &'a str) -> [&'a str; 8] {
    ["-T", "10", "-p", port_s, "-t", "ed25519,rsa", "--", host]
}
