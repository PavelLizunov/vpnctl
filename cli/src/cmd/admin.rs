use anyhow::Context;
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};

pub(crate) fn hash_password(password_arg: Option<String>) -> anyhow::Result<()> {
    let plaintext = match password_arg {
        Some(p) => {
            eprintln!(
                "warning: password was passed on the command line; \
                 it now appears in shell history and /proc/<pid>/cmdline. \
                 Prefer stdin: `echo -n SECRET | vpnctl admin hash-password`."
            );
            p
        }
        None => read_one_line_from_stdin().context("read password from stdin")?,
    };
    if plaintext.is_empty() {
        anyhow::bail!("empty password — refusing to hash");
    }
    let salt = SaltString::generate(&mut rand_core::OsRng);
    let argon2 = Argon2::default();
    let phc = argon2
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash failed: {e}"))?
        .to_string();
    println!("{phc}");
    Ok(())
}

fn read_one_line_from_stdin() -> anyhow::Result<String> {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut line = String::new();
    let n = stdin.lock().read_line(&mut line)?;
    if n == 0 {
        anyhow::bail!("stdin closed before reading a password");
    }
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(line)
}
