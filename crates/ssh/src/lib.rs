pub mod mock;
pub mod subprocess;

// Remote commands return configuration and diagnostics, not bulk backups or downloads.
pub(crate) const MAX_STDOUT_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_STDERR_BYTES: usize = 1024 * 1024;

#[cfg(feature = "russh")]
pub mod russh_transport;

pub use mock::MockTransport;
pub use subprocess::{
    SubprocessSshTransport, ensure_deploy_key, public_key_path, read_public_key, ssh_safety_opts,
};

#[cfg(feature = "russh")]
pub use russh_transport::{RusshTransport, RusshTransportBuilder};
