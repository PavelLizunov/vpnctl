use std::path::{Path, PathBuf};

pub(crate) fn public_key_path(private_path: &Path) -> PathBuf {
    let mut path = private_path.as_os_str().to_os_string();
    path.push(".pub");
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_path_appends_pub_without_replacing_extension() {
        assert_eq!(
            public_key_path(Path::new("/etc/vpnctl/id_ed25519")),
            PathBuf::from("/etc/vpnctl/id_ed25519.pub")
        );
        assert_eq!(
            public_key_path(Path::new("/etc/vpnctl/id.key")),
            PathBuf::from("/etc/vpnctl/id.key.pub")
        );
    }
}
