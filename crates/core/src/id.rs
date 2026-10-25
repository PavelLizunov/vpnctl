use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KernelId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtocolId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServerId(pub String);

/// Validate an operator-created user ID for URLs and protocol configurations.
pub fn valid_user_id(id: &str) -> bool {
    let len = id.len();
    if !(2..=32).contains(&len) {
        return false;
    }
    let bytes = id.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    if !bytes[len - 1].is_ascii_lowercase() && !bytes[len - 1].is_ascii_digit() {
        return false;
    }
    if id.contains("..") {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
}

macro_rules! impl_display_for_id {
    ($($t:ty),+ $(,)?) => {
        $(impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        })+
    };
}
impl_display_for_id!(KernelId, ProtocolId, ServerId, UserId);

#[cfg(test)]
mod tests {
    use super::valid_user_id;

    #[test]
    fn valid_user_id_accepts_supported_names_and_length_boundaries() {
        for id in ["a1", "01", "alice", "user.123", "user_name", "u-1", "a._-1"] {
            assert!(valid_user_id(id), "rejected {id:?}");
        }
        assert!(valid_user_id(&"a".repeat(32)));
        assert!(!valid_user_id(&"a".repeat(33)));
        assert!(!valid_user_id("a"));
        assert!(!valid_user_id(""));
    }

    #[test]
    fn valid_user_id_rejects_unsafe_characters_and_does_not_normalize() {
        for id in [
            "Alice",
            ".user",
            "user.",
            "_user",
            "user_",
            "-user",
            "user-",
            "user..name",
            "..",
            "user@domain",
            "user/name",
            "user\\name",
            "user name",
            " user",
            "user ",
            "user\n[Peer]",
            "user\r\n",
            "user\0name",
            "алиса",
            "éa",
        ] {
            assert!(!valid_user_id(id), "accepted {id:?}");
        }
    }
}
