use std::collections::HashMap;

pub const DEFAULT_AMNEZIA_PARAMS: [(&str, &str); 9] = [
    ("Jc", "4"),
    ("Jmin", "40"),
    ("Jmax", "70"),
    ("S1", "50"),
    ("S2", "100"),
    ("H1", "1"),
    ("H2", "2"),
    ("H3", "3"),
    ("H4", "4"),
];

/// Resolve legacy AmneziaWG parameters identically for the server and clients.
pub fn effective_params(secrets: &HashMap<String, String>) -> [(&'static str, &str); 9] {
    DEFAULT_AMNEZIA_PARAMS.map(|(key, default)| {
        let secret_key = format!("amneziawg.{}", key.to_ascii_lowercase());
        let value = secrets
            .get(&secret_key)
            .map(String::as_str)
            .unwrap_or(default);
        (key, value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_params_use_server_defaults_and_supplied_strings_are_preserved() {
        let mut secrets = HashMap::new();
        assert_eq!(
            effective_params(&secrets),
            [
                ("Jc", "4"),
                ("Jmin", "40"),
                ("Jmax", "70"),
                ("S1", "50"),
                ("S2", "100"),
                ("H1", "1"),
                ("H2", "2"),
                ("H3", "3"),
                ("H4", "4"),
            ]
        );
        secrets.insert("amneziawg.h1".into(), "0012345".into());
        let resolved = effective_params(&secrets);
        assert_eq!(resolved[5], ("H1", "0012345"));
        assert_eq!(resolved[6], ("H2", "2"));
        assert_eq!(resolved[0], ("Jc", "4"));
    }
}
