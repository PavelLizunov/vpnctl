use std::collections::HashSet;
use std::sync::LazyLock;

use idna::AsciiDenyList;
use serde::Deserialize;
use url::{Host, Url};

use super::{PolicyError, PolicyRule};

const PROTECTED: &[&str] = &[
    "uiscom.ru",
    "uiscom.co",
    "comagic.ru",
    "callbackhunter.com",
    "admin.corp.ninitux.com",
];

static SUFFIXES: LazyLock<Result<PublicSuffixes, PolicyError>> =
    LazyLock::new(PublicSuffixes::read);

pub fn normalize_site(input: &str) -> Result<String, PolicyError> {
    if input.is_empty()
        || input.encode_utf16().count() > 4096
        || input.chars().any(char::is_control)
    {
        return Err(PolicyError);
    }
    let trimmed = input.trim();
    let url;
    let host = if let Some((_, after_scheme)) = trimmed.split_once("://") {
        let authority = after_scheme
            .split(['/', '?', '#'])
            .next()
            .ok_or(PolicyError)?;
        if authority.is_empty() || trimmed.contains('\\') || authority.contains('@') {
            return Err(PolicyError);
        }
        url = Url::parse(trimmed).map_err(|_| PolicyError)?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(PolicyError);
        }
        match url.host() {
            Some(Host::Domain(host)) => host,
            _ => return Err(PolicyError),
        }
    } else {
        trimmed
    };
    normalize_dns(host.strip_suffix('.').unwrap_or(host))
}

pub fn validate_rules(rules: &[PolicyRule]) -> Result<(), PolicyError> {
    if rules.len() > 512 {
        return Err(PolicyError);
    }
    let mut seen = HashSet::with_capacity(rules.len());
    for rule in rules {
        if rule.domain != normalize_dns(&rule.domain)?
            || protected(&rule.domain)
            || !matches!(rule.action.as_str(), "direct" | "proxy")
            || !seen.insert(rule.domain.as_str())
            || rule.comment.len() > 256
            || rule.comment.chars().any(char::is_control)
        {
            return Err(PolicyError);
        }
    }
    for (index, left) in rules.iter().enumerate() {
        for right in &rules[index + 1..] {
            if left.action != right.action && intersects(&left.domain, &right.domain) {
                return Err(PolicyError);
            }
        }
    }
    Ok(())
}

pub fn seed_rules() -> Result<Vec<PolicyRule>, PolicyError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EmbeddedRule {
        action: String,
        r#type: String,
        value: String,
        comment: String,
        enabled: bool,
    }
    let source: Vec<EmbeddedRule> =
        serde_json::from_str(include_str!("../../assets/corp-policy/business-rules.json"))
            .map_err(|_| PolicyError)?;
    let rules: Vec<_> = source
        .into_iter()
        .filter(|rule| rule.enabled && rule.r#type == "domain_suffix" && !protected(&rule.value))
        .map(|rule| PolicyRule {
            domain: rule.value,
            action: rule.action,
            comment: rule.comment,
        })
        .collect();
    validate_rules(&rules)?;
    Ok(rules)
}

fn protected(domain: &str) -> bool {
    PROTECTED
        .iter()
        .any(|protected| intersects(domain, protected))
}

fn intersects(left: &str, right: &str) -> bool {
    left == right || is_subdomain(left, right) || is_subdomain(right, left)
}

fn is_subdomain(child: &str, parent: &str) -> bool {
    child
        .strip_suffix(parent)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

fn normalize_dns(input: &str) -> Result<String, PolicyError> {
    if input.is_empty()
        || input.encode_utf16().count() > 253
        || input.chars().any(|c| c.is_control() || c.is_whitespace())
        || input.contains(['/', '\\', ':', '?', '#', '@', '[', ']', '%', '*'])
    {
        return Err(PolicyError);
    }
    let domain = ascii_domain(input)?;
    if domain.len() > 253
        || !domain.contains('.')
        || domain.bytes().all(|c| c.is_ascii_digit() || c == b'.')
        || matches!(Host::parse(&domain), Ok(Host::Ipv4(_) | Host::Ipv6(_)))
    {
        return Err(PolicyError);
    }
    for label in domain.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return Err(PolicyError);
        }
    }
    let (unicode, validity) = idna::domain_to_unicode(&domain);
    if validity.is_err() || ascii_domain(&unicode)? != domain {
        return Err(PolicyError);
    }
    if SUFFIXES
        .as_ref()
        .map_err(|_| PolicyError)?
        .contains(&domain)
    {
        return Err(PolicyError);
    }
    Ok(domain)
}

fn ascii_domain(input: &str) -> Result<String, PolicyError> {
    // STD3 characters plus explicit DNS-label checks match the client. UTS46's
    // strict hyphen mode would also reject ordinary CDN labels such as ab--cd.
    idna::domain_to_ascii_cow(input.as_bytes(), AsciiDenyList::STD3)
        .map(|value| value.to_ascii_lowercase())
        .map_err(|_| PolicyError)
}

struct PublicSuffixes {
    exact: HashSet<String>,
    wildcard: HashSet<String>,
    exceptions: HashSet<String>,
}

impl PublicSuffixes {
    fn read() -> Result<Self, PolicyError> {
        let mut suffixes = Self {
            exact: HashSet::new(),
            wildcard: HashSet::new(),
            exceptions: HashSet::new(),
        };
        for line in include_str!("../../assets/corp-policy/public_suffix_list.dat").lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            let (rules, domain) = if let Some(domain) = line.strip_prefix("*.") {
                (&mut suffixes.wildcard, domain)
            } else if let Some(domain) = line.strip_prefix('!') {
                (&mut suffixes.exceptions, domain)
            } else {
                (&mut suffixes.exact, line)
            };
            rules.insert(ascii_domain(domain)?);
        }
        if suffixes.exact.is_empty() {
            return Err(PolicyError);
        }
        Ok(suffixes)
    }

    fn contains(&self, domain: &str) -> bool {
        if self.exceptions.contains(domain) {
            return false;
        }
        self.exact.contains(domain)
            || domain
                .split_once('.')
                .is_some_and(|(_, parent)| self.wildcard.contains(parent))
    }
}
