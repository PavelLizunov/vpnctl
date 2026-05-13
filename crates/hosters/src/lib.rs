//! Hosters — шаблоны поведения per-провайдер.
//! Главное, что они задают: разрешён ли смена SSH-порта, и какие
//! «особенности firewall'a».

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub trait Hoster: Send + Sync {
    fn name(&self) -> &'static str;
    /// На каком SSH-порту ноду надо настраивать. Для DigitalOcean — 22 (Cloud
    /// Firewall блокирует кастомные), для Cloudzy — 2222 ОК.
    fn ssh_port(&self) -> u16;
    fn allows_custom_ssh_port(&self) -> bool;
    /// Эвристика по rDNS / ASN — определить хостер автоматически.
    fn detect_from_rdns(rdns: &str) -> Option<Self>
    where
        Self: Sized;
}

pub struct DigitalOcean;
impl Hoster for DigitalOcean {
    fn name(&self) -> &'static str {
        "digitalocean"
    }
    fn ssh_port(&self) -> u16 {
        22
    }
    fn allows_custom_ssh_port(&self) -> bool {
        false
    }
    fn detect_from_rdns(rdns: &str) -> Option<Self> {
        rdns.contains("digitalocean.com").then_some(Self)
    }
}

pub struct Cloudzy;
impl Hoster for Cloudzy {
    fn name(&self) -> &'static str {
        "cloudzy"
    }
    fn ssh_port(&self) -> u16 {
        2222
    }
    fn allows_custom_ssh_port(&self) -> bool {
        true
    }
    fn detect_from_rdns(rdns: &str) -> Option<Self> {
        rdns.contains("cloudzy").then_some(Self)
    }
}

/// Дефолтный hoster — для всего остального.
pub struct Generic;
impl Hoster for Generic {
    fn name(&self) -> &'static str {
        "generic"
    }
    fn ssh_port(&self) -> u16 {
        2222
    }
    fn allows_custom_ssh_port(&self) -> bool {
        true
    }
    fn detect_from_rdns(_rdns: &str) -> Option<Self> {
        Some(Self)
    }
}
