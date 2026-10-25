use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct GeoInfo {
    pub country_iso: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<String>,
}

impl GeoInfo {
    pub fn asn_label(&self) -> Option<String> {
        match (self.asn, self.org.as_deref()) {
            (Some(n), Some(o)) => Some(format!("AS{n} {o}")),
            (Some(n), None) => Some(format!("AS{n}")),
            (None, Some(o)) => Some(o.to_string()),
            (None, None) => None,
        }
    }
}

#[derive(Clone)]
pub struct GeoLookup {
    inner: Option<Arc<Inner>>,
}

impl std::fmt::Debug for GeoLookup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoLookup")
            .field("loaded", &self.inner.is_some())
            .finish()
    }
}

struct Inner {
    #[cfg(feature = "geoip")]
    city: Option<maxminddb::Reader<Vec<u8>>>,
    #[cfg(feature = "geoip")]
    asn: Option<maxminddb::Reader<Vec<u8>>>,
}

impl GeoLookup {
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    pub fn from_env() -> Self {
        let Some(dir) = std::env::var_os("VPNCTLD_GEOIP_DIR") else {
            return Self::disabled();
        };
        let dir = PathBuf::from(dir);
        let g = Self::open(
            &dir.join("GeoLite2-City.mmdb"),
            &dir.join("GeoLite2-ASN.mmdb"),
        )
        .unwrap_or_else(|e| {
            tracing::warn!(
                target = "vpnctld::geoip",
                dir = ?dir,
                error = %e,
                "VPNCTLD_GEOIP_DIR set but DB load failed — falling back to disabled lookup"
            );
            Self::disabled()
        });
        if !g.is_loaded() {
            tracing::warn!(
                target = "vpnctld::geoip",
                dir = ?dir,
                "VPNCTLD_GEOIP_DIR set but neither GeoLite2-City.mmdb \
                 nor GeoLite2-ASN.mmdb is present — sub_access_log rows \
                 will leave geo_country / geo_asn NULL. Drop the .mmdb \
                 files into the dir + restart the daemon to enable \
                 enrichment."
            );
        }
        g
    }

    #[cfg(feature = "geoip")]
    pub fn open(city: &Path, asn: &Path) -> Result<Self, std::io::Error> {
        let read = |p: &Path| -> Option<maxminddb::Reader<Vec<u8>>> {
            if !p.exists() {
                return None;
            }
            match maxminddb::Reader::open_readfile(p) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::warn!(
                        target = "vpnctld::geoip",
                        path = ?p,
                        error = %e,
                        "GeoIP .mmdb open failed"
                    );
                    None
                }
            }
        };
        let city = read(city);
        let asn = read(asn);
        if city.is_none() && asn.is_none() {
            return Ok(Self::disabled());
        }
        Ok(Self {
            inner: Some(Arc::new(Inner { city, asn })),
        })
    }

    #[cfg(not(feature = "geoip"))]
    pub fn open(_city: &Path, _asn: &Path) -> Result<Self, std::io::Error> {
        Ok(Self::disabled())
    }

    pub fn is_loaded(&self) -> bool {
        self.inner.is_some()
    }

    #[cfg(feature = "geoip")]
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        use maxminddb::geoip2;
        let inner = self.inner.as_ref()?;
        let mut info = GeoInfo::default();
        if let Some(reader) = &inner.city
            && let Ok(lookup) = reader.lookup(ip)
            && let Ok(Some(city_rec)) = lookup.decode::<geoip2::City>()
        {
            info.country_iso = city_rec.country.iso_code.map(|s| s.to_string());
            if let Some(en) = city_rec.city.names.english {
                info.city = Some(en.to_string());
            }
        }
        if let Some(reader) = &inner.asn
            && let Ok(lookup) = reader.lookup(ip)
            && let Ok(Some(asn_rec)) = lookup.decode::<geoip2::Asn>()
        {
            info.asn = asn_rec.autonomous_system_number;
            info.org = asn_rec
                .autonomous_system_organization
                .map(|s| s.to_string());
        }
        if info.country_iso.is_none()
            && info.city.is_none()
            && info.asn.is_none()
            && info.org.is_none()
        {
            None
        } else {
            Some(info)
        }
    }

    #[cfg(not(feature = "geoip"))]
    pub fn lookup(&self, _ip: IpAddr) -> Option<GeoInfo> {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn disabled_lookup_returns_none() {
        let g = GeoLookup::disabled();
        assert!(!g.is_loaded());
        assert!(g.lookup("8.8.8.8".parse().unwrap()).is_none());
    }

    #[test]
    fn asn_label_composes_fields() {
        let info = GeoInfo {
            country_iso: Some("DE".into()),
            city: None,
            asn: Some(24940),
            org: Some("Hetzner Online".into()),
        };
        assert_eq!(info.asn_label().as_deref(), Some("AS24940 Hetzner Online"));

        let info2 = GeoInfo {
            asn: Some(24940),
            ..Default::default()
        };
        assert_eq!(info2.asn_label().as_deref(), Some("AS24940"));

        let info3 = GeoInfo::default();
        assert_eq!(info3.asn_label(), None);
    }

    #[test]
    fn from_env_unset_returns_disabled() {
        if std::env::var_os("VPNCTLD_GEOIP_DIR").is_none() {
            let g = GeoLookup::from_env();
            assert!(
                !g.is_loaded(),
                "no env var → from_env must yield disabled stub"
            );
        }
    }
}
