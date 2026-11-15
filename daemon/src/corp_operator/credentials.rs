use argon2::password_hash::{PasswordHasher, SaltString};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use vpnctl_inventory::{CorpCredentials, CorpReaderToken, CorpSigningKey};
use zeroize::Zeroizing;

use super::{Result, unavailable};
use crate::{
    corp_policy::PolicySigningKey,
    handlers::auth::{VERIFY_PERMITS, bounded_corp_password_hash, bounded_password_work},
};

pub(super) fn token() -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| unavailable())?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref())))
}

pub(super) fn identifier() -> Result<String> {
    Ok(token()?.to_string())
}

pub(super) fn reader() -> Result<CorpReaderToken> {
    Ok(CorpReaderToken {
        id: identifier()?,
        token: token()?.to_string(),
    })
}

pub(super) fn signer() -> Result<CorpSigningKey> {
    let key = PolicySigningKey::generate().map_err(|_| unavailable())?;
    let der = key.export_pkcs8_der().map_err(|_| unavailable())?;
    Ok(CorpSigningKey {
        id: identifier()?,
        pkcs8: STANDARD.encode(der.as_bytes()),
        spki: key.spki_base64().map_err(|_| unavailable())?,
    })
}

pub(super) async fn password() -> Result<(Zeroizing<String>, Zeroizing<String>)> {
    let password = token()?;
    let input = password.clone();
    let hash = bounded_password_work(&VERIFY_PERMITS, move || {
        let mut salt_bytes = Zeroizing::new([0u8; 16]);
        getrandom::fill(salt_bytes.as_mut()).ok()?;
        let salt = SaltString::encode_b64(salt_bytes.as_ref()).ok()?;
        let params = argon2::Params::new(19456, 2, 1, Some(32)).ok()?;
        let engine =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        Some(Zeroizing::new(
            engine
                .hash_password(input.as_bytes(), &salt)
                .ok()?
                .to_string(),
        ))
    })
    .await
    .flatten()
    .ok_or_else(unavailable)?;
    Ok((password, hash))
}

pub(super) fn validate(credentials: &CorpCredentials) -> Result<()> {
    bounded_corp_password_hash(&credentials.password_phc).ok_or_else(unavailable)?;
    for stored in &credentials.signing_keys {
        let der = Zeroizing::new(STANDARD.decode(&stored.pkcs8).map_err(|_| unavailable())?);
        if STANDARD.encode(der.as_slice()) != stored.pkcs8 {
            return Err(unavailable());
        }
        let key = PolicySigningKey::from_pkcs8_der(&der).map_err(|_| unavailable())?;
        if key.spki_base64().map_err(|_| unavailable())? != stored.spki {
            return Err(unavailable());
        }
    }
    Ok(())
}
