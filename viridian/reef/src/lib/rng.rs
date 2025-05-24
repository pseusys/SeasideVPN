use rand::CryptoRng;
use rand::rngs::OsRng;
use rand::Rng;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::crypto::PUBLIC_KEY_SIZE;
use crate::DynResult;


#[inline]
pub(crate) fn get_rng() -> impl Rng + CryptoRng {
    OsRng
}

#[inline]
pub(crate) fn generate_public_key(asymmetric_key: &[u8]) -> DynResult<PublicKey> {
    let private_bytes = <[u8; PUBLIC_KEY_SIZE]>::try_from(&asymmetric_key[..PUBLIC_KEY_SIZE])?;
    Ok(PublicKey::from(private_bytes))
}

#[inline]
pub(crate) fn generate_key_pair() -> DynResult<(EphemeralSecret, PublicKey)> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(get_rng());
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    Ok((ephemeral_secret, ephemeral_public))
}
