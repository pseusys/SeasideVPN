use rand::{CryptoRng, RngCore};
use rand::Rng;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::DynResult;


const SAMPLE_ASYMMETRIC_KEY_PRIVATE: &[u8] = b"p\xfa\xc7\xaf\x9e\xb8\x07\x16{R\x03\x91\xb7\xbbI\x03_\xdd#Y\x8b\x1a\xd3&z\x96\xd4\x9b%\xae\xa7\xbc";
const SAMPLE_ASYMMETRIC_KEY_PUBLIC: &[u8] = b"\rnS=\x06\xbc\x0e^\x9b\x03Sw\x02H\xaf=\x1e\x10\xe2\x14\xb1\xf9\xfc\x01Wp\xe2\xd4L!\x9e&";


struct MockRng;

impl RngCore for MockRng {
    fn next_u32(&mut self) -> u32 {
        0u32
    }

    fn next_u64(&mut self) -> u64 {
        0u64
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0u8)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        Ok(dest.fill(0u8))
    }
}

impl CryptoRng for MockRng {}


#[inline]
pub(crate) fn get_rng() -> impl Rng + CryptoRng {
    MockRng
}

#[inline]
pub(crate) fn generate_public_key(_: &[u8]) -> DynResult<PublicKey> {
    let public_key_bytes = <[u8; 32]>::try_from(SAMPLE_ASYMMETRIC_KEY_PUBLIC)?;
    Ok(PublicKey::from(public_key_bytes))
}


struct PrivateKeyRng;

impl RngCore for PrivateKeyRng {
    fn next_u32(&mut self) -> u32 {
        todo!("This method is not supposed to be called!")
    }

    fn next_u64(&mut self) -> u64 {
        todo!("This method is not supposed to be called!")
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.copy_from_slice(SAMPLE_ASYMMETRIC_KEY_PRIVATE);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        todo!("This method is not supposed to be called!")
    }
}

impl CryptoRng for PrivateKeyRng {}


#[inline]
pub(crate) fn generate_key_pair() -> DynResult<(EphemeralSecret, PublicKey)> {
    let private_key = EphemeralSecret::random_from_rng(PrivateKeyRng);
    let public_key = generate_public_key(&[])?;
    Ok((private_key, public_key))
}
