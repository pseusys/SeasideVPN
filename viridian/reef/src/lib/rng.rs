use rand::CryptoRng;
use rand::rngs::OsRng;
use rand::Rng;


#[inline]
pub(crate) fn get_rng() -> impl Rng + CryptoRng {
    OsRng
}
